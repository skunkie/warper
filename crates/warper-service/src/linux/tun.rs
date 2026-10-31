// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Journaled creation/rename/retirement of one fresh down Linux TUN.
//! Call only in retained native workers; this does not publish routes or traffic.

use super::context::{Context, RecordedOwner};
use nix::{
    errno::Errno,
    net::if_::{if_indextoname, if_nametoindex},
};
use std::{fmt, io, sync::Arc};
use tun_rs::{DeviceBuilder, SyncDevice};
use warper_control::runtime::journal::{Error as StorageError, NetworkJournal};

mod node;
mod record;
pub use record::Stage;
use record::{Identity, Record};
const MTU: u16 = 1280;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Context(super::context::Error),
    Storage(StorageError),
    InvalidInput,
    UnsupportedMtu,
    DeviceUnavailable,
    DeviceInspection(io::ErrorKind),
    Conflict,
    InvalidState,
    RecoveryRequired,
    InvalidRecord,
    Io(io::ErrorKind),
    CleanupUncertain,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Context(_) => "SystemConfiguration: TUN owner context failed",
            Self::Storage(_) => "SystemConfiguration: TUN journal operation failed",
            Self::InvalidInput => "InvalidConfig: invalid TUN interface name",
            Self::UnsupportedMtu => "UnsupportedCapability: initial TUN MTU must be 1280",
            Self::DeviceUnavailable => {
                "UnsupportedIntegration: protected native TUN device is unavailable"
            }
            Self::DeviceInspection(_) => {
                "UnsupportedIntegration: native TUN device inspection failed"
            }
            Self::Conflict => "Conflict: requested TUN name or owned identity changed",
            Self::InvalidState => "Conflict: invalid TUN lifecycle transition",
            Self::RecoveryRequired => "RecoveryRequired: prior TUN state requires inspection",
            Self::InvalidRecord => "RecoveryRequired: invalid platform TUN journal",
            Self::Io(_) => "SystemConfiguration: native TUN operation failed",
            Self::CleanupUncertain => {
                "RecoveryRequired: native TUN retirement could not be verified"
            }
        })
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub primary: Error,
    pub cleanup: [Option<Error>; 2],
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.primary)?;
        if self.cleanup.iter().any(Option::is_some) {
            f.write_str("; TUN cleanup also failed")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameOutcome {
    OsSelected,
    AlreadyApplied,
    Renamed,
}

/// Retains the fresh device until explicit close or drop. No raw descriptor or
/// upstream device escapes; a stored name/index can never attach an interface.
pub struct Owner {
    device: Option<SyncDevice>,
    identity: Option<Identity>,
    journal: NetworkJournal,
    revision: u64,
    record: Record,
    failed: bool,
    // Device and journal resources retire before the last native context owner.
    context: Arc<Context>,
}
impl Owner {
    pub fn prepare(context: Arc<Context>, name: Option<&str>, mtu: u16) -> Result<Self, Error> {
        if name.is_some_and(|name| !record::valid_name(name)) {
            return Err(Error::InvalidInput);
        }
        if mtu != MTU {
            return Err(Error::UnsupportedMtu);
        }
        context.revalidate().map_err(Error::Context)?;
        node::verify()?;
        if let Some(name) = name {
            match if_nametoindex(name) {
                Ok(_) => return Err(Error::Conflict),
                Err(Errno::ENODEV | Errno::ENXIO) => {}
                Err(error) => return Err(native_error(error.into())),
            }
        }
        let mut journal = NetworkJournal::open(context.runtime()).map_err(Error::Storage)?;
        let previous = journal.read(context.runtime()).map_err(Error::Storage)?;
        if let Some(previous) = &previous
            && Record::decode(previous.payload())?.stage != Stage::Retired
        {
            return Err(Error::RecoveryRequired);
        }
        let revision = previous.as_ref().map_or(0, |snapshot| snapshot.revision());
        let record = Record {
            owner: context.recorded_owner(),
            stage: Stage::Prepared,
            requested: name.map(str::to_owned),
            identity: None,
        };
        let revision = journal
            .replace(context.runtime(), revision, &record.encode())
            .map_err(Error::Storage)?
            .revision();
        Ok(Self {
            device: None,
            identity: None,
            journal,
            revision,
            record,
            failed: false,
            context,
        })
    }
    pub fn allocate(&mut self) -> Result<(), Error> {
        if self.record.stage != Stage::Prepared || self.device.is_some() {
            return Err(Error::InvalidState);
        }
        self.ready()?;
        node::verify()?;
        let device = match DeviceBuilder::new().mtu(MTU).enable(false).build_sync() {
            Ok(device) => device,
            Err(error) => {
                self.failed = true;
                return Err(native_error(error));
            }
        };
        self.device = Some(device);
        let result = (|| {
            let device = self.device.as_ref().ok_or(Error::InvalidState)?;
            let identity = identity(device)?;
            self.identity = Some(identity.clone());
            if device.mtu().map_err(native_error)? != MTU
                || device.is_running().map_err(native_error)?
                || device.tcp_gso()
                || device.udp_gso()
            {
                return Err(Error::Conflict);
            }
            let mut record = self.record.clone();
            record.stage = Stage::Allocated;
            record.identity = Some(identity);
            self.save(record)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn apply_name(&mut self) -> Result<NameOutcome, Error> {
        if !matches!(self.record.stage, Stage::Allocated | Stage::Named) {
            return Err(Error::InvalidState);
        }
        self.ready()?;
        self.verify_device()?;
        let Some(requested) = self.record.requested.clone() else {
            return Ok(NameOutcome::OsSelected);
        };
        let actual = self.identity.as_ref().ok_or(Error::InvalidState)?;
        if actual.name == requested {
            if self.record.stage != Stage::Named {
                let mut named = self.record.clone();
                named.stage = Stage::Named;
                self.save(named)?;
            }
            return Ok(NameOutcome::AlreadyApplied);
        }
        let mut intent = self.record.clone();
        intent.stage = Stage::Renaming;
        self.save(intent)?;
        let result = (|| {
            self.context.revalidate().map_err(Error::Context)?;
            let device = self.device.as_ref().ok_or(Error::InvalidState)?;
            device.set_name(&requested).map_err(native_error)?;
            let renamed = identity(device)?;
            if self
                .identity
                .as_ref()
                .is_none_or(|previous| previous.index != renamed.index)
                || renamed.name != requested
            {
                return Err(Error::Conflict);
            }
            self.identity = Some(renamed.clone());
            let mut record = self.record.clone();
            record.stage = Stage::Named;
            record.identity = Some(renamed);
            self.save(record)?;
            Ok(NameOutcome::Renamed)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        if self.record.stage == Stage::Retired && self.device.is_none() {
            return self.check_storage().map_err(|primary| Failure {
                primary,
                cleanup: [None; 2],
            });
        }
        let initial = self
            .context
            .revalidate()
            .map_err(Error::Context)
            .and_then(|()| self.verify_device())
            .err();
        let mut retiring = self.record.clone();
        retiring.stage = Stage::Retiring;
        retiring.identity = self.identity.clone();
        let journal_error = self.save(retiring).err();
        // The original durable intent permits compensating closure of the exact
        // newly created descriptor even when a subsequent journal write failed.
        self.device.take();
        let inspection_error = self
            .context
            .revalidate()
            .map_err(Error::Context)
            .and_then(|()| {
                if let Some(identity) = &self.identity {
                    match if_indextoname(identity.index) {
                        Err(Errno::ENODEV | Errno::ENXIO) => {}
                        Ok(_) => return Err(Error::CleanupUncertain),
                        Err(error) => return Err(native_error(error.into())),
                    }
                }
                Ok(())
            })
            .err();
        let mut errors = [initial, journal_error, inspection_error]
            .into_iter()
            .flatten();
        if let Some(primary) = errors.next() {
            return Err(Failure {
                primary,
                cleanup: [errors.next(), errors.next()],
            });
        }
        let mut retired = self.record.clone();
        retired.stage = Stage::Retired;
        retired.identity = self.identity.clone();
        self.save(retired).map_err(|primary| Failure {
            primary,
            cleanup: [None; 2],
        })?;
        Ok(())
    }
    pub fn stage(&self) -> Stage {
        self.record.stage
    }
    pub fn name(&self) -> Option<&str> {
        self.identity
            .as_ref()
            .map(|identity| identity.name.as_str())
    }
    pub fn index(&self) -> Option<u32> {
        self.identity.as_ref().map(|identity| identity.index)
    }
    fn ready(&self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::RecoveryRequired);
        }
        self.check_storage()
    }
    fn check_storage(&self) -> Result<(), Error> {
        self.context.revalidate().map_err(Error::Context)?;
        let snapshot = self
            .journal
            .read(self.context.runtime())
            .map_err(Error::Storage)?
            .ok_or(Error::Conflict)?;
        if snapshot.revision() != self.revision || snapshot.payload() != self.record.encode() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn verify_device(&self) -> Result<(), Error> {
        if let Some(device) = &self.device {
            let actual = identity(device)?;
            if self.identity.as_ref() != Some(&actual) || device.mtu().map_err(native_error)? != MTU
            {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
    fn save(&mut self, record: Record) -> Result<(), Error> {
        match self
            .journal
            .replace(self.context.runtime(), self.revision, &record.encode())
        {
            Ok(snapshot) => {
                self.revision = snapshot.revision();
                self.record = record;
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                Err(Error::Storage(error))
            }
        }
    }
}
impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TunOwner(<redacted>)")
    }
}
fn identity(device: &SyncDevice) -> Result<Identity, Error> {
    let name = device.name().map_err(native_error)?;
    let index = device.if_index().map_err(native_error)?;
    if !record::valid_name(&name) || index == 0 || index > i32::MAX as u32 {
        return Err(Error::Conflict);
    }
    Ok(Identity { name, index })
}
fn native_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::AlreadyExists {
        Error::Conflict
    } else {
        Error::Io(error.kind())
    }
}
