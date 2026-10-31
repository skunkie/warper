// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Journaled lifecycle of one fresh owned Linux TUN.
//! Call only in retained native workers; this does not publish routes or traffic.

use super::context::{Context, RecordedOwner};
use nix::{errno::Errno, net::if_::if_nametoindex};
use std::{fmt, io, net::Ipv4Addr, sync::Arc};
use tun_rs::{AsyncDevice, DeviceBuilder, DeviceImpl};
use warper_control::runtime::journal::{Error as StorageError, NetworkJournal};
use warper_core::transport::Request;

mod address;
mod link;
mod node;
mod packet;
pub use packet::{BUFFER_BYTES, Error as PacketError, PacketPort};
mod transaction;
pub use transaction::{
    Cause as AddressCause, Delivery as AddressDelivery, Failure as AddressFailure,
};
pub use transaction::{Cause as NativeCause, Delivery as NativeDelivery, Failure as NativeFailure};
mod record;
pub use record::Stage;
use record::{Identity, Record};
const MTU: u16 = 1280;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Context(super::context::Error),
    Storage(StorageError),
    InvalidInput,
    InvalidAddress,
    Address(AddressFailure),
    Activation(NativeFailure),
    UnsupportedMtu,
    DeviceUnavailable,
    DeviceInspection(io::ErrorKind),
    Conflict,
    InvalidState,
    NoRuntime,
    PacketPortActive,
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
            Self::InvalidAddress => "InvalidConfig: invalid initial TUN IPv4 address",
            Self::Address(_) => "SystemConfiguration: native TUN address transaction failed",
            Self::Activation(_) => "SystemConfiguration: native TUN activation failed",
            Self::InvalidInput => "InvalidConfig: invalid TUN interface name",
            Self::UnsupportedMtu => "UnsupportedCapability: initial TUN MTU must be 1280",
            Self::DeviceUnavailable => {
                "UnsupportedIntegration: protected native TUN device is unavailable"
            }
            Self::DeviceInspection(_) => {
                "UnsupportedIntegration: native TUN device inspection failed"
            }
            Self::Conflict => "Conflict: requested TUN name or owned identity changed",
            Self::NoRuntime => "SystemConfiguration: native TUN allocation requires an I/O runtime",
            Self::PacketPortActive => "Conflict: packet work must retire before native TUN close",
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
    device: Option<Arc<AsyncDevice>>,
    identity: Option<Identity>,
    journal: NetworkJournal,
    revision: u64,
    record: Record,
    failed: bool,
    port_issued: bool,
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
            address: None,
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
            port_issued: false,
            context,
        })
    }
    pub fn allocate(&mut self) -> Result<(), Error> {
        if self.record.stage != Stage::Prepared || self.device.is_some() {
            return Err(Error::InvalidState);
        }
        tokio::runtime::Handle::try_current().map_err(|_| Error::NoRuntime)?;
        self.ready()?;
        node::verify()?;
        let device = match DeviceBuilder::new().mtu(MTU).enable(false).build_async() {
            Ok(device) => device,
            Err(error) => {
                self.failed = true;
                return Err(native_error(error));
            }
        };
        self.device = Some(Arc::new(device));
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
    /// Assign exactly one /32 while down. No connected prefix route or UP
    /// publication is authorized by this operation. Run in a retained worker.
    pub fn assign_ipv4(&mut self, value: Ipv4Addr, request: Request) -> Result<(), Error> {
        if !record::valid_address(value) {
            return Err(Error::InvalidAddress);
        }
        if !matches!(
            self.record.stage,
            Stage::Allocated | Stage::Named | Stage::Addressed | Stage::Enabled
        ) {
            return Err(Error::InvalidState);
        }
        if self
            .record
            .address
            .is_some_and(|previous| previous != value)
        {
            return Err(Error::InvalidState);
        }
        let wait = transaction::Wait::new(request).map_err(|cause| {
            Error::Address(AddressFailure {
                delivery: AddressDelivery::NotSent,
                cause,
            })
        })?;
        self.ready()?;
        self.verify_device()?;
        let index = self.identity.as_ref().ok_or(Error::InvalidState)?.index;
        let before = address::inspect(index, value, &wait).map_err(Error::Address)?;
        if matches!(self.record.stage, Stage::Addressed | Stage::Enabled) {
            return if before.matches == 1 && before.owned_exact == 1 {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if before.matches != 0 {
            return Err(Error::Conflict);
        }
        let mut intent = self.record.clone();
        intent.stage = Stage::Addressing;
        intent.address = Some(value);
        self.save(intent)?;
        let result = (|| {
            self.context.revalidate().map_err(Error::Context)?;
            self.verify_device()?;
            address::add(index, value, &wait).map_err(Error::Address)?;
            let after = address::inspect(index, value, &wait).map_err(|mut failure| {
                failure.delivery = AddressDelivery::Uncertain;
                Error::Address(failure)
            })?;
            if after.matches != 1 || after.owned_exact != 1 {
                return Err(Error::Conflict);
            }
            let mut committed = self.record.clone();
            committed.stage = Stage::Addressed;
            self.save(committed)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Set only IFF_UP after committed address ownership. No capture route is
    /// published here. Run in a retained worker and join across caller detach.
    pub fn enable(&mut self, request: Request) -> Result<(), Error> {
        if !matches!(self.record.stage, Stage::Addressed | Stage::Enabled) {
            return Err(Error::InvalidState);
        }
        let wait = transaction::Wait::new(request).map_err(|cause| {
            Error::Activation(NativeFailure {
                delivery: NativeDelivery::NotSent,
                cause,
            })
        })?;
        self.ready()?;
        self.verify_device()?;
        let index = self.identity.as_ref().ok_or(Error::InvalidState)?.index;
        let address = self.record.address.ok_or(Error::InvalidState)?;
        let verify_address = |wait: &transaction::Wait, delivery| -> Result<(), Error> {
            let observed = address::inspect(index, address, wait).map_err(|mut failure| {
                failure.delivery = delivery;
                Error::Activation(failure)
            })?;
            if observed.matches != 1 || observed.owned_exact != 1 {
                return Err(Error::Conflict);
            }
            Ok(())
        };
        verify_address(&wait, NativeDelivery::NotSent)?;
        let up = link::is_up(index, &wait).map_err(Error::Activation)?;
        if self.record.stage == Stage::Enabled {
            return if up { Ok(()) } else { Err(Error::Conflict) };
        }
        if up {
            return Err(Error::Conflict);
        }
        let mut intent = self.record.clone();
        intent.stage = Stage::Enabling;
        self.save(intent)?;
        let result = (|| {
            self.context.revalidate().map_err(Error::Context)?;
            self.verify_device()?;
            link::enable(index, &wait).map_err(Error::Activation)?;
            if !link::is_up(index, &wait).map_err(|mut failure| {
                failure.delivery = NativeDelivery::Uncertain;
                Error::Activation(failure)
            })? {
                return Err(Error::Conflict);
            }
            verify_address(&wait, NativeDelivery::Uncertain)?;
            self.verify_device()?;
            let mut committed = self.record.clone();
            committed.stage = Stage::Enabled;
            self.save(committed)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Issue exactly one bounded packet port after committed activation. The
    /// returned port retains the original descriptor and native runtime pin.
    pub fn packet_port(&mut self) -> Result<PacketPort, Error> {
        if self.port_issued || self.record.stage != Stage::Enabled {
            return Err(Error::InvalidState);
        }
        self.ready()?;
        self.verify_device()?;
        let device = self.device.as_ref().ok_or(Error::InvalidState)?.clone();
        self.port_issued = true;
        Ok(PacketPort::new(device, self.context.clone()))
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        if self
            .device
            .as_ref()
            .is_some_and(|device| Arc::strong_count(device) != 1)
        {
            return Err(Failure {
                primary: Error::PacketPortActive,
                cleanup: [None; 2],
            });
        }
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
                    ensure_index_absent(identity.index)?;
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
fn identity(device: &DeviceImpl) -> Result<Identity, Error> {
    let name = device.name().map_err(native_error)?;
    let index = device.if_index().map_err(native_error)?;
    if !record::valid_name(&name) || index == 0 || index > i32::MAX as u32 {
        return Err(Error::Conflict);
    }
    Ok(Identity { name, index })
}
fn ensure_index_absent(index: u32) -> Result<(), Error> {
    use rustix::net::{
        AddressFamily, SocketFlags, SocketType, netdevice::index_to_name_inlined, socket_with,
    };
    let socket = socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|error| native_error(error.into()))?;
    match index_to_name_inlined(socket, index) {
        Err(rustix::io::Errno::NODEV | rustix::io::Errno::NXIO) => Ok(()),
        Ok(_) => Err(Error::CleanupUncertain),
        Err(error) => Err(native_error(error.into())),
    }
}

fn native_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::AlreadyExists {
        Error::Conflict
    } else {
        Error::Io(error.kind())
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::*;
    #[test]
    fn missing_interface_index_is_not_reported_as_existing() {
        assert_eq!(
            ensure_index_absent(0),
            Ok(()),
            "Linux reserves index zero; absence must reach the retirement check"
        );
        let loopback = if_nametoindex("lo").unwrap();
        assert_eq!(ensure_index_absent(loopback), Err(Error::CleanupUncertain));
    }
}
