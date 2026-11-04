// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Journaled lifecycle of one fresh owned Linux TUN.
//! Native operations run in retained workers; the caller supervises traffic.

use super::context::{Context, RecordedOwner};
use nix::{errno::Errno, net::if_::if_nametoindex};
use std::{fmt, io, net::Ipv4Addr, sync::Arc};
use tun_rs::{AsyncDevice, DeviceBuilder, DeviceImpl};
use warper_control::runtime::journal::{Error as StorageError, NetworkJournal};
use warper_core::transport::Request;

mod address;
mod capture;
mod host_capture;
mod host_retirement;
mod link;
mod node;
mod packet;
use super::transaction;
pub use packet::{BUFFER_BYTES, Error as PacketError, PacketPort};
pub use transaction::{
    Cause as AddressCause, Delivery as AddressDelivery, Failure as AddressFailure,
};
pub use transaction::{Cause as NativeCause, Delivery as NativeDelivery, Failure as NativeFailure};
mod recovery;
pub(crate) use recovery::inspect_snapshot;
pub use recovery::{RecoveryInspection, RecoveryOutcome, inspect_abandoned, recover_abandoned};
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
    InvalidCapturePolicy,
    UnsupportedRules,
    RouteInspection(super::QueryError),
    Capture(NativeFailure),
    CaptureMonitor(super::change_monitor::Error),
    CaptureChanged(super::change_monitor::Invalidation),
    CaptureActive,
    CaptureFlowsActive,
    CaptureHostActive,
    DeviceUnavailable,
    DeviceInspection(io::ErrorKind),
    Conflict,
    InvalidState,
    NoRuntime,
    PacketPortActive,
    RecoveryRequired,
    OwnerAlive,
    RecoveryWait(NativeCause),
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
            Self::InvalidCapturePolicy => {
                "UnsupportedCapability: capture requires 1..4096 canonical IPv4 prefixes"
            }
            Self::UnsupportedRules => {
                "UnsupportedIntegration: capture requires ordinary IPv4 policy rules"
            }
            Self::RouteInspection(_) => "SystemConfiguration: capture route inspection failed",
            Self::Capture(_) => "SystemConfiguration: capture route transaction failed",
            Self::CaptureMonitor(_) => "SystemConfiguration: capture subscription failed",
            Self::CaptureChanged(_) => {
                "SystemConfiguration: capture state changed or became uncertain"
            }
            Self::CaptureActive => "Conflict: withdraw capture routes before closing the TUN",
            Self::CaptureFlowsActive => {
                "Conflict: quiesce and drain flows before withdrawing capture"
            }
            Self::CaptureHostActive => {
                "Conflict: capture host lacks unreferenced retirement ownership"
            }
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
            Self::OwnerAlive => "RecoveryRequired: recorded native owner is still alive",
            Self::RecoveryWait(_) => {
                "RecoveryRequired: abandoned owner inspection cancelled or expired"
            }
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
    capture_publication: Option<warper_stack::runtime::Publication>,
    capture_monitor: Option<super::change_monitor::Monitor>,
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
            capture: None,
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
            capture_publication: None,
            capture_monitor: None,
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
    /// Publish an exclusive static batch after the caller starts and retains
    /// the runtime and packet owners. Run in a retained native worker.
    pub fn publish_capture(
        &mut self,
        publication: warper_stack::runtime::Publication,
        request: Request,
    ) -> Result<(), Error> {
        if !matches!(self.record.stage, Stage::Enabled | Stage::Captured) || !self.port_issued {
            return Err(Error::InvalidState);
        }
        let wait = transaction::Wait::new(request.clone()).map_err(capture_cause)?;
        self.ready()?;
        self.verify_device()?;
        tokio::runtime::Handle::try_current().map_err(|_| Error::NoRuntime)?;
        let owner = self.record.owner.encode();
        let metric = 0x80000000 | u32::from_be_bytes([owner[56], owner[57], owner[58], owner[59]]);
        let plan = capture::Plan::new(&publication, metric)?;
        let index = self.index().ok_or(Error::InvalidState)?;
        if self.record.stage == Stage::Captured {
            if self.record.capture.as_ref() != Some(&plan)
                || self
                    .capture_publication
                    .as_ref()
                    .is_none_or(|current| !current.same_runtime(&publication))
            {
                return Err(Error::Conflict);
            }
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            plan.inspect(index, request, true)?;
            return self
                .capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged);
        }
        let mut before =
            super::change_monitor::Monitor::subscribe().map_err(Error::CaptureMonitor)?;
        plan.inspect(index, request.clone(), false)?;
        before.check_pending().map_err(Error::CaptureChanged)?;
        self.verify_capture_device(&wait)?;
        let mut intent = self.record.clone();
        intent.stage = Stage::Routing;
        intent.capture = Some(plan.clone());
        // Retain runtime identity before saving: uncertain persistence must not
        // permit closing the descriptor while accepted streams still exist.
        self.capture_publication = Some(publication);
        self.save(intent)?;
        let result = (|| {
            for prefix in &plan.prefixes {
                wait.check().map_err(capture_cause)?;
                self.context.revalidate().map_err(Error::Context)?;
                self.verify_device()?;
                let publication = self
                    .capture_publication
                    .as_ref()
                    .ok_or(Error::InvalidState)?;
                if !publication.is_published() || publication.is_quiescent() {
                    return Err(Error::InvalidState);
                }
                capture::add(*prefix, plan.metric, index, &wait)?;
            }
            // Own additions invalidate the initial subscription. Subscribe
            // again before fresh full verification rather than clearing events.
            drop(before);
            self.capture_monitor =
                Some(super::change_monitor::Monitor::subscribe().map_err(Error::CaptureMonitor)?);
            plan.inspect(index, request, true)?;
            self.verify_capture_device(&wait)?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            let publication = self
                .capture_publication
                .as_ref()
                .ok_or(Error::InvalidState)?;
            if !publication.is_published() || publication.is_quiescent() {
                return Err(Error::InvalidState);
            }
            let mut committed = self.record.clone();
            committed.stage = Stage::Captured;
            self.save(committed)?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Retain and supervise this monitor. A quiet check is momentary metadata,
    /// not permission to report service readiness or ignore later changes.
    pub fn capture_changes(&mut self) -> Result<&mut super::change_monitor::Monitor, Error> {
        self.capture_monitor.as_mut().ok_or(Error::InvalidState)
    }
    /// Quiescence and zero flow owners are necessary; the supervisor must also
    /// drain packet/grace work. Cleanup never adopts a changed route key.
    pub fn withdraw_capture(&mut self, request: Request) -> Result<(), Error> {
        let wait = transaction::Wait::new(request.clone()).map_err(capture_cause)?;
        if self.record.stage == Stage::Enabled
            && self.record.capture.is_none()
            && self.capture_publication.is_none()
        {
            self.check_storage()?;
            return self.verify_device();
        }
        let publication = self
            .capture_publication
            .as_ref()
            .ok_or(Error::InvalidState)?;
        if !publication.is_quiescent() || publication.retained_flows() != 0 {
            return Err(Error::CaptureFlowsActive);
        }
        self.check_storage()?;
        self.verify_device()?;
        let plan = self.record.capture.clone().ok_or(Error::RecoveryRequired)?;
        let index = self.index().ok_or(Error::InvalidState)?;
        let mut intent = self.record.clone();
        intent.stage = Stage::RoutesRetiring;
        self.save(intent)?;
        let result = (|| {
            capture::remove(&plan, index, request, &wait, || {
                self.context.revalidate().map_err(Error::Context)?;
                self.verify_device()
            })?;
            self.verify_device()?;
            let mut retired = self.record.clone();
            retired.stage = Stage::Enabled;
            retired.capture = None;
            self.save(retired)?;
            self.capture_publication = None;
            self.capture_monitor = None;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn verify_capture_device(&self, wait: &transaction::Wait) -> Result<(), Error> {
        self.context.revalidate().map_err(Error::Context)?;
        self.verify_device()?;
        let index = self.index().ok_or(Error::InvalidState)?;
        if !link::is_up(index, wait).map_err(Error::Capture)? {
            return Err(Error::Conflict);
        }
        let observed =
            address::inspect(index, self.record.address.ok_or(Error::InvalidState)?, wait)
                .map_err(Error::Capture)?;
        if observed.matches != 1 || observed.owned_exact != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        if self.record.capture.is_some() || self.capture_publication.is_some() {
            return Err(Failure {
                primary: Error::CaptureActive,
                cleanup: [None; 2],
            });
        }
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

fn capture_cause(cause: NativeCause) -> Error {
    Error::Capture(NativeFailure {
        delivery: NativeDelivery::NotSent,
        cause,
    })
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
