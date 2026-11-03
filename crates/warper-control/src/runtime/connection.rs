// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Durable accepted intent, distinct from actual network readiness or RPC auth.

use super::{
    RuntimeLease, named, require_same,
    state::{self, StateDirectory},
};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, openat2, renameat, unlinkat,
};
use std::{
    cell::Cell,
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::{fd::OwnedFd, unix::fs::FileExt},
};

mod identity;
mod recovery;
pub use identity::BootId;
pub use recovery::PendingInspection;

const CURRENT: &str = "connection";
const PENDING: &str = "connection.pending";
const RECORD_LEN: usize = 80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Runtime(super::Error),
    Identity(crate::Error),
    UnsafeState,
    InvalidRecord,
    InvalidRequest,
    Conflict,
    RevisionExhausted,
    RecoveryRequired,
    InvalidBoot,
    Entropy(io::ErrorKind),
    EntropyIncomplete,
    Io(io::ErrorKind),
    CommitUncertain(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Runtime(_) => "SystemConfiguration: connection intent runtime ownership failed",
            Self::Identity(_) | Self::InvalidBoot => {
                "Authentication: native connection boot identity is unavailable"
            }
            Self::UnsafeState => "Conflict: protected connection state is unsafe or changed",
            Self::InvalidRecord | Self::InvalidRequest => {
                "InvalidConfig: connection intent record or request is invalid"
            }
            Self::Conflict => "Conflict: connection intent instance, revision or operation changed",
            Self::RevisionExhausted => "ResourceLimit: desired-state revision exhausted",
            Self::RecoveryRequired => {
                "RecoveryRequired: pending connection intent requires inspection"
            }
            Self::Entropy(_) | Self::EntropyIncomplete => {
                "Entropy: native service instance randomness is unavailable"
            }
            Self::Io(_) => "SystemConfiguration: connection intent storage operation failed",
            Self::CommitUncertain(_) => {
                "RecoveryRequired: connection intent durability is uncertain"
            }
        })
    }
}
impl std::error::Error for Error {}
impl From<state::Error> for Error {
    fn from(error: state::Error) -> Self {
        match error {
            state::Error::Runtime(error) => Self::Runtime(error),
            state::Error::UnsafeState => Self::UnsafeState,
            state::Error::Io(kind) => Self::Io(kind),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub primary: Error,
    pub cleanup: Option<Error>,
}
impl From<Error> for Failure {
    fn from(primary: Error) -> Self {
        Self {
            primary,
            cleanup: None,
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.primary)?;
        if self.cleanup.is_some() {
            f.write_str("; connection intent cleanup also failed")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Desired {
    Down,
    Up,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Snapshot {
    revision: u64,
    boot: BootId,
    instance: [u8; 16],
    operation: [u8; 16],
    configuration: u64,
    desired: Desired,
}
impl Snapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn configuration_generation(&self) -> u64 {
        self.configuration
    }
    pub fn desired(&self) -> Desired {
        self.desired
    }
    pub fn same_boot(&self, boot: &BootId) -> bool {
        self.boot == *boot
    }
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionSnapshot(<redacted>)")
    }
}
#[derive(Clone, Copy)]
pub struct Request {
    pub operation: [u8; 16],
    pub expected_configuration: u64,
    pub expected_revision: u64,
    pub expected_instance: [u8; 16],
    pub desired: Desired,
}
impl Request {
    pub fn from_frame(frame: &crate::wire::Frame) -> Result<Self, Error> {
        let desired = match frame.kind() {
            crate::wire::Kind::Connect => Desired::Up,
            crate::wire::Kind::Disconnect => Desired::Down,
            _ => return Err(Error::InvalidRequest),
        };
        let bytes = frame.body();
        Ok(Self {
            operation: bytes[..16].try_into().map_err(|_| Error::InvalidRequest)?,
            expected_configuration: u64::from_be_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| Error::InvalidRequest)?,
            ),
            expected_revision: u64::from_be_bytes(
                bytes[24..32]
                    .try_into()
                    .map_err(|_| Error::InvalidRequest)?,
            ),
            expected_instance: bytes[32..48]
                .try_into()
                .map_err(|_| Error::InvalidRequest)?,
            desired,
        })
    }
}
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionRequest(<redacted>)")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acceptance {
    Accepted(Snapshot),
    AlreadyAccepted(Snapshot),
}
struct Pin {
    fd: OwnedFd,
    metadata: Stat,
}
#[derive(Clone, Copy)]
struct Observed {
    record: Option<Snapshot>,
    metadata: Option<Stat>,
}
impl Observed {
    fn from_current(current: &Option<(Snapshot, Pin)>) -> Self {
        match current {
            Some((record, pin)) => Self {
                record: Some(*record),
                metadata: Some(pin.metadata),
            },
            None => Self {
                record: None,
                metadata: None,
            },
        }
    }
    fn same(self, other: Self) -> bool {
        self.record == other.record
            && match (self.metadata, other.metadata) {
                (Some(a), Some(b)) => unchanged(&a, &b),
                (None, None) => true,
                _ => false,
            }
    }
}

/// Root service persistence under the runtime lease. Authenticate requests and
/// compare the approved configuration generation before invoking acceptance.
/// No public path/boot/instance override exists; operations spawn no tasks.
///
/// ```compile_fail
/// use warper_control::runtime::{RuntimeLease, connection::ConnectionStore};
/// fn redirect(lease: &RuntimeLease) {
///     let _ = ConnectionStore::open(lease, "/tmp/untrusted-intent");
/// }
/// ```
pub struct ConnectionStore {
    state: StateDirectory,
    boot: BootId,
    instance: [u8; 16],
    observed: Cell<Option<Observed>>,
    uncertain: Cell<bool>,
}
impl ConnectionStore {
    pub fn open(lease: &RuntimeLease) -> Result<Self, Error> {
        let state = StateDirectory::open(lease).map_err(Error::from)?;
        Ok(Self {
            state,
            boot: BootId::current()?,
            instance: identity::instance()?,
            observed: Cell::new(None),
            uncertain: Cell::new(false),
        })
    }
    pub fn read(&self, lease: &RuntimeLease) -> Result<Option<Snapshot>, Error> {
        self.verify(lease)?;
        if self.uncertain.get() {
            return Err(Error::RecoveryRequired);
        }
        self.inspect(lease)
    }
    /// Inspect an uncertain acceptance without treating it as usable intent.
    pub fn inspect(&self, lease: &RuntimeLease) -> Result<Option<Snapshot>, Error> {
        self.verify(lease)?;
        self.no_pending()?;
        Ok(self.observed_load()?.map(|(record, _)| record))
    }
    /// Make the unchanged inspected file/directory durable, without accepting
    /// another operation or performing any network action.
    pub fn resync(&mut self, lease: &RuntimeLease) -> Result<(), Error> {
        self.uncertain.set(true);
        let result = (|| {
            self.verify(lease)?;
            self.no_pending()?;
            if let Some((_record, pin)) = self.observed_load()? {
                let fd = openat2(
                    &self.state.directory,
                    CURRENT,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                    resolution(),
                )
                .map_err(os_error)?;
                if !unchanged(&pin.metadata, &fstat(&fd).map_err(os_error)?) {
                    return Err(Error::UnsafeState);
                }
                rustix::fs::fsync(&fd).map_err(os_error)?;
                self.verify(lease)?;
                if !unchanged(
                    &pin.metadata,
                    &named(&self.state.directory, CURRENT).map_err(Error::Runtime)?,
                ) {
                    return Err(Error::UnsafeState);
                }
            }
            self.sync()
        })()
        .map_err(|error| match error {
            Error::Io(kind) => Error::CommitUncertain(kind),
            other => other,
        });
        if result.is_ok() {
            self.uncertain.set(false);
        }
        result
    }
    pub fn accept(
        &mut self,
        lease: &RuntimeLease,
        current_configuration: u64,
        request: Request,
    ) -> Result<Acceptance, Failure> {
        self.accept_with_sync(lease, current_configuration, request, Self::sync)
    }
    pub fn instance_id(&self) -> [u8; 16] {
        self.instance
    }
    pub fn boot_id(&self) -> BootId {
        self.boot
    }

    fn accept_with_sync(
        &mut self,
        lease: &RuntimeLease,
        current_configuration: u64,
        request: Request,
        commit_sync: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<Acceptance, Failure> {
        self.accept_staged(
            lease,
            current_configuration,
            request,
            || Ok(()),
            commit_sync,
        )
    }

    fn accept_staged(
        &mut self,
        lease: &RuntimeLease,
        current_configuration: u64,
        request: Request,
        after_stage: impl FnOnce() -> Result<(), Error>,
        commit_sync: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<Acceptance, Failure> {
        self.verify(lease)?;
        if self.uncertain.get() {
            return Err(Error::RecoveryRequired.into());
        }
        if !nonzero(&request.operation)
            || !nonzero(&request.expected_instance)
            || (request.desired == Desired::Up && request.expected_configuration == 0)
        {
            return Err(Error::InvalidRequest.into());
        }
        if request.expected_instance != self.instance
            || request.expected_configuration != current_configuration
            || !operation_revision(&request.operation, request.expected_revision)
        {
            return Err(Error::Conflict.into());
        }
        self.no_pending()?;
        let before = self.observed_load()?;
        if let Some((record, _)) = &before
            && record.operation == request.operation
        {
            return if record.instance == self.instance
                && record.configuration == request.expected_configuration
                && record.desired == request.desired
                && record.revision.checked_sub(1) == Some(request.expected_revision)
            {
                Ok(Acceptance::AlreadyAccepted(*record))
            } else {
                Err(Error::Conflict.into())
            };
        }
        let revision = before.as_ref().map_or(0, |(record, _)| record.revision);
        if request.expected_revision != revision {
            return Err(Error::Conflict.into());
        }
        let after = Snapshot {
            revision: revision.checked_add(1).ok_or(Error::RevisionExhausted)?,
            boot: self.boot,
            instance: self.instance,
            operation: request.operation,
            configuration: request.expected_configuration,
            desired: request.desired,
        };
        let pending = openat2(
            &self.state.directory,
            PENDING,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            resolution(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                Error::RecoveryRequired
            } else {
                os_error(error)
            }
        })?;
        let mut pending = File::from(pending);
        let mut published = false;
        let result = (|| {
            check_file(&fstat(&pending).map_err(os_error)?, self.state.owner, 0)?;
            let bytes = encode(after);
            pending.write_all(&bytes).map_err(|e| Error::Io(e.kind()))?;
            pending.sync_all().map_err(|e| Error::Io(e.kind()))?;
            self.sync()?;
            after_stage()?;
            self.verify(lease)?;
            let current = self.load()?;
            match (&before, &current) {
                (None, None) => {}
                (Some((old, old_pin)), Some((new, new_pin))) if old == new => {
                    if !unchanged(&old_pin.metadata, &fstat(&old_pin.fd).map_err(os_error)?)
                        || !unchanged(&old_pin.metadata, &new_pin.metadata)
                    {
                        return Err(Error::UnsafeState);
                    }
                }
                _ => return Err(Error::Conflict),
            }
            self.verify_pending(&pending)?;
            let mut actual = [0; RECORD_LEN];
            pending
                .read_exact_at(&mut actual, 0)
                .map_err(|e| Error::Io(e.kind()))?;
            if actual != bytes {
                return Err(Error::UnsafeState);
            }
            renameat(
                &self.state.directory,
                PENDING,
                &self.state.directory,
                CURRENT,
            )
            .map_err(os_error)?;
            published = true;
            self.uncertain.set(true);
            self.observed.set(Some(Observed {
                record: Some(after),
                metadata: Some(fstat(&pending).map_err(os_error)?),
            }));
            commit_sync(self).map_err(|error| match error {
                Error::Io(kind) => Error::CommitUncertain(kind),
                other => other,
            })?;
            self.uncertain.set(false);
            Ok(Acceptance::Accepted(after))
        })();
        result.map_err(|primary| Failure {
            primary,
            cleanup: if published {
                None
            } else {
                self.remove_pending(lease, &pending).err()
            },
        })
    }
    fn verify(&self, lease: &RuntimeLease) -> Result<(), Error> {
        lease.revalidate().map_err(Error::Runtime)?;
        self.state.verify().map_err(Error::from)
    }
    fn no_pending(&self) -> Result<(), Error> {
        match named(&self.state.directory, PENDING) {
            Err(super::Error::Io(io::ErrorKind::NotFound)) => Ok(()),
            Ok(_) => Err(Error::RecoveryRequired),
            Err(error) => Err(Error::Runtime(error)),
        }
    }
    fn observed_load(&self) -> Result<Option<(Snapshot, Pin)>, Error> {
        let current = self.load()?;
        let observed = Observed::from_current(&current);
        if self
            .observed
            .get()
            .is_some_and(|before| !before.same(observed))
        {
            return Err(Error::UnsafeState);
        }
        self.observed.set(Some(observed));
        Ok(current)
    }
    fn load(&self) -> Result<Option<(Snapshot, Pin)>, Error> {
        let fd = match openat2(
            &self.state.directory,
            CURRENT,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(os_error(error)),
        };
        let metadata = fstat(&fd).map_err(os_error)?;
        check_file(&metadata, self.state.owner, RECORD_LEN as u64)?;
        let input = openat2(
            &self.state.directory,
            CURRENT,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?;
        if !unchanged(&metadata, &fstat(&input).map_err(os_error)?) {
            return Err(Error::UnsafeState);
        }
        let mut bytes = Vec::with_capacity(RECORD_LEN + 1);
        File::from(input)
            .take((RECORD_LEN + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Io(e.kind()))?;
        if !unchanged(&metadata, &fstat(&fd).map_err(os_error)?)
            || !unchanged(
                &metadata,
                &named(&self.state.directory, CURRENT).map_err(Error::Runtime)?,
            )
        {
            return Err(Error::UnsafeState);
        }
        Ok(Some((decode(&bytes)?, Pin { fd, metadata })))
    }
    fn verify_pending(&self, file: &File) -> Result<(), Error> {
        let metadata = fstat(file).map_err(os_error)?;
        check_file(&metadata, self.state.owner, metadata.st_size as u64)?;
        if !(0..=RECORD_LEN as i64).contains(&metadata.st_size) {
            return Err(Error::UnsafeState);
        }
        require_same(
            &metadata,
            &named(&self.state.directory, PENDING).map_err(Error::Runtime)?,
        )
        .map_err(|_| Error::UnsafeState)
    }
    fn remove_pending(&self, lease: &RuntimeLease, file: &File) -> Result<(), Error> {
        self.verify(lease)?;
        self.verify_pending(file)?;
        unlinkat(&self.state.directory, PENDING, AtFlags::empty()).map_err(os_error)?;
        self.sync()
    }
    fn sync(&self) -> Result<(), Error> {
        let fd = openat2(
            &self.state.directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?;
        rustix::fs::fsync(fd).map_err(os_error)
    }
}
impl fmt::Debug for ConnectionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionStore(<redacted>)")
    }
}
fn operation_revision(operation: &[u8; 16], revision: u64) -> bool {
    operation[..8] == revision.to_be_bytes() && nonzero(&operation[8..])
}
fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}
fn unchanged(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}
fn check_file(metadata: &Stat, owner: u32, size: u64) -> Result<(), Error> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != owner
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
        || metadata.st_size as u64 != size
    {
        return Err(Error::UnsafeState);
    }
    Ok(())
}
fn resolution() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV
}
fn os_error(error: rustix::io::Errno) -> Error {
    Error::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}
fn encode(record: Snapshot) -> [u8; RECORD_LEN] {
    let mut bytes = [0; RECORD_LEN];
    bytes[..4].copy_from_slice(b"WCIN");
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[8..16].copy_from_slice(&record.revision.to_be_bytes());
    bytes[16..32].copy_from_slice(&record.boot.0);
    bytes[32..48].copy_from_slice(&record.instance);
    bytes[48..64].copy_from_slice(&record.operation);
    bytes[64..72].copy_from_slice(&record.configuration.to_be_bytes());
    bytes[72] = u8::from(record.desired == Desired::Up);
    bytes
}
fn decode(bytes: &[u8]) -> Result<Snapshot, Error> {
    let bytes: &[u8; RECORD_LEN] = bytes.try_into().map_err(|_| Error::InvalidRecord)?;
    if &bytes[..4] != b"WCIN"
        || bytes[4..8] != 1u32.to_be_bytes()
        || bytes[73..].iter().any(|byte| *byte != 0)
    {
        return Err(Error::InvalidRecord);
    }
    let record = Snapshot {
        revision: u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| Error::InvalidRecord)?),
        boot: BootId(bytes[16..32].try_into().map_err(|_| Error::InvalidRecord)?),
        instance: bytes[32..48].try_into().map_err(|_| Error::InvalidRecord)?,
        operation: bytes[48..64].try_into().map_err(|_| Error::InvalidRecord)?,
        configuration: u64::from_be_bytes(
            bytes[64..72].try_into().map_err(|_| Error::InvalidRecord)?,
        ),
        desired: match bytes[72] {
            0 => Desired::Down,
            1 => Desired::Up,
            _ => return Err(Error::InvalidRecord),
        },
    };
    if record.revision == 0
        || !nonzero(&record.boot.0)
        || !nonzero(&record.instance)
        || !nonzero(&record.operation)
        || !record
            .revision
            .checked_sub(1)
            .is_some_and(|revision| operation_revision(&record.operation, revision))
        || (record.desired == Desired::Up && record.configuration == 0)
    {
        return Err(Error::InvalidRecord);
    }
    Ok(record)
}

#[cfg(test)]
mod tests;
