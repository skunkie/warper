// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed protected network-journal storage. Payload semantics belong to the
//! platform; durability does not authorize an OS action or establish ownership.

use super::{
    RuntimeLease, named,
    state::{self, StateDirectory},
};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, openat2, renameat, unlinkat,
};
use std::{
    cell::{Cell, RefCell},
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::{fd::OwnedFd, unix::fs::FileExt},
    sync::atomic::{AtomicU64, Ordering},
};

pub const MAX_PAYLOAD: usize = 65536;
const HEADER: usize = 24;
const MAX_FILE: usize = HEADER + MAX_PAYLOAD;
const CURRENT: &str = "network.journal";
const PENDING: &str = "network.pending";
static NEXT_STORE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Runtime(super::Error),
    UnsafeState,
    InvalidRecord,
    Conflict,
    ResourceLimit,
    RecoveryRequired,
    Io(io::ErrorKind),
    CommitUncertain(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Runtime(_) => "SystemConfiguration: journal runtime ownership failed",
            Self::UnsafeState => "Conflict: protected network journal changed or is unsafe",
            Self::InvalidRecord => "InvalidConfig: invalid network journal envelope",
            Self::Conflict => "Conflict: network journal revision changed",
            Self::ResourceLimit => "ResourceLimit: network journal capacity exhausted",
            Self::RecoveryRequired => "RecoveryRequired: network journal needs inspection",
            Self::Io(_) => "SystemConfiguration: network journal storage failed",
            Self::CommitUncertain(_) => "RecoveryRequired: network journal durability is uncertain",
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

#[derive(Clone, Eq, PartialEq)]
pub struct Snapshot {
    revision: u64,
    payload: Vec<u8>,
}
impl Snapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalSnapshot(<redacted>)")
    }
}
struct Pin {
    fd: OwnedFd,
    metadata: Stat,
}
struct Loaded {
    snapshot: Snapshot,
    pin: Pin,
}
#[derive(Clone)]
struct Observed {
    snapshot: Option<Snapshot>,
    metadata: Option<Stat>,
}
impl Observed {
    fn from_loaded(loaded: &Option<Loaded>) -> Self {
        Self {
            snapshot: loaded.as_ref().map(|loaded| loaded.snapshot.clone()),
            metadata: loaded.as_ref().map(|loaded| loaded.pin.metadata),
        }
    }
    fn same(&self, other: &Self) -> bool {
        self.snapshot == other.snapshot
            && match (&self.metadata, &other.metadata) {
                (None, None) => true,
                (Some(a), Some(b)) => unchanged(a, b),
                _ => false,
            }
    }
}

/// An opaque bounded recovery token. It cannot be deserialized or constructed
/// from a caller's path/metadata. Dropping it preserves all staged state.
pub struct PendingInspection {
    store: u64,
    directory: Stat,
    current: Option<Loaded>,
    pending: Pin,
    bytes: Vec<u8>,
}
impl PendingInspection {
    pub fn staged_length(&self) -> usize {
        self.bytes.len()
    }
    pub fn committed(&self) -> Option<&Snapshot> {
        self.current.as_ref().map(|current| &current.snapshot)
    }
}
impl fmt::Debug for PendingInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalPendingInspection(<redacted>)")
    }
}

/// All filesystem calls are synchronous. The service must serialize and retain
/// blocking workers and their runtime references, including after caller timeout.
/// No network state, credentials, raw configuration or packet data belongs here.
///
/// ```compile_fail
/// use warper_control::runtime::journal::NetworkJournal;
/// let journal = NetworkJournal::open("/tmp/claimed-journal");
/// ```
pub struct NetworkJournal {
    state: StateDirectory,
    id: u64,
    observed: RefCell<Option<Observed>>,
    uncertain: Cell<bool>,
}
impl NetworkJournal {
    pub fn open(lease: &RuntimeLease) -> Result<Self, Error> {
        Self::new(StateDirectory::open(lease)?)
    }
    fn new(state: StateDirectory) -> Result<Self, Error> {
        let id = NEXT_STORE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?;
        Ok(Self {
            state,
            id,
            observed: RefCell::new(None),
            uncertain: Cell::new(false),
        })
    }
    pub fn read(&self, lease: &RuntimeLease) -> Result<Option<Snapshot>, Error> {
        self.verify(lease)?;
        self.ready()?;
        Ok(self.observed_load()?.map(|loaded| loaded.snapshot))
    }
    /// Inspect committed state without promoting pending bytes or clearing an
    /// uncertain result. Changed prior observations remain conflicts.
    pub fn inspect(&self, lease: &RuntimeLease) -> Result<Option<Snapshot>, Error> {
        self.verify(lease)?;
        Ok(self.observed_load()?.map(|loaded| loaded.snapshot))
    }
    pub fn replace(
        &mut self,
        lease: &RuntimeLease,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<Snapshot, Error> {
        self.replace_with(
            lease,
            expected_revision,
            payload,
            || Ok(()),
            |journal| journal.sync(),
        )
    }
    /// Resync only the unchanged observed snapshot and directory. This accepts
    /// no new intent and never permits native work without platform inspection.
    pub fn resync(&mut self, lease: &RuntimeLease) -> Result<(), Error> {
        self.verify(lease)?;
        self.no_pending()?;
        let current = self.observed_load()?;
        if let Some(current) = current {
            self.verify_pin(CURRENT, &current.pin)?;
            let file = self.open_input(CURRENT, &current.pin.metadata)?;
            file.sync_all().map_err(io_error)?;
        }
        self.sync()?;
        self.uncertain.set(false);
        Ok(())
    }
    pub fn inspect_pending(
        &self,
        lease: &RuntimeLease,
    ) -> Result<Option<PendingInspection>, Error> {
        self.verify(lease)?;
        let current = self.observed_load()?;
        let Some((bytes, pending)) = self.load_bytes(PENDING, true)? else {
            return Ok(None);
        };
        let directory = fstat(&self.state.directory).map_err(os_error)?;
        Ok(Some(PendingInspection {
            store: self.id,
            directory,
            current,
            pending,
            bytes,
        }))
    }
    pub fn discard_pending(
        &mut self,
        lease: &RuntimeLease,
        token: PendingInspection,
    ) -> Result<(), Error> {
        self.discard_with(lease, token, |journal| journal.sync())
    }
    fn replace_with(
        &mut self,
        lease: &RuntimeLease,
        expected_revision: u64,
        payload: &[u8],
        after_stage: impl FnOnce() -> Result<(), Error>,
        commit_sync: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<Snapshot, Error> {
        if payload.is_empty() {
            return Err(Error::InvalidRecord);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::ResourceLimit);
        }
        self.verify(lease)?;
        self.ready()?;
        let before = self.observed_load()?;
        let revision = before.as_ref().map_or(0, |loaded| loaded.snapshot.revision);
        if revision != expected_revision {
            return Err(Error::Conflict);
        }
        let after = Snapshot {
            revision: revision.checked_add(1).ok_or(Error::ResourceLimit)?,
            payload: payload.to_vec(),
        };
        let bytes = encode(&after);
        let fd = openat2(
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
        // Any failure from this point preserves staging. Explicit inspected
        // discard is safer than guessing which partial bytes reached storage.
        let mut file = File::from(fd);
        check_file(&fstat(&file).map_err(os_error)?, self.state.owner, true)?;
        file.write_all(&bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        self.sync()?;
        after_stage()?;
        self.verify(lease)?;
        drop(self.observed_load()?);
        if let Some(before) = before {
            self.verify_pin(CURRENT, &before.pin)?;
        }
        let pending = Pin {
            metadata: fstat(&file).map_err(os_error)?,
            fd: file.try_clone().map_err(io_error)?.into(),
        };
        self.verify_pin(PENDING, &pending)?;
        if pending.metadata.st_size as usize != bytes.len() {
            return Err(Error::UnsafeState);
        }
        let mut readback = vec![0; bytes.len()];
        file.read_exact_at(&mut readback, 0).map_err(io_error)?;
        if readback != bytes {
            return Err(Error::UnsafeState);
        }
        self.verify_pin(PENDING, &pending)?;
        renameat(
            &self.state.directory,
            PENDING,
            &self.state.directory,
            CURRENT,
        )
        .map_err(os_error)?;
        self.uncertain.set(true);
        *self.observed.borrow_mut() = Some(Observed {
            snapshot: Some(after.clone()),
            metadata: Some(fstat(&file).map_err(os_error)?),
        });
        commit_sync(self).map_err(uncertain_error)?;
        self.uncertain.set(false);
        Ok(after)
    }
    fn discard_with(
        &mut self,
        lease: &RuntimeLease,
        token: PendingInspection,
        sync: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.verify(lease)?;
        if token.store != self.id
            || !same_directory(
                &token.directory,
                &fstat(&self.state.directory).map_err(os_error)?,
            )
        {
            return Err(Error::Conflict);
        }
        let current = self.observed_load()?;
        if !Observed::from_loaded(&token.current).same(&Observed::from_loaded(&current)) {
            return Err(Error::UnsafeState);
        }
        if let Some(current) = token.current {
            self.verify_pin(CURRENT, &current.pin)?;
        }
        self.verify_pin(PENDING, &token.pending)?;
        let (bytes, pin) = self.load_bytes(PENDING, true)?.ok_or(Error::UnsafeState)?;
        if bytes != token.bytes || !unchanged(&token.pending.metadata, &pin.metadata) {
            return Err(Error::UnsafeState);
        }
        self.verify(lease)?;
        self.verify_pin(PENDING, &token.pending)?;
        unlinkat(&self.state.directory, PENDING, AtFlags::empty()).map_err(os_error)?;
        self.uncertain.set(true);
        sync(self).map_err(uncertain_error)?;
        self.uncertain.set(false);
        Ok(())
    }
    fn verify(&self, lease: &RuntimeLease) -> Result<(), Error> {
        lease.revalidate().map_err(Error::Runtime)?;
        self.state.verify().map_err(Error::from)
    }
    fn ready(&self) -> Result<(), Error> {
        if self.uncertain.get() {
            return Err(Error::RecoveryRequired);
        }
        self.no_pending()
    }
    fn no_pending(&self) -> Result<(), Error> {
        match named(&self.state.directory, PENDING) {
            Err(super::Error::Io(io::ErrorKind::NotFound)) => Ok(()),
            Ok(_) => Err(Error::RecoveryRequired),
            Err(error) => Err(Error::Runtime(error)),
        }
    }
    fn observed_load(&self) -> Result<Option<Loaded>, Error> {
        let current = self.load()?;
        let observed = Observed::from_loaded(&current);
        if self
            .observed
            .borrow()
            .as_ref()
            .is_some_and(|before| !before.same(&observed))
        {
            return Err(Error::UnsafeState);
        }
        *self.observed.borrow_mut() = Some(observed);
        Ok(current)
    }
    fn load(&self) -> Result<Option<Loaded>, Error> {
        self.load_bytes(CURRENT, false)?
            .map(|(bytes, pin)| {
                Ok(Loaded {
                    snapshot: decode(&bytes)?,
                    pin,
                })
            })
            .transpose()
    }
    fn load_bytes(&self, name: &str, partial: bool) -> Result<Option<(Vec<u8>, Pin)>, Error> {
        let fd = match openat2(
            &self.state.directory,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(os_error(error)),
        };
        let metadata = fstat(&fd).map_err(os_error)?;
        check_file(&metadata, self.state.owner, partial)?;
        let mut file = self.open_input(name, &metadata)?;
        let mut bytes = vec![0; MAX_FILE + 1];
        let mut length = 0;
        while length < bytes.len() {
            let read = file.read(&mut bytes[length..]).map_err(io_error)?;
            if read == 0 {
                break;
            }
            length += read;
        }
        bytes.truncate(length);
        let pin = Pin { fd, metadata };
        self.verify_pin(name, &pin)?;
        if bytes.len() != metadata.st_size as usize {
            return Err(Error::UnsafeState);
        }
        Ok(Some((bytes, pin)))
    }
    fn open_input(&self, name: &str, metadata: &Stat) -> Result<File, Error> {
        let input = openat2(
            &self.state.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?;
        if !unchanged(metadata, &fstat(&input).map_err(os_error)?) {
            return Err(Error::UnsafeState);
        }
        Ok(File::from(input))
    }
    fn verify_pin(&self, name: &str, pin: &Pin) -> Result<(), Error> {
        let actual = fstat(&pin.fd).map_err(os_error)?;
        check_file(&actual, self.state.owner, true)?;
        if !unchanged(&pin.metadata, &actual)
            || !unchanged(
                &pin.metadata,
                &named(&self.state.directory, name).map_err(Error::Runtime)?,
            )
        {
            return Err(Error::UnsafeState);
        }
        Ok(())
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
impl fmt::Debug for NetworkJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NetworkJournal(<redacted>)")
    }
}
fn encode(snapshot: &Snapshot) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + snapshot.payload.len());
    bytes.extend_from_slice(b"WJNL");
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&snapshot.revision.to_be_bytes());
    bytes.extend_from_slice(&(snapshot.payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&snapshot.payload);
    bytes
}
fn decode(bytes: &[u8]) -> Result<Snapshot, Error> {
    if !(HEADER + 1..=MAX_FILE).contains(&bytes.len())
        || &bytes[..4] != b"WJNL"
        || bytes[4..8] != 1u32.to_be_bytes()
        || bytes[20..24] != [0; 4]
    {
        return Err(Error::InvalidRecord);
    }
    let revision = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| Error::InvalidRecord)?);
    let length =
        u32::from_be_bytes(bytes[16..20].try_into().map_err(|_| Error::InvalidRecord)?) as usize;
    if revision == 0 || length != bytes.len() - HEADER {
        return Err(Error::InvalidRecord);
    }
    Ok(Snapshot {
        revision,
        payload: bytes[HEADER..].to_vec(),
    })
}
fn check_file(metadata: &Stat, owner: u32, partial: bool) -> Result<(), Error> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != owner
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
        || !(0..=MAX_FILE as i64).contains(&metadata.st_size)
        || (!partial && metadata.st_size <= (HEADER as i64))
    {
        return Err(Error::UnsafeState);
    }
    Ok(())
}
fn unchanged(a: &Stat, b: &Stat) -> bool {
    same_directory(a, b)
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}
fn same_directory(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
}
fn resolution() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV
}
fn os_error(error: rustix::io::Errno) -> Error {
    io_error(io::Error::from_raw_os_error(error.raw_os_error()))
}
fn io_error(error: io::Error) -> Error {
    Error::Io(error.kind())
}
fn uncertain_error(error: Error) -> Error {
    match error {
        Error::Io(kind) => Error::CommitUncertain(kind),
        other => other,
    }
}

#[cfg(test)]
mod tests;
