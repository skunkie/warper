// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native process/namespace evidence for platform journal ownership. Decoded
//! records are observations, never capabilities to change or recover the host.

use rustix::fs::{
    FileType, Mode, OFlags, ResolveFlags, fstat, fstatfs, open, openat, openat2, readlinkat_raw,
};
use std::{
    fmt,
    fs::File,
    io::{self, Read},
    os::fd::OwnedFd,
    sync::Arc,
};
use warper_control::runtime::{
    RuntimeLease,
    connection::{BootId, ConnectionStore},
};

const RECORD_LEN: usize = 88;
const PROCFS: u64 = 0x9fa0;
const NSFS: u64 = 0x6e736673;
const MAX_STAT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Runtime(warper_control::runtime::Error),
    Boot(warper_control::runtime::connection::Error),
    InvalidEvidence,
    InvalidRecord,
    ContextChanged,
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Runtime(_) => "Authentication: native context runtime ownership failed",
            Self::Boot(_) => "Authentication: native context boot identity failed",
            Self::InvalidEvidence => "NativeProtocol: invalid process or namespace evidence",
            Self::InvalidRecord => "InvalidConfig: invalid journal owner component",
            Self::ContextChanged => "Conflict: native journal context changed",
            Self::Io(_) => "NativeIo: cannot inspect journal owner context",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Eq, PartialEq)]
struct NamespaceId {
    device: u64,
    inode: u64,
}
impl fmt::Debug for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NamespaceId(<redacted>)")
    }
}
struct NamespacePin {
    _fd: OwnedFd,
    id: NamespaceId,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Process {
    pid: u32,
    start_ticks: u64,
}
impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessIdentity(<redacted>)")
    }
}
struct Scope {
    network: NamespacePin,
    pid: NamespacePin,
    process: Process,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecordedOwner {
    boot: [u8; 16],
    network: NamespaceId,
    pid_namespace: NamespaceId,
    instance: [u8; 16],
    process: Process,
}
impl RecordedOwner {
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut bytes = [0; RECORD_LEN];
        bytes[..4].copy_from_slice(b"WNOC");
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..24].copy_from_slice(&self.boot);
        bytes[24..32].copy_from_slice(&self.network.device.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.network.inode.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.pid_namespace.device.to_be_bytes());
        bytes[48..56].copy_from_slice(&self.pid_namespace.inode.to_be_bytes());
        bytes[56..72].copy_from_slice(&self.instance);
        bytes[72..76].copy_from_slice(&self.process.pid.to_be_bytes());
        bytes[76..84].copy_from_slice(&self.process.start_ticks.to_be_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RECORD_LEN
            || &bytes[..4] != b"WNOC"
            || bytes[4..8] != 1u32.to_be_bytes()
            || bytes[84..] != [0; 4]
        {
            return Err(Error::InvalidRecord);
        }
        let u64_at = |start| {
            bytes[start..start + 8]
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::InvalidRecord)
        };
        let recorded = Self {
            boot: bytes[8..24].try_into().map_err(|_| Error::InvalidRecord)?,
            network: NamespaceId {
                device: u64_at(24)?,
                inode: u64_at(32)?,
            },
            pid_namespace: NamespaceId {
                device: u64_at(40)?,
                inode: u64_at(48)?,
            },
            instance: bytes[56..72].try_into().map_err(|_| Error::InvalidRecord)?,
            process: Process {
                pid: u32::from_be_bytes(
                    bytes[72..76].try_into().map_err(|_| Error::InvalidRecord)?,
                ),
                start_ticks: u64_at(76)?,
            },
        };
        if recorded.boot == [0; 16]
            || recorded.instance == [0; 16]
            || recorded.network.inode == 0
            || recorded.pid_namespace.inode == 0
            || recorded.process.pid == 0
            || recorded.process.pid > i32::MAX as u32
        {
            return Err(Error::InvalidRecord);
        }
        Ok(recorded)
    }
}
impl fmt::Debug for RecordedOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordedOwner(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Classification {
    Current,
    PreviousInstance,
    ConflictingOwner,
    ForeignBoot,
    ForeignNamespace,
}

/// Retained native evidence. It cannot be constructed from serialized IDs.
///
/// ```compile_fail
/// use warper_service::linux::context::Context;
/// let context = Context::capture("/tmp/claimed-namespace");
/// ```
pub struct Context {
    scope: Scope,
    recorded: RecordedOwner,
    // Release native namespace pins before the last instance-lock reference.
    lease: Arc<RuntimeLease>,
}
impl Context {
    pub fn capture(lease: Arc<RuntimeLease>, connection: &ConnectionStore) -> Result<Self, Error> {
        lease.revalidate().map_err(Error::Runtime)?;
        let boot = BootId::current().map_err(Error::Boot)?;
        if boot != connection.boot_id() {
            return Err(Error::ContextChanged);
        }
        let scope = inspect_scope()?;
        let recorded = RecordedOwner {
            boot: *boot.as_bytes(),
            network: scope.network.id,
            pid_namespace: scope.pid.id,
            instance: connection.instance_id(),
            process: scope.process,
        };
        Ok(Self {
            scope,
            recorded,
            lease,
        })
    }
    pub fn revalidate(&self) -> Result<(), Error> {
        self.lease.revalidate().map_err(Error::Runtime)?;
        let current = inspect_scope()?;
        let boot = BootId::current().map_err(Error::Boot)?;
        if current.network.id != self.scope.network.id
            || current.pid.id != self.scope.pid.id
            || current.process != self.scope.process
            || boot.as_bytes() != &self.recorded.boot
        {
            return Err(Error::ContextChanged);
        }
        Ok(())
    }
    pub fn recorded_owner(&self) -> RecordedOwner {
        self.recorded
    }
    pub fn classify(&self, recorded: &RecordedOwner) -> Classification {
        classify(&self.recorded, recorded)
    }
}
impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeContext(<redacted>)")
    }
}

fn classify(current: &RecordedOwner, recorded: &RecordedOwner) -> Classification {
    if current.boot != recorded.boot {
        Classification::ForeignBoot
    } else if current.network != recorded.network || current.pid_namespace != recorded.pid_namespace
    {
        Classification::ForeignNamespace
    } else if current.instance != recorded.instance {
        Classification::PreviousInstance
    } else if current.process != recorded.process {
        Classification::ConflictingOwner
    } else {
        Classification::Current
    }
}
fn inspect_scope() -> Result<Scope, Error> {
    warper_control::namespace::require_initial_user_namespace()
        .map_err(|error| Error::Runtime(warper_control::runtime::Error::Admission(error)))?;
    let proc = open(
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(os_error)?;
    if fstatfs(&proc).map_err(os_error)?.f_type as u64 != PROCFS {
        return Err(Error::InvalidEvidence);
    }
    let network = namespace(&proc, "net")?;
    let pid = namespace(&proc, "pid")?;
    let input = openat2(
        &proc,
        "self/stat",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(os_error)?;
    if fstatfs(&input).map_err(os_error)?.f_type as u64 != PROCFS
        || FileType::from_raw_mode(fstat(&input).map_err(os_error)?.st_mode)
            != FileType::RegularFile
    {
        return Err(Error::InvalidEvidence);
    }
    let mut bytes = [0; MAX_STAT + 1];
    let mut length = 0;
    let mut input = File::from(input);
    while length < bytes.len() {
        let read = input
            .read(&mut bytes[length..])
            .map_err(|error| Error::Io(error.kind()))?;
        if read == 0 {
            break;
        }
        length += read;
    }
    if length > MAX_STAT {
        return Err(Error::InvalidEvidence);
    }
    let process = parse_stat(&bytes[..length], std::process::id())?;
    Ok(Scope {
        network,
        pid,
        process,
    })
}
fn namespace(proc: &OwnedFd, name: &str) -> Result<NamespacePin, Error> {
    let directory = openat2(
        proc,
        "thread-self/ns",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(os_error)?;
    let link = openat2(
        &directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(os_error)?;
    let metadata = fstat(&link).map_err(os_error)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Symlink
        || fstatfs(&link).map_err(os_error)?.f_type as u64 != PROCFS
        || metadata.st_dev != fstat(proc).map_err(os_error)?.st_dev
    {
        return Err(Error::InvalidEvidence);
    }
    let mut label = [0; 64];
    let length = readlinkat_raw(&link, "", &mut label).map_err(os_error)?;
    if length == label.len() {
        return Err(Error::InvalidEvidence);
    }
    let inode = parse_namespace(&label[..length], name)?;
    // Final traversal intentionally crosses from the checked fixed procfs link
    // into nsfs. Compare type, target inode and the still-pinned original link.
    let fd = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(os_error)?;
    let target = fstat(&fd).map_err(os_error)?;
    let mut again = [0; 64];
    let repeated = readlinkat_raw(&link, "", &mut again).map_err(os_error)?;
    if fstatfs(&fd).map_err(os_error)?.f_type as u64 != NSFS
        || FileType::from_raw_mode(target.st_mode) != FileType::RegularFile
        || target.st_ino != inode
        || repeated != length
        || again[..repeated] != label[..length]
    {
        return Err(Error::InvalidEvidence);
    }
    Ok(NamespacePin {
        _fd: fd,
        id: NamespaceId {
            device: target.st_dev,
            inode: target.st_ino,
        },
    })
}
fn parse_namespace(label: &[u8], name: &str) -> Result<u64, Error> {
    let prefix = match name {
        "net" => b"net:[".as_slice(),
        "pid" => b"pid:[".as_slice(),
        _ => return Err(Error::InvalidEvidence),
    };
    let digits = label
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(b"]"))
        .ok_or(Error::InvalidEvidence)?;
    if digits.first().is_none_or(|value| *value == b'0') {
        return Err(Error::InvalidEvidence);
    }
    decimal(digits)
}
fn parse_stat(bytes: &[u8], expected: u32) -> Result<Process, Error> {
    let open = bytes
        .iter()
        .position(|value| *value == b'(')
        .ok_or(Error::InvalidEvidence)?;
    if open < 2 || bytes[open - 1] != b' ' || decimal(&bytes[..open - 1])? != u64::from(expected) {
        return Err(Error::InvalidEvidence);
    }
    let close = bytes
        .iter()
        .rposition(|value| *value == b')')
        .filter(|value| *value > open)
        .ok_or(Error::InvalidEvidence)?;
    if bytes.get(close + 1) != Some(&b' ') {
        return Err(Error::InvalidEvidence);
    }
    let mut fields = bytes[close + 2..]
        .split(|value| value.is_ascii_whitespace())
        .filter(|value| !value.is_empty());
    let start = fields.nth(19).ok_or(Error::InvalidEvidence)?;
    Ok(Process {
        pid: expected,
        start_ticks: decimal(start)?,
    })
}
fn decimal(digits: &[u8]) -> Result<u64, Error> {
    if digits.is_empty() {
        return Err(Error::InvalidEvidence);
    }
    digits.iter().try_fold(0u64, |value, digit| {
        if !digit.is_ascii_digit() {
            return Err(Error::InvalidEvidence);
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(Error::InvalidEvidence)
    })
}
fn os_error(error: rustix::io::Errno) -> Error {
    Error::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}

#[cfg(test)]
mod tests;
