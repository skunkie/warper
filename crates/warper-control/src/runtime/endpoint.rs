// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Linux control listener publication and explicit retirement under a lease.
//! Drop closes sockets but leaves uncertain state for administrative recovery.

use std::{
    fmt,
    fs::File,
    io,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::net::UnixStream,
};

use rustix::{
    fs::{AtFlags, Mode, OFlags, ResolveFlags, chmodat, fstat, openat2, unlinkat},
    net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, accept_with, bind, listen,
        socket_with,
    },
};

use super::{RuntimeLease, named, require_same};
use crate::{Access, OwnerPolicy, Role};

const SOCKET: &str = "control.sock";
const INTENT: &str = "control.intent";
const BACKLOG: i32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Runtime(super::Error),
    Conflict,
    ChangedState,
    Io(io::ErrorKind),
    Peer(crate::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Runtime(_) => "SystemConfiguration: control runtime ownership failed",
            Self::Conflict => "Conflict: control endpoint or intent already exists",
            Self::ChangedState => "Conflict: owned control endpoint state changed",
            Self::Io(_) => "SystemConfiguration: control endpoint operation failed",
            Self::Peer(_) => "PermissionDenied: control peer authentication failed",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub primary: Error,
    pub cleanup: Option<Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.primary)?;
        if self.cleanup.is_some() {
            f.write_str("; endpoint cleanup also failed")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {}
impl From<Error> for Failure {
    fn from(primary: Error) -> Self {
        Self {
            primary,
            cleanup: None,
        }
    }
}

/// Only authenticated peers leave the listener. Authorize each decoded request
/// against the current owner policy again; Observe does not grant administration.
pub struct Accepted {
    pub stream: UnixStream,
    pub role: Role,
}

pub struct ControlEndpoint {
    listener: Option<OwnedFd>,
    socket: Option<OwnedFd>,
    socket_mode: Option<u32>,
    intent: OwnedFd,
    lease: RuntimeLease,
}

impl ControlEndpoint {
    /// Publish a nonblocking listener only after durable intent and final mode.
    /// Existing objects are conflicts, including stale sockets after a crash.
    pub fn bind(lease: RuntimeLease) -> Result<Self, Failure> {
        lease.revalidate().map_err(Error::Runtime)?;
        match named(&lease.directory, SOCKET) {
            Ok(_) => return Err(Error::Conflict.into()),
            Err(super::Error::Io(io::ErrorKind::NotFound)) => {}
            Err(error) => return Err(Error::Runtime(error).into()),
        }
        let intent = openat2(
            &lease.directory,
            INTENT,
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
                Error::Conflict
            } else {
                os_error(error)
            }
        })?;
        let mut endpoint = Self {
            listener: None,
            socket: None,
            socket_mode: None,
            intent,
            lease,
        };
        let result = endpoint.publish();
        if let Err(primary) = result {
            let cleanup = endpoint.retire().err();
            return Err(Failure { primary, cleanup });
        }
        Ok(endpoint)
    }

    pub fn accept(&self, policy: &OwnerPolicy) -> Result<Option<Accepted>, Error> {
        self.verify()?;
        let listener = self.listener.as_ref().ok_or(Error::ChangedState)?;
        let fd = match accept_with(listener, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::WOULDBLOCK) => return Ok(None),
            Err(error) => return Err(os_error(error)),
        };
        let stream = UnixStream::from(fd);
        let role = crate::unix::authenticate_client(&stream, policy, Access::Observe)
            .map_err(Error::Peer)?;
        Ok(Some(Accepted { stream, role }))
    }

    /// Close admission, then retire unchanged owned objects while holding flock.
    /// Caller must separately cancel/join all accepted connection tasks first.
    pub fn close(mut self) -> Result<(), Error> {
        self.listener.take();
        self.retire()
    }

    fn publish(&mut self) -> Result<(), Error> {
        self.verify_intent()?;
        rustix::fs::fsync(&self.intent).map_err(os_error)?;
        self.sync_directory()?;
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .map_err(os_error)?;
        // A descriptor-relative name avoids process-global cwd changes. Procfs
        // and the launch mount namespace are trusted as required by ADR 0009.
        let path = format!(
            "/proc/self/fd/{}/{SOCKET}",
            self.lease.directory.as_raw_fd()
        );
        let address = SocketAddrUnix::new(path).map_err(os_error)?;
        bind(&listener, &address).map_err(|error| {
            if error == rustix::io::Errno::ADDRINUSE {
                Error::Conflict
            } else {
                os_error(error)
            }
        })?;
        // Pin the pathname inode (not the unrelated sockfs descriptor inode).
        self.socket = Some(
            openat2(
                &self.lease.directory,
                SOCKET,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                resolution(),
            )
            .map_err(os_error)?,
        );
        self.socket_mode = Some(
            fstat(self.socket.as_ref().ok_or(Error::ChangedState)?)
                .map_err(os_error)?
                .st_mode
                & 0o7777,
        );
        self.verify_socket(false)?;
        // The directory is writable only by trusted root. No global umask is
        // changed; ordinary owners must be able to connect for OS peer checks.
        chmodat(
            &self.lease.directory,
            SOCKET,
            Mode::from_raw_mode(0o666),
            AtFlags::empty(),
        )
        .map_err(os_error)?;
        self.socket_mode = Some(0o666);
        self.verify_socket(true)?;
        self.sync_directory()?;
        listen(&listener, BACKLOG).map_err(os_error)?;
        self.listener = Some(listener);
        self.verify()
    }

    fn verify(&self) -> Result<(), Error> {
        self.lease.revalidate().map_err(Error::Runtime)?;
        self.verify_intent()?;
        self.verify_socket(true)
    }

    fn verify_intent(&self) -> Result<(), Error> {
        let metadata = fstat(&self.intent).map_err(os_error)?;
        super::validate_lock(&metadata, self.lease.owner).map_err(|_| Error::ChangedState)?;
        require_same(
            &metadata,
            &named(&self.lease.directory, INTENT).map_err(Error::Runtime)?,
        )
        .map_err(|_| Error::ChangedState)
    }

    fn verify_socket(&self, final_mode: bool) -> Result<(), Error> {
        let socket = self.socket.as_ref().ok_or(Error::ChangedState)?;
        let metadata = fstat(socket).map_err(os_error)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Socket
            || metadata.st_uid != self.lease.owner
            || metadata.st_nlink != 1
            || self.socket_mode != Some(metadata.st_mode & 0o7777)
            || (final_mode && metadata.st_mode & 0o7777 != 0o666)
        {
            return Err(Error::ChangedState);
        }
        require_same(
            &metadata,
            &named(&self.lease.directory, SOCKET).map_err(Error::Runtime)?,
        )
        .map_err(|_| Error::ChangedState)
    }

    fn retire(&mut self) -> Result<(), Error> {
        self.listener.take();
        self.lease.revalidate().map_err(Error::Runtime)?;
        self.verify_intent()?;
        if self.socket.is_some() {
            // Compare the recorded inode and mode even on partial publication.
            self.verify_socket(false)?;
            unlinkat(&self.lease.directory, SOCKET, AtFlags::empty()).map_err(os_error)?;
            self.socket.take();
        } else {
            match named(&self.lease.directory, SOCKET) {
                Err(super::Error::Io(io::ErrorKind::NotFound)) => {}
                Ok(_) => return Err(Error::ChangedState),
                Err(error) => return Err(Error::Runtime(error)),
            }
        }
        unlinkat(&self.lease.directory, INTENT, AtFlags::empty()).map_err(os_error)?;
        self.sync_directory()
    }

    fn sync_directory(&self) -> Result<(), Error> {
        let fd = openat2(
            &self.lease.directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?;
        File::from(fd)
            .sync_all()
            .map_err(|error| Error::Io(error.kind()))
    }
}

impl fmt::Debug for ControlEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlEndpoint(<redacted>)")
    }
}

fn resolution() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV
}
fn os_error(error: rustix::io::Errno) -> Error {
    Error::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}
