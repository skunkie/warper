// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed protected endpoint admission before sending any client payload.

use super::{named, open_directory, require_same, validate_directory};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat2};
use std::{
    fmt, io,
    os::fd::{AsRawFd, OwnedFd},
};
use tokio::{
    net::UnixStream,
    sync::watch,
    time::{Instant, timeout_at},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Admission(crate::Error),
    UnsafeEndpoint,
    Io(io::ErrorKind),
    Timeout,
    Cancelled,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Admission(_) => "Authentication: control service identity verification failed",
            Self::UnsafeEndpoint => {
                "PermissionDenied: control endpoint metadata is unsafe or changed"
            }
            Self::Io(_) => "ServiceUnavailable: control endpoint connection failed",
            Self::Timeout => "Timeout: control endpoint connection expired",
            Self::Cancelled => "Cancelled: control endpoint connection cancelled",
        })
    }
}
impl std::error::Error for Error {}

/// Connect only to the fixed protected Linux endpoint and authenticate real
/// initial-namespace root before returning a stream. Sends no payload. The
/// caller must negotiate the wire version before transferring configuration.
///
/// Filesystem/procfs inspection is synchronous; the deadline bounds admission
/// checks and asynchronous connect, not a stalled kernel filesystem operation.
///
/// ```compile_fail
/// use warper_control::runtime::client;
/// let _ = client::connect("/tmp/untrusted.sock");
/// ```
pub async fn connect(
    deadline: Instant,
    cancel: watch::Receiver<bool>,
) -> Result<UnixStream, Error> {
    check(deadline, &cancel)?;
    crate::namespace::require_initial_user_namespace().map_err(Error::Admission)?;
    let root = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(os_error)?;
    let endpoint = Endpoint::open_at(root, 0)?;
    endpoint.connect(deadline, cancel).await
}

struct Endpoint {
    root: OwnedFd,
    run: OwnedFd,
    directory: OwnedFd,
    socket: OwnedFd,
    owner: u32,
}
impl Endpoint {
    fn open_at(root: OwnedFd, owner: u32) -> Result<Self, Error> {
        validate_directory(&fstat(&root).map_err(os_error)?, owner, false)
            .map_err(|_| Error::UnsafeEndpoint)?;
        let run = open_directory(&root, "run", false).map_err(runtime_error)?;
        validate_directory(&fstat(&run).map_err(os_error)?, owner, false)
            .map_err(|_| Error::UnsafeEndpoint)?;
        let directory = open_directory(&run, "warper", true).map_err(runtime_error)?;
        validate_directory(&fstat(&directory).map_err(os_error)?, owner, true)
            .map_err(|_| Error::UnsafeEndpoint)?;
        let socket = openat2(
            &directory,
            "control.sock",
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )
        .map_err(os_error)?;
        let endpoint = Self {
            root,
            run,
            directory,
            socket,
            owner,
        };
        endpoint.verify()?;
        Ok(endpoint)
    }
    async fn connect(
        &self,
        deadline: Instant,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<UnixStream, Error> {
        check(deadline, &cancel)?;
        self.verify()?;
        // Connect through the pinned pathname inode, even if trusted root
        // renames a directory while async connection setup is pending.
        let path = format!("/proc/self/fd/{}", self.socket.as_raw_fd());
        let stream = tokio::select! {
            biased;
            ()=cancelled(&mut cancel)=>return Err(Error::Cancelled),
            result=timeout_at(deadline, UnixStream::connect(path))=>result.map_err(|_|Error::Timeout)?.map_err(|e|Error::Io(e.kind()))?,
        };
        let stream = stream.into_std().map_err(|e| Error::Io(e.kind()))?;
        crate::unix::authenticate_service(&stream).map_err(Error::Admission)?;
        self.verify()?;
        check(deadline, &cancel)?;
        UnixStream::from_std(stream).map_err(|e| Error::Io(e.kind()))
    }
    fn verify(&self) -> Result<(), Error> {
        validate_directory(&fstat(&self.root).map_err(os_error)?, self.owner, false)
            .map_err(|_| Error::UnsafeEndpoint)?;
        for (parent, name, fd, protected) in [
            (&self.root, "run", &self.run, false),
            (&self.run, "warper", &self.directory, true),
        ] {
            let metadata = fstat(fd).map_err(os_error)?;
            validate_directory(&metadata, self.owner, protected)
                .map_err(|_| Error::UnsafeEndpoint)?;
            require_same(&metadata, &named(parent, name).map_err(runtime_error)?)
                .map_err(|_| Error::UnsafeEndpoint)?;
        }
        let metadata = fstat(&self.socket).map_err(os_error)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket
            || metadata.st_uid != self.owner
            || metadata.st_mode & 0o7777 != 0o666
            || metadata.st_nlink != 1
        {
            return Err(Error::UnsafeEndpoint);
        }
        require_same(
            &metadata,
            &named(&self.directory, "control.sock").map_err(runtime_error)?,
        )
        .map_err(|_| Error::UnsafeEndpoint)
    }
}
fn check(deadline: Instant, cancel: &watch::Receiver<bool>) -> Result<(), Error> {
    if *cancel.borrow() || cancel.has_changed().is_err() {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    Ok(())
}
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}
fn os_error(error: rustix::io::Errno) -> Error {
    Error::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}
fn runtime_error(error: super::Error) -> Error {
    match error {
        super::Error::Io(kind) => Error::Io(kind),
        _ => Error::UnsafeEndpoint,
    }
}

#[cfg(test)]
mod tests;
