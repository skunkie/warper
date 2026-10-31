// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Shared fixed protected state-directory pins; no arbitrary public path API.

use super::{RuntimeLease, named, require_same, validate_directory};
use rustix::fs::{Mode, OFlags, ResolveFlags, Stat, fstat, open, openat2};
use std::{io, os::fd::OwnedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Runtime(super::Error),
    UnsafeState,
    Io(io::ErrorKind),
}
pub(super) struct StateDirectory {
    anchor: OwnedFd,
    var: OwnedFd,
    lib: OwnedFd,
    pub(super) directory: OwnedFd,
    pub(super) owner: u32,
}
impl StateDirectory {
    pub(super) fn open(lease: &RuntimeLease) -> Result<Self, Error> {
        lease.revalidate().map_err(Error::Runtime)?;
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::Runtime(super::Error::PrivilegeRequired));
        }
        let anchor = open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(os_error)?;
        Self::open_at(anchor, 0)
    }
    pub(super) fn open_at(anchor: OwnedFd, owner: u32) -> Result<Self, Error> {
        check_directory(&fstat(&anchor).map_err(os_error)?, owner, false)?;
        let var = directory(&anchor, "var", false)?;
        check_directory(&fstat(&var).map_err(os_error)?, owner, false)?;
        let lib = directory(&var, "lib", false)?;
        check_directory(&fstat(&lib).map_err(os_error)?, owner, false)?;
        let directory = directory(&lib, "warper", true)?;
        check_directory(&fstat(&directory).map_err(os_error)?, owner, true)?;
        Ok(Self {
            anchor,
            var,
            lib,
            directory,
            owner,
        })
    }
    pub(super) fn verify(&self) -> Result<(), Error> {
        check_directory(&fstat(&self.anchor).map_err(os_error)?, self.owner, false)?;
        for (parent, name, fd, protected) in [
            (&self.anchor, "var", &self.var, false),
            (&self.var, "lib", &self.lib, false),
            (&self.lib, "warper", &self.directory, true),
        ] {
            let metadata = fstat(fd).map_err(os_error)?;
            check_directory(&metadata, self.owner, protected)?;
            require_same(&metadata, &named(parent, name).map_err(Error::Runtime)?)
                .map_err(|_| Error::UnsafeState)?;
        }
        Ok(())
    }
}
fn directory(parent: &OwnedFd, name: &str, same_mount: bool) -> Result<OwnedFd, Error> {
    let mut resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS;
    if same_mount {
        resolve |= ResolveFlags::NO_XDEV;
    }
    openat2(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        resolve,
    )
    .map_err(os_error)
}
fn check_directory(metadata: &Stat, owner: u32, protected: bool) -> Result<(), Error> {
    validate_directory(metadata, owner, false).map_err(|_| Error::UnsafeState)?;
    if protected && metadata.st_mode & 0o7777 != 0o700 {
        return Err(Error::UnsafeState);
    }
    Ok(())
}
fn os_error(error: rustix::io::Errno) -> Error {
    Error::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}
