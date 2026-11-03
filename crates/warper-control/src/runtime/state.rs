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
    parents: Vec<(&'static str, OwnedFd)>,
    pub(super) directory: OwnedFd,
    pub(super) owner: u32,
}
impl StateDirectory {
    pub(super) fn open(lease: &RuntimeLease) -> Result<Self, Error> {
        Self::open_location(lease, false)
    }
    pub(super) fn open_configuration(lease: &RuntimeLease) -> Result<Self, Error> {
        Self::open_location(lease, true)
    }
    fn open_location(lease: &RuntimeLease, configuration: bool) -> Result<Self, Error> {
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
        Self::open_at_location(anchor, 0, configuration)
    }
    #[cfg(test)]
    pub(super) fn open_at(anchor: OwnedFd, owner: u32) -> Result<Self, Error> {
        Self::open_at_location(anchor, owner, false)
    }
    pub(super) fn open_at_location(
        anchor: OwnedFd,
        owner: u32,
        configuration: bool,
    ) -> Result<Self, Error> {
        check_directory(&fstat(&anchor).map_err(os_error)?, owner, false)?;
        let names: &[&str] = if configuration {
            &["etc"]
        } else {
            &["var", "lib"]
        };
        let mut parents = Vec::with_capacity(names.len());
        for &name in names {
            let parent = parents.last().map_or(&anchor, |(_, fd)| fd);
            let fd = directory(parent, name, false)?;
            check_directory(&fstat(&fd).map_err(os_error)?, owner, false)?;
            parents.push((name, fd));
        }
        let parent = parents.last().map_or(&anchor, |(_, fd)| fd);
        let directory = directory(parent, "warper", true)?;
        check_directory(&fstat(&directory).map_err(os_error)?, owner, true)?;
        Ok(Self {
            anchor,
            parents,
            directory,
            owner,
        })
    }
    pub(super) fn verify(&self) -> Result<(), Error> {
        check_directory(&fstat(&self.anchor).map_err(os_error)?, self.owner, false)?;
        let mut parent = &self.anchor;
        for (name, fd, protected) in self
            .parents
            .iter()
            .map(|(name, fd)| (*name, fd, false))
            .chain(std::iter::once(("warper", &self.directory, true)))
        {
            let metadata = fstat(fd).map_err(os_error)?;
            check_directory(&metadata, self.owner, protected)?;
            require_same(&metadata, &named(parent, name).map_err(Error::Runtime)?)
                .map_err(|_| Error::UnsafeState)?;
            parent = fd;
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
