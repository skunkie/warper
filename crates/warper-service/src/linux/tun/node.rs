// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fail before the upstream builder's optional missing-node repair can run.

use super::Error;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, major, minor, open, openat2};

pub(super) fn verify() -> Result<(), Error> {
    let root = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        Error::DeviceInspection(std::io::Error::from_raw_os_error(error.raw_os_error()).kind())
    })?;
    let dev = openat2(
        &root,
        "dev",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        Error::DeviceInspection(std::io::Error::from_raw_os_error(error.raw_os_error()).kind())
    })?;
    let net = openat2(
        &dev,
        "net",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|error| {
        Error::DeviceInspection(std::io::Error::from_raw_os_error(error.raw_os_error()).kind())
    })?;
    for fd in [&root, &dev, &net] {
        let metadata = fstat(fd).map_err(|error| {
            Error::DeviceInspection(std::io::Error::from_raw_os_error(error.raw_os_error()).kind())
        })?;
        if metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0 {
            return Err(Error::DeviceUnavailable);
        }
    }
    let device = openat2(
        &net,
        "tun",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|error| {
        Error::DeviceInspection(std::io::Error::from_raw_os_error(error.raw_os_error()).kind())
    })?;
    let metadata = fstat(device).map_err(|error| {
        Error::DeviceInspection(std::io::Error::from_raw_os_error(error.raw_os_error()).kind())
    })?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::CharacterDevice
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7000 != 0
        || major(metadata.st_rdev) != 10
        || minor(metadata.st_rdev) != 200
    {
        return Err(Error::DeviceUnavailable);
    }
    Ok(())
}
