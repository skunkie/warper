// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Retirement of proven stale control publication after fresh flock acquisition.

use super::{Error, INTENT, Identity, LENGTH, Record, SOCKET, os_error, resolution};
use crate::runtime::{RuntimeLease, named};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, openat2, unlinkat};
use std::{fs::File, io, os::unix::fs::FileExt, sync::atomic::Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    Absent,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inspection {
    Absent,
    Retirable,
}

/// Verify a stale publication without unlinking or syncing any object.
/// This observation is not authorization for a later retirement; recover
/// repeats every check under its exclusive, freshly acquired lease.
pub fn inspect(lease: &RuntimeLease) -> Result<Inspection, Error> {
    reconcile(lease, false)
}

/// Unique access and the never-published marker prevent live ownership recovery.
/// Unknown or changed objects are preserved; legacy intent requires inspection.
pub fn recover(lease: &mut RuntimeLease) -> Result<Recovery, Error> {
    reconcile(lease, true).map(|inspection| match inspection {
        Inspection::Absent => Recovery::Absent,
        Inspection::Retirable => Recovery::Retired,
    })
}

fn reconcile(lease: &RuntimeLease, retire: bool) -> Result<Inspection, Error> {
    lease.revalidate().map_err(Error::Runtime)?;
    if lease.endpoint_bound.load(Ordering::Acquire) {
        return Err(Error::ReacquisitionRequired);
    }
    let metadata = match named(&lease.directory, INTENT) {
        Ok(metadata) => metadata,
        Err(crate::runtime::Error::Io(io::ErrorKind::NotFound)) => {
            return match named(&lease.directory, SOCKET) {
                Err(crate::runtime::Error::Io(io::ErrorKind::NotFound)) => Ok(Inspection::Absent),
                Ok(_) => Err(Error::RecoveryRequired),
                Err(error) => Err(Error::Runtime(error)),
            };
        }
        Err(error) => return Err(Error::Runtime(error)),
    };
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != lease.owner
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
        || metadata.st_size != LENGTH as i64
    {
        return Err(Error::RecoveryRequired);
    }
    let stamp = Identity::of(&metadata);
    let file = File::from(
        openat2(
            &lease.directory,
            INTENT,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?,
    );
    let read = || -> Result<[u8; LENGTH], Error> {
        if Identity::of(&fstat(&file).map_err(os_error)?) != stamp
            || Identity::of(&named(&lease.directory, INTENT).map_err(Error::Runtime)?) != stamp
        {
            return Err(Error::ChangedState);
        }
        let mut bytes = [0; LENGTH];
        file.read_exact_at(&mut bytes, 0)
            .map_err(|error| Error::Io(error.kind()))?;
        if Identity::of(&fstat(&file).map_err(os_error)?) != stamp
            || Identity::of(&named(&lease.directory, INTENT).map_err(Error::Runtime)?) != stamp
        {
            return Err(Error::ChangedState);
        }
        Ok(bytes)
    };
    let bytes = read()?;
    let record = Record::decode(&bytes, lease.owner)?;
    if !record.matches_lock(&fstat(&lease.lock).map_err(os_error)?) {
        return Err(Error::RecoveryRequired);
    }
    let socket = match named(&lease.directory, SOCKET) {
        Ok(stat) => {
            let identity = Identity::of(&stat);
            if record.socket != Some(identity) || !identity.valid_socket(lease.owner) {
                return Err(Error::ChangedState);
            }
            Some(identity)
        }
        Err(crate::runtime::Error::Io(io::ErrorKind::NotFound)) => None,
        Err(error) => return Err(Error::Runtime(error)),
    };
    lease.revalidate().map_err(Error::Runtime)?;
    if read()? != bytes {
        return Err(Error::ChangedState);
    }
    if !retire {
        return Ok(Inspection::Retirable);
    }
    if let Some(socket) = socket {
        if Identity::of(&named(&lease.directory, SOCKET).map_err(Error::Runtime)?) != socket {
            return Err(Error::ChangedState);
        }
        unlinkat(&lease.directory, SOCKET, AtFlags::empty()).map_err(os_error)?;
    } else {
        match named(&lease.directory, SOCKET) {
            Err(crate::runtime::Error::Io(io::ErrorKind::NotFound)) => {}
            Ok(_) => return Err(Error::ChangedState),
            Err(error) => return Err(Error::Runtime(error)),
        }
    }
    // If retirement is interrupted here, the valid Bound intent plus an absent
    // socket lets the next eligible lease finish without adopting any object.
    if read()? != bytes {
        return Err(Error::ChangedState);
    }
    unlinkat(&lease.directory, INTENT, AtFlags::empty()).map_err(os_error)?;
    let directory = File::from(
        openat2(
            &lease.directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?,
    );
    directory
        .sync_all()
        .map_err(|error| Error::Io(error.kind()))?;
    Ok(Inspection::Retirable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{endpoint::ControlEndpoint, tests::Fixture};
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        sync::Arc,
    };

    #[test]
    fn stale_bound_recovery_requires_fresh_acquisition_and_retires_idempotently() {
        let fixture = Fixture::new();
        let lease = Arc::new(fixture.acquire().unwrap());
        let lock = fs::metadata(fixture.lock_path()).unwrap();
        let endpoint = ControlEndpoint::bind(lease.clone()).unwrap();
        drop(endpoint);
        let mut used = Arc::try_unwrap(lease)
            .unwrap_or_else(|_| panic!("endpoint retained runtime after drop"));
        assert_eq!(recover(&mut used), Err(Error::ReacquisitionRequired));
        drop(used);
        let mut fresh = fixture.acquire().unwrap();
        let intent = fixture.path.join("run/warper/control.intent");
        let socket = fixture.path.join("run/warper/control.sock");
        let before = fs::read(&intent).unwrap();
        assert_eq!(inspect(&fresh), Ok(Inspection::Retirable));
        assert!(socket.exists());
        assert_eq!(fs::read(&intent).unwrap(), before);
        assert_eq!(recover(&mut fresh), Ok(Recovery::Retired));
        assert_eq!(inspect(&fresh), Ok(Inspection::Absent));
        assert_eq!(recover(&mut fresh), Ok(Recovery::Absent));
        use std::os::unix::fs::MetadataExt;
        assert_eq!(lock.ino(), fs::metadata(fixture.lock_path()).unwrap().ino());
        ControlEndpoint::bind(fresh).unwrap().close().unwrap();
    }

    #[test]
    fn recovery_preserves_foreign_socket_changes_and_legacy_intent() {
        for change in ["mode", "replace", "intent", "legacy", "socket_absent"] {
            let fixture = Fixture::new();
            drop(ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap());
            let socket = fixture.path.join("run/warper/control.sock");
            let intent = fixture.path.join("run/warper/control.intent");
            let mut foreign = None;
            match change {
                "mode" => fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap(),
                "replace" => {
                    fs::remove_file(&socket).unwrap();
                    foreign = Some(UnixListener::bind(&socket).unwrap());
                    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
                }
                "intent" => fs::write(&intent, b"invented foreign intent").unwrap(),
                "legacy" => fs::write(&intent, []).unwrap(),
                "socket_absent" => fs::remove_file(&socket).unwrap(),
                _ => unreachable!(),
            }
            let mut fresh = fixture.acquire().unwrap();
            if change == "socket_absent" {
                assert_eq!(recover(&mut fresh), Ok(Recovery::Retired));
            } else {
                let expected = fs::read(&intent).unwrap();
                assert!(inspect(&fresh).is_err(), "{change}");
                assert!(recover(&mut fresh).is_err(), "{change}");
                assert!(socket.exists(), "{change}");
                assert_eq!(fs::read(&intent).unwrap(), expected, "{change}");
            }
            drop(foreign);
        }
    }

    #[test]
    fn prepared_without_socket_can_retire_but_never_identifies_an_existing_socket() {
        for present in [false, true] {
            let fixture = Fixture::new();
            let mut lease = fixture.acquire().unwrap();
            let bytes = Record::prepared(&fstat(&lease.lock).unwrap()).encode();
            let path = fixture.path.join("run/warper/control.intent");
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let socket = fixture.path.join("run/warper/control.sock");
            let foreign = if present {
                Some(UnixListener::bind(&socket).unwrap())
            } else {
                None
            };
            assert_eq!(
                recover(&mut lease),
                if present {
                    Err(Error::ChangedState)
                } else {
                    Ok(Recovery::Retired)
                }
            );
            if present {
                assert!(path.exists());
                assert!(socket.exists());
            }
            drop(foreign);
        }
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;
    use crate::runtime::tests::Fixture;
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };

    #[test]
    fn unknown_socket_lock_mismatch_and_shared_intent_are_preserved() {
        for change in ["unknown_socket", "lock", "hard_link"] {
            let fixture = Fixture::new();
            let mut lease = fixture.acquire().unwrap();
            let socket = fixture.path.join("run/warper/control.sock");
            let _foreign = UnixListener::bind(&socket).unwrap();
            let intent = fixture.path.join("run/warper/control.intent");
            let mut bytes = Record::prepared(&fstat(&lease.lock).unwrap()).encode();
            if change != "unknown_socket" {
                if change == "lock" {
                    bytes[16] ^= 1;
                }
                fs::write(&intent, bytes).unwrap();
                fs::set_permissions(&intent, fs::Permissions::from_mode(0o600)).unwrap();
                if change == "hard_link" {
                    fs::hard_link(&intent, fixture.path.join("linked-intent")).unwrap();
                }
            }
            assert_eq!(
                recover(&mut lease),
                Err(Error::RecoveryRequired),
                "{change}"
            );
            assert!(socket.exists(), "{change}");
            if change != "unknown_socket" {
                assert_eq!(fs::read(&intent).unwrap(), bytes, "{change}");
            }
        }
    }
}
