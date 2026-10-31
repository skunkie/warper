// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed protected owner snapshots with bounded reads and atomic publication.

use super::{RuntimeLease, named, require_same, validate_directory};
use crate::{Access, OwnerPolicy};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, open, openat2, renameat, unlinkat,
};
use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::fd::OwnedFd,
    os::unix::net::UnixStream,
};

const OWNER: &str = "owner";
const PENDING: &str = "owner.pending";
const RECORD_LEN: usize = 24;

mod recovery;
pub use recovery::PendingInspection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Runtime(super::Error),
    Peer(crate::Error),
    UnsafeState,
    InvalidRecord,
    InvalidOwner,
    RevisionConflict,
    RevisionExhausted,
    RecoveryRequired,
    Io(io::ErrorKind),
    CommitUncertain(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Runtime(_) => "SystemConfiguration: enrollment runtime ownership failed",
            Self::Peer(_) => "PermissionDenied: enrollment requires an administrative peer",
            Self::UnsafeState => "Conflict: protected enrollment state is unsafe or changed",
            Self::InvalidRecord => "InvalidConfig: protected enrollment record is invalid",
            Self::InvalidOwner => "InvalidConfig: enrolled owner UID is reserved",
            Self::RevisionConflict => "Conflict: enrollment revision changed",
            Self::RevisionExhausted => "ResourceLimit: enrollment revision exhausted",
            Self::RecoveryRequired => {
                "RecoveryRequired: pending enrollment state requires inspection"
            }
            Self::Io(_) => "SystemConfiguration: enrollment storage operation failed",
            Self::CommitUncertain(_) => {
                "RecoveryRequired: enrollment commit durability is uncertain"
            }
        })
    }
}
impl std::error::Error for Error {}

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
            f.write_str("; enrollment cleanup also failed")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Enrollment {
    owner: Option<u32>,
    revision: u64,
}
impl Enrollment {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn policy(&self) -> OwnerPolicy {
        OwnerPolicy { owner: self.owner }
    }
}
impl fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Enrollment(<redacted>)")
    }
}

/// Only fixed root-owned state is accessible in production. Every operation
/// requires the same process to retain and revalidate its runtime lease.
///
/// ```compile_fail
/// use warper_control::runtime::{RuntimeLease, enrollment::OwnerStore};
/// fn redirect(lease: &RuntimeLease) {
///     let _ = OwnerStore::open(lease, "/tmp/claimed-state");
/// }
/// ```
pub struct OwnerStore {
    anchor: OwnedFd,
    var: OwnedFd,
    lib: OwnedFd,
    directory: OwnedFd,
    owner: u32,
}
impl OwnerStore {
    pub fn open(lease: &RuntimeLease) -> Result<Self, Error> {
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

    pub fn read(&self, lease: &RuntimeLease) -> Result<Enrollment, Error> {
        lease.revalidate().map_err(Error::Runtime)?;
        self.verify()?;
        self.require_no_pending()?;
        Ok(self.load()?.0)
    }

    pub fn enroll(
        &mut self,
        lease: &RuntimeLease,
        peer: &UnixStream,
        expected_revision: u64,
        owner: Option<u32>,
    ) -> Result<Enrollment, Failure> {
        lease.revalidate().map_err(Error::Runtime)?;
        let policy = OwnerPolicy { owner: None };
        crate::unix::authenticate_client(peer, &policy, Access::Administer).map_err(Error::Peer)?;
        self.replace(lease, expected_revision, owner)
    }

    fn open_at(anchor: OwnedFd, owner: u32) -> Result<Self, Error> {
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

    fn replace(
        &mut self,
        lease: &RuntimeLease,
        expected_revision: u64,
        owner: Option<u32>,
    ) -> Result<Enrollment, Failure> {
        self.replace_with_sync(lease, expected_revision, owner, Self::sync)
    }

    fn replace_with_sync(
        &mut self,
        lease: &RuntimeLease,
        expected_revision: u64,
        owner: Option<u32>,
        commit_sync: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<Enrollment, Failure> {
        lease.revalidate().map_err(Error::Runtime)?;
        self.verify()?;
        self.require_no_pending()?;
        if owner == Some(u32::MAX) {
            return Err(Error::InvalidOwner.into());
        }
        let (before, pinned) = self.load()?;
        if before.revision != expected_revision {
            return Err(Error::RevisionConflict.into());
        }
        let after = Enrollment {
            owner,
            revision: before
                .revision
                .checked_add(1)
                .ok_or(Error::RevisionExhausted)?,
        };
        let fd = openat2(
            &self.directory,
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
        let mut pending = File::from(fd);
        let mut published = false;
        let result = (|| {
            check_file(&fstat(&pending).map_err(os_error)?, self.owner, 0)?;
            pending
                .write_all(&encode(after))
                .map_err(|e| Error::Io(e.kind()))?;
            pending.sync_all().map_err(|e| Error::Io(e.kind()))?;
            self.sync()?;
            lease.revalidate().map_err(Error::Runtime)?;
            self.verify()?;
            let (current, current_pin) = self.load()?;
            if current != before {
                return Err(Error::RevisionConflict);
            }
            match (&pinned, &current_pin) {
                (Some(a), Some(b)) => {
                    require_same(&fstat(a).map_err(os_error)?, &fstat(b).map_err(os_error)?)
                        .map_err(|_| Error::UnsafeState)?
                }
                (None, None) => {}
                _ => return Err(Error::UnsafeState),
            }
            self.verify_pending(&pending, Some(RECORD_LEN as u64))?;
            renameat(&self.directory, PENDING, &self.directory, OWNER).map_err(os_error)?;
            published = true;
            commit_sync(self).map_err(|e| match e {
                Error::Io(kind) => Error::CommitUncertain(kind),
                other => other,
            })?;
            Ok(after)
        })();
        match result {
            Ok(after) => Ok(after),
            Err(primary) => {
                let cleanup = if published {
                    None
                } else {
                    self.remove_pending(lease, &pending).err()
                };
                Err(Failure { primary, cleanup })
            }
        }
    }

    fn verify(&self) -> Result<(), Error> {
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

    fn require_no_pending(&self) -> Result<(), Error> {
        match named(&self.directory, PENDING) {
            Err(super::Error::Io(io::ErrorKind::NotFound)) => Ok(()),
            Ok(_) => Err(Error::RecoveryRequired),
            Err(error) => Err(Error::Runtime(error)),
        }
    }

    fn load(&self) -> Result<(Enrollment, Option<OwnedFd>), Error> {
        let pin = match openat2(
            &self.directory,
            OWNER,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => {
                return Ok((
                    Enrollment {
                        owner: None,
                        revision: 0,
                    },
                    None,
                ));
            }
            Err(error) => return Err(os_error(error)),
        };
        let metadata = fstat(&pin).map_err(os_error)?;
        check_file(&metadata, self.owner, RECORD_LEN as u64)?;
        let fd = openat2(
            &self.directory,
            OWNER,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?;
        require_same(&metadata, &fstat(&fd).map_err(os_error)?).map_err(|_| Error::UnsafeState)?;
        let mut bytes = Vec::with_capacity(RECORD_LEN + 1);
        File::from(fd)
            .take((RECORD_LEN + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Io(e.kind()))?;
        let record = decode(&bytes)?;
        require_same(
            &metadata,
            &named(&self.directory, OWNER).map_err(Error::Runtime)?,
        )
        .map_err(|_| Error::UnsafeState)?;
        Ok((record, Some(pin)))
    }

    fn verify_pending(&self, file: &File, size: Option<u64>) -> Result<(), Error> {
        let metadata = fstat(file).map_err(os_error)?;
        check_file(
            &metadata,
            self.owner,
            size.unwrap_or(metadata.st_size as u64),
        )?;
        require_same(
            &metadata,
            &named(&self.directory, PENDING).map_err(Error::Runtime)?,
        )
        .map_err(|_| Error::UnsafeState)
    }

    fn remove_pending(&self, lease: &RuntimeLease, file: &File) -> Result<(), Error> {
        lease.revalidate().map_err(Error::Runtime)?;
        self.verify()?;
        self.verify_pending(file, None)?;
        unlinkat(&self.directory, PENDING, AtFlags::empty()).map_err(os_error)?;
        self.sync()
    }

    fn sync(&self) -> Result<(), Error> {
        let fd = openat2(
            &self.directory,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?;
        rustix::fs::fsync(fd).map_err(os_error)
    }
}
impl fmt::Debug for OwnerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerStore(<redacted>)")
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
fn encode(record: Enrollment) -> [u8; RECORD_LEN] {
    let mut bytes = [0; RECORD_LEN];
    bytes[..4].copy_from_slice(b"WOWN");
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[8..16].copy_from_slice(&record.revision.to_be_bytes());
    bytes[16..20].copy_from_slice(&u32::from(record.owner.is_some()).to_be_bytes());
    bytes[20..].copy_from_slice(&record.owner.unwrap_or(0).to_be_bytes());
    bytes
}
fn decode(bytes: &[u8]) -> Result<Enrollment, Error> {
    let bytes: &[u8; RECORD_LEN] = bytes.try_into().map_err(|_| Error::InvalidRecord)?;
    if &bytes[..4] != b"WOWN" || bytes[4..8] != 1u32.to_be_bytes() {
        return Err(Error::InvalidRecord);
    }
    let revision = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| Error::InvalidRecord)?);
    let present = u32::from_be_bytes(bytes[16..20].try_into().map_err(|_| Error::InvalidRecord)?);
    let uid = u32::from_be_bytes(bytes[20..].try_into().map_err(|_| Error::InvalidRecord)?);
    let owner = match (present, uid) {
        (0, 0) => None,
        (1, uid) if uid != u32::MAX => Some(uid),
        _ => return Err(Error::InvalidRecord),
    };
    if revision == 0 {
        return Err(Error::InvalidRecord);
    }
    Ok(Enrollment { owner, revision })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::Fixture;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    pub(super) fn store(fixture: &Fixture) -> OwnerStore {
        fs::create_dir_all(fixture.path.join("var/lib/warper")).unwrap();
        for (name, mode) in [
            ("var", 0o755),
            ("var/lib", 0o755),
            ("var/lib/warper", 0o700),
        ] {
            fs::set_permissions(fixture.path.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        let anchor = open(
            &fixture.path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        OwnerStore::open_at(anchor, fixture.owner).unwrap()
    }

    pub(super) fn record_path(fixture: &Fixture) -> std::path::PathBuf {
        fixture.path.join("var/lib/warper/owner")
    }

    pub(super) fn write_record(fixture: &Fixture, bytes: &[u8]) {
        let path = record_path(fixture);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn atomic_enrollment_replacement_and_removal_survive_reopen_with_monotonic_revisions() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut store = store(&fixture);
        assert_eq!(
            store.read(&lease).unwrap(),
            Enrollment {
                owner: None,
                revision: 0
            }
        );
        let enrolled = store.replace(&lease, 0, Some(1234)).unwrap();
        assert_eq!(
            enrolled,
            Enrollment {
                owner: Some(1234),
                revision: 1
            }
        );
        let policy = enrolled.policy();
        assert_eq!(
            policy.authorize(&crate::PeerCredentials { uid: 1234 }, Access::Operate),
            Ok(crate::Role::Owner)
        );
        assert!(
            matches!(store.replace(&lease, 0, Some(4321)), Err(failure) if failure.primary == Error::RevisionConflict)
        );
        assert!(
            matches!(store.replace(&lease, 1, Some(u32::MAX)), Err(failure) if failure.primary == Error::InvalidOwner)
        );
        assert_eq!(store.read(&lease).unwrap(), enrolled);
        store.replace(&lease, 1, Some(4321)).unwrap();
        let cleared = store.replace(&lease, 2, None).unwrap();
        assert_eq!(
            cleared,
            Enrollment {
                owner: None,
                revision: 3
            }
        );
        drop(store);
        let anchor = open(
            &fixture.path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let store = OwnerStore::open_at(anchor, fixture.owner).unwrap();
        assert_eq!(store.read(&lease).unwrap(), cleared);
        assert_eq!(fs::metadata(record_path(&fixture)).unwrap().len(), 24);
        assert!(!fixture.path.join("var/lib/warper/owner.pending").exists());
    }

    #[test]
    fn post_rename_sync_failure_reports_uncertainty_without_rolling_back_the_new_owner() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut store = store(&fixture);
        store.replace(&lease, 0, Some(1234)).unwrap();
        let failure = store
            .replace_with_sync(&lease, 1, Some(4321), |_| {
                Err(Error::Io(io::ErrorKind::Other))
            })
            .unwrap_err();
        assert_eq!(
            failure,
            Failure {
                primary: Error::CommitUncertain(io::ErrorKind::Other),
                cleanup: None
            }
        );
        assert_eq!(
            store.read(&lease).unwrap(),
            Enrollment {
                owner: Some(4321),
                revision: 2
            }
        );
        assert!(!fixture.path.join("var/lib/warper/owner.pending").exists());
    }

    #[test]
    fn pending_state_and_revision_exhaustion_never_become_an_unenrolled_installation() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut store = store(&fixture);
        let pending = fixture.path.join("var/lib/warper/owner.pending");
        fs::write(&pending, b"partial fixture").unwrap();
        assert_eq!(store.read(&lease), Err(Error::RecoveryRequired));
        assert!(
            matches!(store.replace(&lease,0,None),Err(failure) if failure.primary==Error::RecoveryRequired)
        );
        assert_eq!(fs::read(&pending).unwrap(), b"partial fixture");
        fs::remove_file(pending).unwrap();
        write_record(
            &fixture,
            &encode(Enrollment {
                owner: Some(1234),
                revision: u64::MAX,
            }),
        );
        assert!(
            matches!(store.replace(&lease,u64::MAX,None),Err(failure) if failure.primary==Error::RevisionExhausted)
        );
    }

    #[test]
    fn native_administrative_denial_precedes_record_access_or_mutation() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut store = store(&fixture);
        let (_client, peer) = UnixStream::pair().unwrap();
        if fixture.owner != 0 {
            // Even malformed stored state must not disclose anything to a denied peer.
            write_record(&fixture, b"invalid fixture");
            assert!(
                matches!(store.enroll(&lease,&peer,0,Some(1234)),Err(failure) if failure.primary==Error::Peer(crate::Error::PermissionDenied))
            );
            assert_eq!(fs::read(record_path(&fixture)).unwrap(), b"invalid fixture");
        } else {
            assert_eq!(
                store
                    .enroll(&lease, &peer, 0, Some(1234))
                    .unwrap()
                    .revision(),
                1
            );
        }
    }

    #[test]
    fn unsafe_record_metadata_and_changed_directories_are_preserved() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let store = store(&fixture);
        let bytes = encode(Enrollment {
            owner: Some(1234),
            revision: 1,
        });
        write_record(&fixture, &bytes);
        let path = record_path(&fixture);
        fs::hard_link(&path, fixture.path.join("alias")).unwrap();
        assert_eq!(store.read(&lease), Err(Error::UnsafeState));
        fs::remove_file(fixture.path.join("alias")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(store.read(&lease), Err(Error::UnsafeState));
        fs::remove_file(&path).unwrap();
        symlink(fixture.path.join("alias"), &path).unwrap();
        assert_eq!(store.read(&lease), Err(Error::UnsafeState));
        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
        fs::remove_file(&path).unwrap();
        fs::rename(
            fixture.path.join("var/lib/warper"),
            fixture.path.join("retired"),
        )
        .unwrap();
        fs::create_dir(fixture.path.join("var/lib/warper")).unwrap();
        assert_eq!(store.read(&lease), Err(Error::UnsafeState));
        assert!(fixture.path.join("retired").exists());
    }

    #[test]
    fn pending_cleanup_preserves_committed_and_replaced_objects() {
        use std::os::unix::fs::OpenOptionsExt;
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut store = store(&fixture);
        let committed = store.replace(&lease, 0, Some(1234)).unwrap();
        let path = fixture.path.join("var/lib/warper/owner.pending");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"partial").unwrap();
        store.remove_pending(&lease, &file).unwrap();
        assert_eq!(store.read(&lease).unwrap(), committed);
        drop(file);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        fs::rename(&path, fixture.path.join("retired-pending")).unwrap();
        fs::write(&path, b"foreign fixture state").unwrap();
        assert_eq!(store.remove_pending(&lease, &file), Err(Error::UnsafeState));
        assert_eq!(fs::read(&path).unwrap(), b"foreign fixture state");
        drop(file);
    }

    #[test]
    fn malformed_stored_records_fail_closed_and_public_open_rejects_non_root() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let store = store(&fixture);
        write_record(&fixture, &[0; 24]);
        assert_eq!(store.read(&lease), Err(Error::InvalidRecord));
        write_record(&fixture, &[0; 25]);
        assert_eq!(store.read(&lease), Err(Error::UnsafeState));
        if fixture.owner != 0 {
            assert!(matches!(
                OwnerStore::open(&lease),
                Err(Error::Runtime(super::super::Error::PrivilegeRequired))
            ));
        }
    }

    #[test]
    fn wire_record_is_exact_versioned_bounded_and_redacted() {
        let sample = Enrollment {
            owner: Some(1234),
            revision: 7,
        };
        let expected = [
            87, 79, 87, 78, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 4, 210,
        ];
        assert_eq!(encode(sample), expected);
        assert_eq!(decode(&expected), Ok(sample));
        assert_eq!(format!("{sample:?}"), "Enrollment(<redacted>)");
        for count in 0..24 {
            assert_eq!(decode(&expected[..count]), Err(Error::InvalidRecord));
        }
        let mut oversized = expected.to_vec();
        oversized.push(0);
        assert_eq!(decode(&oversized), Err(Error::InvalidRecord));
        for (range, value) in [(0..4, 0), (4..8, 2), (8..16, 0), (16..20, 2), (20..24, 255)] {
            let mut invalid = expected;
            invalid[range].fill(value);
            assert_eq!(decode(&invalid), Err(Error::InvalidRecord));
        }
        let mut invalid = expected;
        invalid[16..20].fill(0);
        assert_eq!(decode(&invalid), Err(Error::InvalidRecord));
    }
}
