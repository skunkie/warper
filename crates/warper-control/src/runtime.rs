// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed Linux runtime ownership. No listener, enrollment or network mutation.
//! The persistent lock name must never be unlinked during ordinary shutdown.

use std::{fmt, io, os::fd::OwnedFd};

use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, ResolveFlags, Stat, flock, fstat, open,
    openat2, statat,
};

pub mod client;
pub mod connection;
pub mod endpoint;
pub mod enrollment;
mod state;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Admission(crate::Error),
    PrivilegeRequired,
    UnsafeState,
    AlreadyRunning,
    Io(io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Admission(_) => "Authentication: runtime namespace admission failed",
            Self::PrivilegeRequired => "PermissionDenied: runtime ownership requires UID 0",
            Self::UnsafeState => "Conflict: runtime ownership metadata is unsafe or changed",
            Self::AlreadyRunning => "Conflict: runtime ownership is already held",
            Self::Io(_) => "SystemConfiguration: runtime ownership inspection or locking failed",
        })
    }
}

impl std::error::Error for Error {}

/// Exclusive ownership of the fixed Linux service runtime directory.
/// Drop closes descriptors and releases flock; it never unlinks persistent state.
/// This does not authorize a network mutation or replace durable journal intent.
///
/// No public path, UID override, descriptor constructor or deserializer exists.
///
/// ```compile_fail
/// use warper_control::runtime::RuntimeLease;
/// let lease = RuntimeLease::acquire("/tmp/claimed-runtime");
/// ```
pub struct RuntimeLease {
    anchor: OwnedFd,
    parent: OwnedFd,
    directory: OwnedFd,
    lock: OwnedFd,
    owner: u32,
}

impl RuntimeLease {
    pub fn acquire() -> Result<Self, Error> {
        crate::namespace::require_initial_user_namespace().map_err(Error::Admission)?;
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::PrivilegeRequired);
        }
        let anchor = open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(system_error)?;
        Self::acquire_at(anchor, 0)
    }

    /// Check again immediately before a subsequent runtime mutation. Integration
    /// must serialize its own operations and prevent namespace/credential changes.
    /// A privileged administrator can still race these checks; root is trusted.
    pub fn revalidate(&self) -> Result<(), Error> {
        crate::namespace::require_initial_user_namespace().map_err(Error::Admission)?;
        if nix::unistd::geteuid().as_raw() != self.owner {
            return Err(Error::PrivilegeRequired);
        }
        self.validate_state()
    }

    fn acquire_at(anchor: OwnedFd, owner: u32) -> Result<Self, Error> {
        validate_directory(&fstat(&anchor).map_err(system_error)?, owner, false)?;
        let parent = open_directory(&anchor, "run", false)?;
        validate_directory(&fstat(&parent).map_err(system_error)?, owner, false)?;
        let directory = open_directory(&parent, "warper", true)?;
        validate_directory(&fstat(&directory).map_err(system_error)?, owner, true)?;
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;
        let lock = match openat2(
            &directory,
            "service.lock",
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
            resolve,
        ) {
            Ok(lock) => lock,
            Err(rustix::io::Errno::EXIST) => {
                // Inspect without opening a device/FIFO for I/O. Unprivileged
                // callers cannot replace this name in the verified directory.
                let inspected = openat2(
                    &directory,
                    "service.lock",
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    resolve,
                )
                .map_err(system_error)?;
                let metadata = fstat(&inspected).map_err(system_error)?;
                validate_lock(&metadata, owner)?;
                let lock = openat2(&directory, "service.lock", flags, Mode::empty(), resolve)
                    .map_err(system_error)?;
                require_same(&metadata, &fstat(&lock).map_err(system_error)?)?;
                lock
            }
            Err(error) => return Err(system_error(error)),
        };
        validate_lock(&fstat(&lock).map_err(system_error)?, owner)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                Error::AlreadyRunning
            } else {
                system_error(error)
            }
        })?;
        let lease = Self {
            anchor,
            parent,
            directory,
            lock,
            owner,
        };
        lease.validate_state()?;
        Ok(lease)
    }

    fn validate_state(&self) -> Result<(), Error> {
        validate_directory(
            &fstat(&self.anchor).map_err(system_error)?,
            self.owner,
            false,
        )?;
        let parent = fstat(&self.parent).map_err(system_error)?;
        validate_directory(&parent, self.owner, false)?;
        require_same(&parent, &named(&self.anchor, "run")?)?;
        let directory = fstat(&self.directory).map_err(system_error)?;
        validate_directory(&directory, self.owner, true)?;
        require_same(&directory, &named(&self.parent, "warper")?)?;
        let lock = fstat(&self.lock).map_err(system_error)?;
        validate_lock(&lock, self.owner)?;
        require_same(&lock, &named(&self.directory, "service.lock")?)
    }
}

impl fmt::Debug for RuntimeLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeLease(<redacted>)")
    }
}

fn open_directory(parent: &OwnedFd, name: &str, same_mount: bool) -> Result<OwnedFd, Error> {
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
    .map_err(system_error)
}

fn validate_directory(metadata: &Stat, owner: u32, runtime: bool) -> Result<(), Error> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != owner
        || metadata.st_mode & 0o022 != 0
        || (runtime && metadata.st_mode & 0o7777 != 0o755)
    {
        return Err(Error::UnsafeState);
    }
    Ok(())
}

fn validate_lock(metadata: &Stat, owner: u32) -> Result<(), Error> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != owner
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
        || metadata.st_size != 0
    {
        return Err(Error::UnsafeState);
    }
    Ok(())
}

fn named(directory: &OwnedFd, name: &str) -> Result<Stat, Error> {
    statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(system_error)
}

fn require_same(pinned: &Stat, named: &Stat) -> Result<(), Error> {
    if pinned.st_dev != named.st_dev || pinned.st_ino != named.st_ino {
        return Err(Error::UnsafeState);
    }
    Ok(())
}

fn system_error(error: rustix::io::Errno) -> Error {
    Error::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        path::PathBuf,
        sync::{
            Mutex, MutexGuard,
            atomic::{AtomicU64, Ordering},
        },
    };

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    // fork temporarily inherits even CLOEXEC descriptors until exec. Keep the
    // kill/reap fixture from borrowing another test's flock during its release
    // assertion. Production acquisition still reports contention immediately.
    static FIXTURE_PROCESS_LOCK: Mutex<()> = Mutex::new(());

    pub(super) struct Fixture {
        pub(super) path: PathBuf,
        pub(super) owner: u32,
        _process_spawn: MutexGuard<'static, ()>,
    }

    impl Fixture {
        pub(super) fn new() -> Self {
            let process_spawn = FIXTURE_PROCESS_LOCK
                .lock()
                .expect("serialize fixture descriptor inheritance");
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("warper-runtime-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(path.join("run")).unwrap();
            fs::set_permissions(path.join("run"), fs::Permissions::from_mode(0o755)).unwrap();
            fs::create_dir(path.join("run/warper")).unwrap();
            fs::set_permissions(path.join("run/warper"), fs::Permissions::from_mode(0o755))
                .unwrap();
            Self {
                path,
                owner: nix::unistd::geteuid().as_raw(),
                _process_spawn: process_spawn,
            }
        }

        pub(super) fn acquire(&self) -> Result<RuntimeLease, Error> {
            let anchor = open(
                &self.path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            RuntimeLease::acquire_at(anchor, self.owner)
        }

        pub(super) fn lock_path(&self) -> PathBuf {
            self.path.join("run/warper/service.lock")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).expect("remove owned runtime fixture");
        }
    }

    #[test]
    fn lease_contention_and_release_preserve_the_same_empty_lock_inode() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        lease.revalidate().unwrap();
        let initial = fstat(&lease.lock).unwrap();
        assert!(matches!(fixture.acquire(), Err(Error::AlreadyRunning)));
        assert_eq!(format!("{lease:?}"), "RuntimeLease(<redacted>)");
        drop(lease);
        let lease = fixture.acquire().unwrap();
        let restarted = fstat(&lease.lock).unwrap();
        require_same(&initial, &restarted).unwrap();
        assert_eq!(restarted.st_size, 0);
        assert_eq!(restarted.st_mode & 0o7777, 0o600);
        drop(lease);
        assert!(fixture.lock_path().exists());
    }

    #[test]
    fn lease_is_released_when_the_holder_is_killed() {
        use std::{
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };

        const HOLDER_PATH: &str = "WARPER_TEST_RUNTIME_HOLDER";
        if let Some(path) = std::env::var_os(HOLDER_PATH) {
            // Only this test executable accepts the injected fixture. The
            // production API has no path/owner override.
            let path = PathBuf::from(path);
            let anchor = open(
                &path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let _lease = RuntimeLease::acquire_at(anchor, nix::unistd::geteuid().as_raw()).unwrap();
            fs::write(path.join("ready"), b"ready").unwrap();
            loop {
                std::thread::park();
            }
        }

        struct Holder(Child);
        impl Drop for Holder {
            fn drop(&mut self) {
                if self.0.try_wait().expect("inspect fixture child").is_none() {
                    self.0.kill().expect("kill fixture child");
                }
                self.0.wait().expect("reap fixture child");
            }
        }
        let fixture = Fixture::new();
        let mut holder = Holder(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::tests::lease_is_released_when_the_holder_is_killed",
                    "--nocapture",
                ])
                .env(HOLDER_PATH, &fixture.path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fixture.path.join("ready").exists() {
            assert!(
                holder.0.try_wait().unwrap().is_none(),
                "holder exited before readiness"
            );
            assert!(
                Instant::now() < deadline,
                "holder readiness deadline expired"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(fixture.acquire(), Err(Error::AlreadyRunning)));
        let initial = fs::metadata(fixture.lock_path()).unwrap();
        holder.0.kill().unwrap();
        let status = holder.0.wait().unwrap();
        use std::os::unix::{fs::MetadataExt, process::ExitStatusExt};
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
        let lease = fixture.acquire().unwrap();
        assert_eq!(fstat(&lease.lock).unwrap().st_ino, initial.ino());
        lease.revalidate().unwrap();
        drop(lease);
        drop(holder);
    }

    #[test]
    fn unsafe_directory_modes_and_symlink_components_are_never_repaired() {
        for relative in ["run", "run/warper"] {
            let fixture = Fixture::new();
            let path = fixture.path.join(relative);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(matches!(fixture.acquire(), Err(Error::UnsafeState)));
            assert!(!fixture.lock_path().exists());
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o777
            );
        }
        for relative in ["run", "run/warper"] {
            let fixture = Fixture::new();
            let path = fixture.path.join(relative);
            let saved = fixture.path.join("saved");
            fs::rename(&path, &saved).unwrap();
            symlink(&saved, &path).unwrap();
            assert!(matches!(fixture.acquire(), Err(Error::Io(_))));
            assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
            assert!(!saved.join("service.lock").exists());
        }
    }

    #[test]
    fn foreign_owner_and_missing_directories_are_rejected_without_creation() {
        let fixture = Fixture::new();
        let anchor = open(
            &fixture.path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            RuntimeLease::acquire_at(anchor, fixture.owner.wrapping_add(1)),
            Err(Error::UnsafeState)
        ));
        fs::remove_dir(fixture.path.join("run/warper")).unwrap();
        assert!(matches!(
            fixture.acquire(),
            Err(Error::Io(io::ErrorKind::NotFound))
        ));
        assert!(!fixture.path.join("run/warper").exists());
    }

    #[test]
    fn unsafe_existing_lock_files_remain_unchanged() {
        let fixture = Fixture::new();
        let lock = fixture.lock_path();
        fs::write(&lock, b"synthetic foreign state").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(fixture.acquire(), Err(Error::UnsafeState)));
        assert_eq!(fs::read(&lock).unwrap(), b"synthetic foreign state");
        fs::remove_file(&lock).unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&lock)
            .unwrap();
        drop(file);
        assert!(matches!(fixture.acquire(), Err(Error::UnsafeState)));
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&lock, fixture.path.join("alias")).unwrap();
        assert!(matches!(fixture.acquire(), Err(Error::UnsafeState)));
        fs::remove_file(&lock).unwrap();
        symlink(fixture.path.join("alias"), &lock).unwrap();
        assert!(matches!(fixture.acquire(), Err(Error::UnsafeState)));
        assert!(fs::symlink_metadata(&lock).unwrap().is_symlink());
        fs::remove_file(&lock).unwrap();
        fs::create_dir(&lock).unwrap();
        assert!(matches!(fixture.acquire(), Err(Error::UnsafeState)));
    }

    #[test]
    fn changed_directory_or_lock_identity_invalidates_the_lease_and_is_preserved() {
        for relative in ["run", "run/warper", "run/warper/service.lock"] {
            let fixture = Fixture::new();
            let lease = fixture.acquire().unwrap();
            let path = fixture.path.join(relative);
            fs::rename(&path, fixture.path.join("retired")).unwrap();
            if relative.ends_with(".lock") {
                fs::write(&path, b"replacement").unwrap();
            } else {
                fs::create_dir(&path).unwrap();
            }
            assert!(matches!(lease.revalidate(), Err(Error::UnsafeState)));
            drop(lease);
            assert!(path.exists());
            assert!(fixture.path.join("retired").exists());
        }
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        fs::set_permissions(fixture.lock_path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(lease.revalidate(), Err(Error::UnsafeState)));
        fs::remove_file(fixture.lock_path()).unwrap();
        assert!(matches!(lease.revalidate(), Err(Error::UnsafeState)));
        drop(lease);
    }

    #[test]
    fn public_acquisition_rejects_unprivileged_callers_before_runtime_access() {
        crate::namespace::require_initial_user_namespace().unwrap();
        if !nix::unistd::geteuid().is_root() {
            assert!(matches!(
                RuntimeLease::acquire(),
                Err(Error::PrivilegeRequired)
            ));
        }
        for error in [
            Error::Admission(crate::Error::UntrustedNamespace),
            Error::PrivilegeRequired,
            Error::UnsafeState,
            Error::AlreadyRunning,
            system_error(rustix::io::Errno::ACCESS),
        ] {
            assert!(!error.to_string().contains("warper-runtime-"));
        }
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::{
        endpoint::{ControlEndpoint, Error},
        tests::Fixture,
    };
    use crate::{OwnerPolicy, Role};
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{fs::PermissionsExt, net::UnixStream},
        sync::Arc,
    };

    #[test]
    fn worker_ownership_keeps_the_instance_locked_after_listener_retirement() {
        let fixture = Fixture::new();
        let lease = Arc::new(fixture.acquire().unwrap());
        let endpoint = ControlEndpoint::bind(lease.clone()).unwrap();
        let worker_lease = lease.clone();
        let (release, finish) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            finish.recv().unwrap();
            worker_lease.revalidate().unwrap();
        });
        drop(lease);
        endpoint.close().unwrap();
        let contention = fixture.acquire();
        let remained_locked = matches!(contention, Err(super::Error::AlreadyRunning));
        drop(contention);
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(
            remained_locked,
            "listener retirement must not release worker ownership"
        );
        drop(fixture.acquire().unwrap());
    }

    #[test]
    fn endpoint_authenticates_local_peers_and_retires_only_owned_state() {
        let fixture = Fixture::new();
        let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
        let policy = OwnerPolicy::new(Some(fixture.owner)).unwrap();
        assert!(endpoint.accept(&policy).unwrap().is_none());
        let mut client = UnixStream::connect(fixture.path.join("run/warper/control.sock")).unwrap();
        let mut accepted = endpoint.accept(&policy).unwrap().unwrap();
        assert_eq!(
            accepted.role,
            if fixture.owner == 0 {
                Role::Administrator
            } else {
                Role::Owner
            }
        );
        client.write_all(b"synthetic control data").unwrap();
        let mut bytes = [0; 22];
        accepted.stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"synthetic control data");
        drop(accepted);
        drop(client);
        endpoint.close().unwrap();
        assert!(!fixture.path.join("run/warper/control.sock").exists());
        assert!(!fixture.path.join("run/warper/control.intent").exists());
        assert!(fixture.lock_path().exists());
        let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
        endpoint.close().unwrap();
    }

    #[test]
    fn endpoint_denies_foreign_policy_before_payload_is_returned() {
        let fixture = Fixture::new();
        let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
        let client = UnixStream::connect(fixture.path.join("run/warper/control.sock")).unwrap();
        let policy = OwnerPolicy::new(None).unwrap();
        if fixture.owner != 0 {
            assert!(matches!(
                endpoint.accept(&policy),
                Err(Error::Peer(crate::Error::PermissionDenied))
            ));
        } else {
            drop(endpoint.accept(&policy).unwrap());
        }
        drop(client);
        endpoint.close().unwrap();
    }

    #[test]
    fn endpoint_drop_preserves_uncertain_state_and_restart_never_deletes_it() {
        let fixture = Fixture::new();
        let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
        drop(endpoint);
        assert!(
            matches!(ControlEndpoint::bind(fixture.acquire().unwrap()), Err(failure) if failure.primary == Error::Conflict)
        );
        assert!(fixture.path.join("run/warper/control.sock").exists());
        assert!(fixture.path.join("run/warper/control.intent").exists());
    }

    #[test]
    fn endpoint_retirement_preserves_replaced_or_changed_socket_and_intent() {
        for name in ["control.sock", "control.intent"] {
            let fixture = Fixture::new();
            let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
            let path = fixture.path.join("run/warper").join(name);
            fs::rename(&path, fixture.path.join("retired")).unwrap();
            fs::write(&path, b"foreign fixture state").unwrap();
            assert!(endpoint.close().is_err());
            assert_eq!(fs::read(&path).unwrap(), b"foreign fixture state");
        }
        let fixture = Fixture::new();
        let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
        let path = fixture.path.join("run/warper/control.sock");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(endpoint.close(), Err(Error::ChangedState));
        assert!(path.exists());
        assert!(fixture.path.join("run/warper/control.intent").exists());
    }

    #[test]
    fn existing_intent_and_socket_objects_are_preserved_before_publication() {
        for name in ["control.sock", "control.intent"] {
            let fixture = Fixture::new();
            let path = fixture.path.join("run/warper").join(name);
            fs::write(&path, b"foreign fixture state").unwrap();
            assert!(
                matches!(ControlEndpoint::bind(fixture.acquire().unwrap()), Err(failure) if failure.primary == Error::Conflict)
            );
            assert_eq!(fs::read(path).unwrap(), b"foreign fixture state");
        }
    }
}
