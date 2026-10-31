// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real root/owner/foreign-peer fixture. Run only through control_acceptance.py.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{fs::MetadataExt, net::UnixStream},
        process::{Child, Command},
        time::{Duration, Instant},
    };
    use warper_control::{
        Access, Error, Role, namespace,
        runtime::{
            RuntimeLease,
            connection::{Acceptance, ConnectionStore, Desired, Request as IntentRequest},
            endpoint::ControlEndpoint,
            enrollment::OwnerStore,
        },
        unix,
    };
    type Failure = Box<dyn std::error::Error>;

    struct Client(Child);
    impl Client {
        fn start(uid: u32, mode: &str) -> Result<Self, Failure> {
            Ok(Self(
                Command::new("/usr/bin/setpriv")
                    .args([
                        "--reuid",
                        &uid.to_string(),
                        "--regid",
                        &uid.to_string(),
                        "--clear-groups",
                    ])
                    .arg(std::env::current_exe()?)
                    .args(["--client", mode])
                    .spawn()?,
            ))
        }
        fn join(&mut self) -> Result<(), Failure> {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(status) = self.0.try_wait()? {
                    if status.success() {
                        return Ok(());
                    }
                    return Err("controlled client failed".into());
                }
                if Instant::now() >= deadline {
                    return Err("controlled client deadline expired".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    impl Drop for Client {
        fn drop(&mut self) {
            if self
                .0
                .try_wait()
                .expect("inspect controlled client")
                .is_none()
            {
                self.0.kill().expect("kill controlled client");
            }
            self.0.wait().expect("reap controlled client");
        }
    }

    fn root() -> Result<(), Failure> {
        namespace::require_initial_user_namespace()?;
        if !nix::unistd::geteuid().is_root() {
            return Err("fixture requires actual initial-namespace UID 0".into());
        }
        let (a, _b) = UnixStream::pair()?;
        unix::authenticate_service(&a)?;
        Ok(())
    }
    fn isolated(mount_fd: &str, net_fd: &str) -> Result<(), Failure> {
        root()?;
        for (kind, anchor) in [("mnt", mount_fd), ("net", net_fd)] {
            let fd: u32 = anchor.parse()?;
            let path = format!("/proc/self/fd/{fd}");
            let label = fs::read_link(&path)?;
            let label = label.to_str().ok_or("invalid namespace anchor")?;
            let file = fs::File::open(&path)?;
            // Linux NSFS_MAGIC. Ordinary descriptors must not pass an accidental
            // direct invocation of this development-only fixture.
            if rustix::fs::fstatfs(&file)?.f_type as u64 != 0x6e736673
                || !label.starts_with(&format!("{kind}:["))
                || !label.ends_with(']')
            {
                return Err("fixture requires inherited namespace handles".into());
            }
            let parent = file.metadata()?;
            let current = fs::metadata(format!("/proc/thread-self/ns/{kind}"))?;
            if parent.dev() == current.dev() && parent.ino() == current.ino() {
                return Err("fixture must use independent mount and network namespaces".into());
            }
        }
        Ok(())
    }
    fn connection_intent(lease: &RuntimeLease) -> Result<(), Failure> {
        let mut store = ConnectionStore::open(lease)?;
        if store.read(lease)?.is_some() {
            return Err("intent fixture must begin empty".into());
        }
        let mut connect_operation = [1; 16];
        connect_operation[..8].copy_from_slice(&0u64.to_be_bytes());
        let connect = IntentRequest {
            operation: connect_operation,
            expected_configuration: 7,
            expected_revision: 0,
            expected_instance: store.instance_id(),
            desired: Desired::Up,
        };
        if !matches!(store.accept(lease, 7, connect)?, Acceptance::Accepted(snapshot) if snapshot.revision()==1)
            || !matches!(store.accept(lease, 7, connect)?, Acceptance::AlreadyAccepted(snapshot) if snapshot.revision()==1)
        {
            return Err("durable intent acceptance/repeat differs".into());
        }
        let mut disconnect_operation = [2; 16];
        disconnect_operation[..8].copy_from_slice(&1u64.to_be_bytes());
        let disconnect = IntentRequest {
            operation: disconnect_operation,
            expected_revision: 1,
            desired: Desired::Down,
            ..connect
        };
        store.accept(lease, 7, disconnect)?;
        drop(store);
        let mut reopened = ConnectionStore::open(lease)?;
        let record = reopened.read(lease)?.ok_or("durable intent disappeared")?;
        if record.revision() != 2
            || record.desired() != Desired::Down
            || !record.same_boot(&reopened.boot_id())
            || reopened.instance_id() == connect.expected_instance
            || !matches!(reopened.accept(lease, 7, connect), Err(failure) if failure.primary==warper_control::runtime::connection::Error::Conflict)
        {
            return Err("durable intent restart fence or preservation differs".into());
        }
        reopened.resync(lease)?;
        use std::os::unix::fs::PermissionsExt;
        fs::write("/var/lib/warper/connection.pending", b"partial")?;
        fs::set_permissions(
            "/var/lib/warper/connection.pending",
            fs::Permissions::from_mode(0o600),
        )?;
        let inspection = reopened
            .inspect_pending(lease)?
            .ok_or("pending intent was not inspected")?;
        if inspection.pending_len() != 7
            || inspection.committed().map(|record| record.revision()) != Some(2)
        {
            return Err("pending intent inspection differs".into());
        }
        reopened.discard_pending(lease, inspection)?;
        if reopened.read(lease)?.map(|record| record.desired()) != Some(Desired::Down) {
            return Err("pending intent discard changed committed desired state".into());
        }
        println!(
            "PASS durable root connection intent, repeat suppression, restart fencing and resync without network actions"
        );
        Ok(())
    }

    fn configure(stream: &UnixStream) -> Result<(), Failure> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        Ok(())
    }
    fn client(mode: &str) -> Result<(), Failure> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (_cancellation, cancel) = tokio::sync::watch::channel(false);
        let connected = runtime.block_on(warper_control::runtime::client::connect(
            tokio::time::Instant::now() + Duration::from_secs(2),
            cancel,
        ));
        if mode == "unsafe-endpoint" {
            return match connected {
                Err(warper_control::runtime::client::Error::UnsafeEndpoint) => Ok(()),
                _ => Err("unsafe endpoint was not rejected before connection".into()),
            };
        }
        let mut stream = connected?.into_std()?;
        configure(&stream)?;
        unix::authenticate_service(&stream)?;
        match mode {
            "allowed" => {
                stream.write_all(b"probe")?;
                let mut reply = [0];
                stream.read_exact(&mut reply)?;
                if reply != [1] {
                    return Err("controlled authorization reply differs".into());
                }
            }
            "denied" => {
                let mut reply = [0];
                if stream.read(&mut reply)? != 0 {
                    return Err("foreign peer received metadata".into());
                }
            }
            _ => return Err("unknown client fixture mode".into()),
        }
        Ok(())
    }

    fn exercise(mount_fd: &str, net_fd: &str) -> Result<(), Failure> {
        isolated(mount_fd, net_fd)?;
        let lease = RuntimeLease::acquire()?;
        if !matches!(
            RuntimeLease::acquire(),
            Err(warper_control::runtime::Error::AlreadyRunning)
        ) {
            return Err("second root instance acquired ownership".into());
        }
        let mut store = OwnerStore::open(&lease)?;
        if store.read(&lease)?.revision() != 0 {
            return Err("fixture must start with empty enrollment".into());
        }
        let endpoint = ControlEndpoint::bind(lease)?;
        // The ordinary owner must inspect the protected endpoint itself,
        // including rejecting changed permissions before sending any payload.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            "/run/warper/control.sock",
            fs::Permissions::from_mode(0o600),
        )?;
        Client::start(1000, "unsafe-endpoint")?.join()?;
        fs::set_permissions(
            "/run/warper/control.sock",
            fs::Permissions::from_mode(0o666),
        )?;
        let (admin, _other) = UnixStream::pair()?;
        let enrolled = store.enroll(endpoint.runtime(), &admin, 0, Some(1000))?;
        if enrolled.revision() != 1 {
            return Err("bootstrap revision differs".into());
        }
        let policy = enrolled.policy();
        let mut old_owner = None;
        for (uid, mode, expected) in [
            (0, "allowed", Some(Role::Administrator)),
            (1000, "allowed", Some(Role::Owner)),
            (1001, "denied", None),
        ] {
            let mut child = Client::start(uid, mode)?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match endpoint.accept(&policy) {
                    Ok(Some(mut accepted)) => {
                        if Some(accepted.role) != expected {
                            return Err("controlled role differs".into());
                        }
                        let admin_result = unix::authenticate_client(
                            &accepted.stream,
                            &policy,
                            Access::Administer,
                        );
                        if uid == 0 {
                            if admin_result != Ok(Role::Administrator) {
                                return Err("root cannot administer".into());
                            }
                        } else if admin_result != Err(Error::PermissionDenied) {
                            return Err("ordinary owner can administer".into());
                        }
                        configure(&accepted.stream)?;
                        let mut bytes = [0; 5];
                        accepted.stream.read_exact(&mut bytes)?;
                        if &bytes != b"probe" {
                            return Err("controlled request differs".into());
                        }
                        accepted.stream.write_all(&[1])?;
                        if uid == 1000 {
                            old_owner = Some(accepted.stream);
                        }
                        break;
                    }
                    Err(warper_control::runtime::endpoint::Error::Peer(
                        Error::PermissionDenied,
                    )) if expected.is_none() => break,
                    Ok(None) => {}
                    _ => return Err("controlled peer admission differs".into()),
                }
                if Instant::now() >= deadline {
                    return Err("controlled accept deadline expired".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            child.join()?;
        }
        let replaced = store.enroll(endpoint.runtime(), &admin, 1, Some(1001))?;
        let old_owner = old_owner.ok_or("owner snapshot is missing")?;
        if unix::authenticate_client(&old_owner, &replaced.policy(), Access::Observe)
            != Err(Error::PermissionDenied)
        {
            return Err("old kernel credential snapshot retained owner permission".into());
        }
        let cleared = store.enroll(endpoint.runtime(), &admin, 2, None)?;
        if cleared.revision() != 3 {
            return Err("owner removal revision differs".into());
        }
        let pending = "/var/lib/warper/owner.pending";
        fs::write(pending, b"WOWN")?;
        fs::set_permissions(pending, fs::Permissions::from_mode(0o600))?;
        if !matches!(
            store.inspect_pending(endpoint.runtime(), &old_owner),
            Err(warper_control::runtime::enrollment::Error::Peer(
                Error::PermissionDenied
            ))
        ) {
            return Err("ordinary peer inspected administrative recovery state".into());
        }
        let inspection = store
            .inspect_pending(endpoint.runtime(), &admin)?
            .ok_or("partial enrollment intent was not inspected")?;
        if inspection.committed().revision() != 3 || inspection.pending_len() != 4 {
            return Err("pending enrollment inspection differs".into());
        }
        if store
            .discard_pending(endpoint.runtime(), &admin, inspection)?
            .revision()
            != 3
            || fs::symlink_metadata(pending).is_ok()
        {
            return Err("partial enrollment recovery did not preserve committed revision".into());
        }
        drop(old_owner);
        connection_intent(endpoint.runtime())?;
        let reopened = OwnerStore::open(endpoint.runtime())?;
        if reopened.read(endpoint.runtime())?.revision() != 3 {
            return Err("protected owner snapshot did not persist".into());
        }
        drop(reopened);
        drop(store);
        drop(admin);
        endpoint.close()?;
        if fs::symlink_metadata("/run/warper/control.sock").is_ok()
            || fs::symlink_metadata("/run/warper/control.intent").is_ok()
        {
            return Err("owned endpoint did not retire".into());
        }
        drop(RuntimeLease::acquire()?);
        println!(
            "PASS root ownership, bootstrap enrollment, actual owner/foreign peers, policy replacement, pending recovery, persistence and endpoint retirement"
        );
        Ok(())
    }

    pub fn run() -> Result<(), Failure> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        match args.as_slice() {
            [mode] if mode == "--require-initial-root" => {
                root()?;
                println!("PASS initial user namespace and real root kernel peer");
                Ok(())
            }
            [mode, mount_fd, net_fd] if mode == "--exercise" => exercise(mount_fd, net_fd),
            [mode, client_mode] if mode == "--client" => client(client_mode),
            _ => Err("use the controlled privileged harness".into()),
        }
    }
}
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedIntegration: privileged control fixture requires Linux");
    std::process::ExitCode::FAILURE
}
