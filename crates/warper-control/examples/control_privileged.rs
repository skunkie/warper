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
        runtime::{RuntimeLease, endpoint::ControlEndpoint, enrollment::OwnerStore},
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
    fn configure(stream: &UnixStream) -> Result<(), Failure> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        Ok(())
    }
    fn client(mode: &str) -> Result<(), Failure> {
        let mut stream = UnixStream::connect("/run/warper/control.sock")?;
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
        drop(old_owner);
        let cleared = store.enroll(endpoint.runtime(), &admin, 2, None)?;
        if cleared.revision() != 3 {
            return Err("owner removal revision differs".into());
        }
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
            "PASS root ownership, bootstrap enrollment, actual owner/foreign peers, policy replacement, persistence and endpoint retirement"
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
