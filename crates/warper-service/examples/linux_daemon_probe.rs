// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Actual foreground daemon and CLI inside the independent disposable harness.

#[cfg(target_os = "linux")]
#[path = "linux/fixture.rs"]
mod fixture;

#[cfg(target_os = "linux")]
mod linux {
    use super::fixture::{self, Failure};
    use std::{
        fs,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{Instant, timeout},
    };
    use warper_config::{managed::Snapshot, schema::Platform};
    use warper_core::configuration::paths::{Account, Paths};

    const DAEMON: &str = "/run/warper/daemon-fixture";
    const CLI: &str = "/run/warper/client-fixture";
    const NAME: &str = "warper-daemon";
    const SAMPLE: &[u8] = b"tunnel: {ip: 198.18.0.1, name: warper-daemon}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]\ntimeouts: {connect_ms: 3000, shutdown_ms: 3000}";

    fn prepare() -> Result<(), Failure> {
        for (variable, destination) in [("WARPERD_BINARY", DAEMON), ("WARPER_BINARY", CLI)] {
            let source =
                PathBuf::from(std::env::var_os(variable).ok_or("fixture binary path missing")?);
            if !source.is_absolute() || !source.metadata()?.is_file() {
                return Err("fixture binary path invalid".into());
            }
            let hash = Command::new("sha256sum").arg(&source).output()?;
            if !hash.status.success() {
                return Err("fixture binary checksum failed".into());
            }
            println!("fixture_binary {}", String::from_utf8(hash.stdout)?);
            fs::copy(source, destination)?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
        }
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open("/etc/group")?
            .write_all(b"shared:x:2000:owner\n")?;
        let sample = String::from_utf8(SAMPLE.to_vec())?;
        let authenticated = sample.replace(
            "host: '127.0.0.1:1080'",
            "host: '127.0.0.1:1080', user: fixture-user, password_file: owner-secret",
        );
        for (name, bytes, uid) in [
            ("source.yaml", sample.as_bytes(), 1000),
            ("owner-auth.yaml", authenticated.as_bytes(), 1000),
            (
                "bad-auth.yaml",
                authenticated
                    .replace("owner-secret", "root-secret")
                    .as_bytes(),
                1000,
            ),
            ("owner-secret", b"fixture-user-password".as_slice(), 1000),
            ("root-secret", b"fixture-root-password".as_slice(), 0),
        ] {
            let path = format!("/run/warper/{name}");
            fs::write(&path, bytes)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            rustix::fs::chown(
                &path,
                Some(rustix::process::Uid::from_raw(uid)),
                Some(rustix::process::Gid::from_raw(uid)),
            )?;
        }
        let shared = "/run/warper/shared.yaml";
        fs::write(shared, SAMPLE)?;
        fs::set_permissions(shared, fs::Permissions::from_mode(0o640))?;
        rustix::fs::chown(
            shared,
            Some(rustix::process::Uid::from_raw(1001)),
            Some(rustix::process::Gid::from_raw(2000)),
        )?;
        Ok(())
    }
    async fn cli(uid: u32, arguments: &[&str]) -> Result<(bool, String, String), Failure> {
        let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
        tokio::task::spawn_blocking(move || {
            let mut command = Command::new("/usr/bin/timeout");
            command
                .args([
                    "--kill-after=1s",
                    "4s",
                    "/usr/bin/setpriv",
                    "--reuid",
                    &uid.to_string(),
                    "--regid",
                    &uid.to_string(),
                    "--clear-groups",
                    CLI,
                ])
                .args(arguments)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null());
            if uid == 0 {
                command.env("SUDO_UID", "1000").env("SUDO_USER", "owner");
            }
            let output = command.output()?;
            Ok((
                output.status.success(),
                String::from_utf8(output.stdout)?,
                String::from_utf8(output.stderr)?,
            ))
        })
        .await?
    }
    async fn status(expected: &str) -> Result<(), Failure> {
        status_for(1000, expected).await
    }
    async fn status_for(uid: u32, expected: &str) -> Result<(), Failure> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let (success, stdout, _) = cli(uid, &["status", "--json"]).await?;
            if success && stdout.contains(&format!("\"state\":\"{expected}\"")) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("daemon did not report {expected}").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn traffic() -> Result<(), Failure> {
        let listener = TcpListener::bind("127.0.0.1:1080").await?;
        let server = tokio::spawn(async move {
            timeout(Duration::from_secs(4), async move {
                let (mut stream, _) = listener.accept().await?;
                let mut hello = [0; 3];
                stream.read_exact(&mut hello).await?;
                if hello != [5, 1, 0] {
                    return Err("SOCKS greeting differs".into());
                }
                stream.write_all(&[5, 0]).await?;
                let mut request = [0; 10];
                stream.read_exact(&mut request).await?;
                if request != [5, 1, 0, 1, 198, 18, 0, 2, 1, 187] {
                    return Err("SOCKS original destination differs".into());
                }
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                let mut payload = Vec::new();
                (&mut stream).take(65_537).read_to_end(&mut payload).await?;
                if payload != vec![0x41; 65_536] {
                    return Err("daemon request bytes or FIN differ".into());
                }
                stream.write_all(&vec![0x42; 16_393]).await?;
                stream.shutdown().await?;
                Ok::<_, Failure>(())
            })
            .await?
        });
        let outcome = timeout(Duration::from_secs(4), async {
            let mut app = TcpStream::connect("198.18.0.2:443").await?;
            app.write_all(&vec![0x41; 65_536]).await?;
            app.shutdown().await?;
            let mut response = Vec::new();
            (&mut app).take(16_394).read_to_end(&mut response).await?;
            if response != vec![0x42; 16_393] {
                return Err("daemon response after application FIN differs".into());
            }
            Ok::<_, Failure>(())
        })
        .await;
        let outcome = outcome
            .map_err(|error| Box::new(error) as Failure)
            .and_then(|result| result);
        if outcome.is_err() {
            server.abort();
        }
        let mut cleanup = Vec::new();
        match server.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup.push(error),
            Err(error) if outcome.is_err() && error.is_cancelled() => {}
            Err(error) => cleanup.push(Box::new(error) as Failure),
        }
        fixture::preserve(outcome, cleanup)
    }
    fn usage(child: &Child) -> Result<(u64, String), Failure> {
        use std::io::Read;
        let mut stat = String::new();
        fs::File::open(format!("/proc/{}/stat", child.id()))?
            .take(8193)
            .read_to_string(&mut stat)?;
        if stat.len() > 8192 {
            return Err("daemon process stat exceeded bound".into());
        }
        let fields: Vec<_> = stat[stat.rfind(')').ok_or("daemon stat delimiter missing")? + 1..]
            .split_whitespace()
            .collect();
        let ticks = fields
            .get(11)
            .ok_or("daemon user CPU missing")?
            .parse::<u64>()?
            .checked_add(fields.get(12).ok_or("daemon system CPU missing")?.parse()?)
            .ok_or("daemon CPU counter overflow")?;
        let mut status = String::new();
        fs::File::open(format!("/proc/{}/status", child.id()))?
            .take(16_385)
            .read_to_string(&mut status)?;
        if status.len() > 16_384 {
            return Err("daemon process status exceeded bound".into());
        }
        let peak = status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .ok_or("daemon peak RSS missing")?
            .to_owned();
        Ok((ticks, peak))
    }
    async fn workload(child: &Child) -> Result<(), Failure> {
        let (before, _) = usage(child)?;
        let started = Instant::now();
        let mut latency = Vec::with_capacity(100);
        for _ in 0..100 {
            let sample = Instant::now();
            let (success, stdout, _) = cli(1000, &["status", "--json"]).await?;
            if !success || !stdout.contains("\"state\":\"connected\"") {
                return Err("daemon status workload failed".into());
            }
            latency.push(sample.elapsed().as_nanos());
        }
        latency.sort_unstable();
        let (after, peak) = usage(child)?;
        let hz = Command::new("getconf").arg("CLK_TCK").output()?;
        if !hz.status.success() {
            return Err("CPU tick frequency unavailable".into());
        }
        let hz: u64 = String::from_utf8(hz.stdout)?.trim().parse()?;
        println!(
            "daemon_workload scope=debug_daemon_cli_process_status iterations=100 concurrency=1 arch={} os={} control_encoded_bytes=12200 elapsed_ns={} daemon_cpu_ticks={} ticks_per_second={hz} p50_ns={} p95_ns={} p99_ns={} app_request_bytes=65536 app_response_bytes=16393 failures=0 kernel_drops=unmeasured {peak}",
            std::env::consts::ARCH,
            std::env::consts::OS,
            started.elapsed().as_nanos(),
            after
                .checked_sub(before)
                .ok_or("daemon CPU counter decreased")?,
            latency[49],
            latency[94],
            latency[98]
        );
        Ok(())
    }

    async fn failed_startup() -> Result<(), Failure> {
        use warper_control::{
            message::Status,
            runtime::client,
            wire::{Frame, Kind},
        };
        let (_keep, mut cancel) = tokio::sync::watch::channel(false);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = client::connect(deadline, cancel.clone()).await?;
        Frame::new(Kind::Hello, 1, vec![])?
            .write(&mut stream, deadline, &mut cancel)
            .await?;
        if Frame::read(&mut stream, deadline, &mut cancel)
            .await?
            .kind()
            != Kind::HelloReply
        {
            return Err("admin Hello differs".into());
        }
        Frame::new(Kind::Status, 2, vec![])?
            .write(&mut stream, deadline, &mut cancel)
            .await?;
        let current = Status::decode(&Frame::read(&mut stream, deadline, &mut cancel).await?)?;
        let paths = Paths::new(
            &Account {
                uid: 1000,
                name: "owner".into(),
                home: "/sample".into(),
            },
            Path::new("/sample"),
            None,
        )?;
        let sample =
            String::from_utf8(SAMPLE.to_vec())?.replace("127.0.0.1:1080", "198.18.0.2:1080");
        let encoded = Snapshot::import(sample.as_bytes(), &paths, Platform::Linux)?.encode()?;
        let mut body = current.configuration_generation.to_be_bytes().to_vec();
        body.extend_from_slice(encoded.expose());
        Frame::new(Kind::InstallConfig, 3, body)?
            .write(&mut stream, deadline, &mut cancel)
            .await?;
        if Frame::read(&mut stream, deadline, &mut cancel)
            .await?
            .kind()
            != Kind::ConfigReply
        {
            return Err("admin installation failed".into());
        }
        drop(stream);
        if cli(1000, &["up", "--wait-ms", "3000"]).await?.0 {
            return Err("unreachable physical endpoint became connected".into());
        }
        status("failed").await?;
        if !cli(1000, &["down", "--wait-ms", "3000"]).await?.0 {
            return Err("failed startup could not be disconnected".into());
        }
        status("disconnected").await
    }

    async fn stop(child: &mut Child) -> Result<(), Failure> {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id().try_into()?),
            nix::sys::signal::Signal::SIGTERM,
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err("daemon graceful shutdown failed".into());
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("daemon graceful shutdown exceeded fixture deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn restart(child: &mut Child) -> Result<(), Failure> {
        if child.try_wait()?.is_none() {
            return Err("cannot replace a live daemon child".into());
        }
        let stdout = fs::OpenOptions::new()
            .append(true)
            .open("/run/warper/daemon.stdout")?;
        let stderr = fs::OpenOptions::new()
            .append(true)
            .open("/run/warper/daemon.stderr")?;
        *child = Command::new(DAEMON)
            .arg("service")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;
        Ok(())
    }
    fn offline_command(arguments: &[&str]) -> Result<std::process::Output, Failure> {
        Ok(Command::new("/usr/bin/timeout")
            .args(["--kill-after=1s", "8s", DAEMON])
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .output()?)
    }
    async fn repair_abandoned() -> Result<(), Failure> {
        tokio::task::spawn_blocking(|| -> Result<(), Failure> {
            let dirty = offline_command(&["recover", "--inspect"])?;
            if !dirty.status.success()
                || dirty.stdout != b"Control endpoint: retirable\nOwner pending intent: no\nConfiguration pending intent: no\nConnection pending intent: no\nNetwork pending intent: no\nNetwork ownership: retirable\n"
            {
                return Err("offline inspection did not identify abandoned service ownership".into());
            }
            let repaired = offline_command(&["recover"])?;
            if !repaired.status.success()
                || repaired.stdout != b"Recovery completed.\n"
                || !repaired.stderr.is_empty()
            {
                return Err(format!(
                    "offline abandoned repair failed: {}",
                    String::from_utf8_lossy(&repaired.stderr)
                ).into());
            }
            let clean = offline_command(&["recover", "--inspect"])?;
            if !clean.status.success()
                || clean.stdout != b"Control endpoint: absent\nOwner pending intent: no\nConfiguration pending intent: no\nConnection pending intent: no\nNetwork pending intent: no\nNetwork ownership: retired\n"
            {
                return Err("offline abandoned repair did not retire protected ownership".into());
            }
            Ok(())
        }).await?
    }
    async fn offline_recovery() -> Result<(), Failure> {
        tokio::task::spawn_blocking(|| -> Result<(), Failure> {
            use std::io::Write;
            use std::os::unix::fs::MetadataExt;
            let paths = [
                "/var/lib/warper/owner",
                "/var/lib/warper/connection",
                "/var/lib/warper/network.journal",
                "/etc/warper/configuration",
            ];
            let before = paths.map(|path| {
                Ok::<_, Failure>((fs::metadata(path)?, fs::read(path)?))
            });
            let output = offline_command(&["recover", "--inspect"])?;
            if !output.status.success()
                || !output.stderr.is_empty()
                || output.stdout != b"Control endpoint: absent\nOwner pending intent: no\nConfiguration pending intent: no\nConnection pending intent: no\nNetwork pending intent: no\nNetwork ownership: retired\n"
            {
                return Err("offline native inspection did not report protected retired state".into());
            }
            let pending = [
                "/var/lib/warper/owner.pending",
                "/var/lib/warper/connection.pending",
                "/var/lib/warper/network.pending",
                "/etc/warper/configuration.pending",
            ];
            for path in pending {
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)?
                    .write_all(b"partial")?;
            }
            fs::set_permissions(pending[2], fs::Permissions::from_mode(0o644))?;
            let rejected = offline_command(&["recover"])?;
            if rejected.status.success() || !rejected.stdout.is_empty() {
                return Err("offline repair accepted unsafe pending metadata".into());
            }
            for path in pending {
                if fs::read(path)? != b"partial" {
                    return Err("offline repair mutated intent before completing validation".into());
                }
            }
            if fs::metadata(pending[2])?.permissions().mode() & 0o7777 != 0o644 {
                return Err("offline repair changed unsafe pending metadata".into());
            }
            fs::set_permissions(pending[2], fs::Permissions::from_mode(0o600))?;
            let dirty = offline_command(&["recover", "--inspect"])?;
            if !dirty.status.success()
                || !dirty.stderr.is_empty()
                || dirty.stdout != b"Control endpoint: absent\nOwner pending intent: yes\nConfiguration pending intent: yes\nConnection pending intent: yes\nNetwork pending intent: yes\nNetwork ownership: retired\n"
            {
                return Err("offline inspection did not classify pending intent".into());
            }
            for path in pending {
                if fs::read(path)? != b"partial" {
                    return Err("offline inspection changed pending intent".into());
                }
            }
            for _ in 0..2 {
                let repaired = offline_command(&["recover"])?;
                if !repaired.status.success()
                    || !repaired.stderr.is_empty()
                    || repaired.stdout != b"Recovery completed.\n"
                {
                    return Err("offline native repair did not complete idempotently".into());
                }
            }
            if pending.iter().any(|path| Path::new(path).exists()) {
                return Err("offline repair retained unpublished intent".into());
            }
            for (path, expected) in paths.iter().zip(before) {
                let (metadata, bytes) = expected?;
                let current = fs::metadata(path)?;
                if fs::read(path)? != bytes
                    || current.dev() != metadata.dev()
                    || current.ino() != metadata.ino()
                    || current.mtime() != metadata.mtime()
                    || current.mtime_nsec() != metadata.mtime_nsec()
                    || current.ctime() != metadata.ctime()
                    || current.ctime_nsec() != metadata.ctime_nsec()
                {
                    return Err("offline inspection/repair changed committed state".into());
                }
            }
            Ok(())
        })
        .await?
    }
    pub async fn exercise(mount: &str, net: &str) -> Result<(), Failure> {
        fixture::isolated(mount, net)?;
        let workers = warper_service::native::Workers::new(1)?;
        let (keep, _) = tokio::sync::watch::channel(false);
        let mut preparation = workers.try_reserve()?.start(prepare);
        fixture::join_native(&mut preparation, &keep).await??;
        let before = fixture::ip(&["-j", "route", "show", "table", "all"])?;
        let stdout = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open("/run/warper/daemon.stdout")?;
        let stderr = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open("/run/warper/daemon.stderr")?;
        let mut child = Command::new(DAEMON)
            .arg("service")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;
        let outcome = async {
            status_for(0, "disconnected").await?;
            let denied = cli(
                0,
                &["config", "install", "--config", "/run/warper/bad-auth.yaml"],
            )
            .await?;
            if denied.0
                || denied.1.contains("fixture-root-password")
                || denied.2.contains("fixture-root-password")
            {
                return Err("sudo import read a root-only credential or exposed it".into());
            }
            let initial = cli(0, &["status", "--json"]).await?;
            if !initial.0 || !initial.1.contains("\"configuration_generation\":0") {
                return Err("denied import changed approved configuration".into());
            }
            for path in [
                "/run/warper/owner-auth.yaml",
                "/run/warper/shared.yaml",
                "/run/warper/source.yaml",
            ] {
                let installed = cli(0, &["config", "install", "--config", path]).await?;
                if !installed.0 {
                    return Err(format!("administrative CLI import failed: {}", installed.2).into());
                }
            }
            if !cli(0, &["owner", "enroll"]).await?.0 {
                return Err("default invoking-owner enrollment failed".into());
            }
            status("disconnected").await?;
            if cli(1000, &["owner", "clear"]).await?.0 {
                return Err("ordinary owner changed administrative policy".into());
            }
            if !cli(0, &["owner", "clear"]).await?.0 || cli(1000, &["status"]).await?.0 {
                return Err("owner removal did not revoke control".into());
            }
            if !cli(0, &["owner", "enroll", "--uid", "1000"]).await?.0 {
                return Err("explicit owner enrollment failed".into());
            }
            status("disconnected").await?;
            let (success, stdout, stderr) = cli(1000, &["up", "--no-wait"]).await?;
            if !success || !stdout.contains(": accepted") {
                return Err(format!("native CLI Connect was not accepted: {stderr}").into());
            }
            status("connected").await?;
            traffic().await?;
            // The CLI process and application have exited; networking stays up.
            status("connected").await?;
            workload(&child).await?;
            if cli(1001, &["up", "--no-wait"]).await?.0 {
                return Err("foreign CLI controlled the service".into());
            }
            status("connected").await?;
            let (success, stdout, stderr) = cli(1000, &["down", "--wait-ms", "3000"]).await?;
            if !success || !stdout.contains(": succeeded") {
                return Err(format!("native CLI Disconnect did not complete: {stderr}").into());
            }
            status("disconnected").await?;
            failed_startup().await?;
            if before != fixture::ip(&["-j", "route", "show", "table", "all"])?
                || nix::net::if_::if_nameindex()?
                    .iter()
                    .any(|interface| interface.name().to_bytes() == NAME.as_bytes())
            {
                return Err("daemon Disconnect did not restore owned networking".into());
            }
            if !cli(
                0,
                &["config", "install", "--config", "/run/warper/source.yaml"],
            )
            .await?
            .0 || !cli(1000, &["up", "--wait-ms", "3000"]).await?.0
            {
                return Err("could not restore approved connection for active shutdown".into());
            }
            status("connected").await?;
            traffic().await?;
            stop(&mut child).await?;
            if before != fixture::ip(&["-j", "route", "show", "table", "all"])?
                || nix::net::if_::if_nameindex()?
                    .iter()
                    .any(|interface| interface.name().to_bytes() == NAME.as_bytes())
            {
                return Err("active SIGTERM did not restore owned networking".into());
            }
            restart(&mut child)?;
            status("connected").await?;
            traffic().await?;
            child.kill()?;
            let killed = child.wait()?;
            use std::os::unix::process::ExitStatusExt;
            if killed.signal() != Some(9) {
                return Err("active daemon was not reaped after SIGKILL".into());
            }
            repair_abandoned().await?;
            restart(&mut child)?;
            status("connected").await?;
            traffic().await?;
            if !cli(1000, &["down", "--wait-ms", "3000"]).await?.0 {
                return Err("restored same-boot intent could not be disconnected".into());
            }
            stop(&mut child).await?;
            restart(&mut child)?;
            status("disconnected").await?;
            Ok::<_, Failure>(())
        }
        .await;
        let mut cleanup = Vec::new();
        if let Err(error) = stop(&mut child).await {
            cleanup.push(error);
        }
        if child.try_wait()?.is_none() {
            if let Err(error) = child.kill() {
                cleanup.push(Box::new(error) as Failure);
            }
            if let Err(error) = child.wait() {
                cleanup.push(Box::new(error) as Failure);
            }
        }
        let stderr = fs::read_to_string("/run/warper/daemon.stderr")?;
        if !stderr.is_empty() {
            println!("daemon_diagnostic {stderr}");
        }
        fixture::preserve(outcome, cleanup)?;
        if Path::new("/run/warper/control.sock").exists()
            || Path::new("/run/warper/control.intent").exists()
        {
            return Err("daemon did not retire its endpoint".into());
        }
        if before != fixture::ip(&["-j", "route", "show", "table", "all"])?
            || nix::net::if_::if_nameindex()?
                .iter()
                .any(|interface| interface.name().to_bytes() == NAME.as_bytes())
        {
            return Err("daemon restart/stop left owned networking".into());
        }
        offline_recovery().await?;
        if before != fixture::ip(&["-j", "route", "show", "table", "all"])? {
            return Err("offline recovery changed namespace routes".into());
        }
        println!(
            "PASS actual warperd/warper owner authentication, accepted-client detach, kernel TCP/FIN, foreign denial, explicit Disconnect, failed-start rollback, active SIGTERM cleanup, SIGKILL recovery, same-boot desired restoration, persisted Disconnect, endpoint retirement and stopped-service inspection/repair"
        );
        Ok(())
    }
    pub fn root() -> Result<(), Failure> {
        fixture::root()
    }
}
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), fixture::Failure> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "--require-initial-root" => linux::root(),
        [mode, mount, net] if mode == "--exercise" => linux::exercise(mount, net).await,
        _ => Err("use the disposable namespace acceptance harness".into()),
    }
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedIntegration: native daemon probe requires Linux");
    std::process::ExitCode::FAILURE
}
