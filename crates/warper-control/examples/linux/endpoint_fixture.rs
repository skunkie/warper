// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Private-harness endpoint identity changes and actual owner death/recovery.

use super::{Client, Failure, isolated, root};
use std::{
    fs, io,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use warper_control::{
    runtime::{
        RuntimeLease,
        endpoint::{self, ControlEndpoint, Recovery},
    },
    unix,
};

const READY: &str = "/run/warper/endpoint-ready";

pub(super) fn changed_permissions(endpoint: ControlEndpoint) -> Result<(), Failure> {
    let socket = fs::symlink_metadata("/run/warper/control.sock")?;
    let intent = fs::read("/run/warper/control.intent")?;
    fs::set_permissions(
        "/run/warper/control.sock",
        fs::Permissions::from_mode(0o600),
    )?;
    Client::start(1000, "unsafe-endpoint")?.join()?;
    // The production endpoint preserves this deliberately changed object. Only
    // the disposable harness retires its own injected state after verification.
    if endpoint.close() != Err(endpoint::Error::ChangedState) {
        return Err("changed endpoint was silently adopted".into());
    }
    let changed = fs::symlink_metadata("/run/warper/control.sock")?;
    if socket.dev() != changed.dev()
        || socket.ino() != changed.ino()
        || socket.uid() != changed.uid()
        || socket.gid() != changed.gid()
        || changed.nlink() != 1
        || changed.mode() & 0o7777 != 0o600
        || fs::read("/run/warper/control.intent")? != intent
    {
        return Err("endpoint failure altered controlled foreign state".into());
    }
    fs::remove_file("/run/warper/control.sock")?;
    fs::remove_file("/run/warper/control.intent")?;
    Ok(())
}

pub(super) fn child(mount_fd: &str, net_fd: &str) -> Result<(), Failure> {
    isolated(mount_fd, net_fd)?;
    let _endpoint = ControlEndpoint::bind(RuntimeLease::acquire()?)?;
    use std::io::Write;
    let mut ready = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(READY)?;
    write!(ready, "{}", std::process::id())?;
    ready.sync_all()?;
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

pub(super) fn crash_recovery(mount_fd: &str, net_fd: &str) -> Result<(), Failure> {
    root()?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--endpoint-child", mount_fd, net_fd])
        .spawn()?;
    let mut reaped = false;
    let outcome = (|| -> Result<(), Failure> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match fs::read_to_string(READY) {
                Ok(value) if value == child.id().to_string() => break,
                Ok(_) => return Err("endpoint child ready identity differs".into()),
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {}
                Err(error) => return Err(error.into()),
            }
            if child.try_wait()?.is_some() {
                reaped = true;
                return Err("endpoint child exited before publication".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if !matches!(
            RuntimeLease::acquire(),
            Err(warper_control::runtime::Error::AlreadyRunning)
        ) {
            return Err("live endpoint child did not retain flock".into());
        }
        let stream = UnixStream::connect("/run/warper/control.sock")?;
        unix::authenticate_service(&stream)?;
        drop(stream);
        child.kill()?;
        let status = child.wait()?;
        reaped = true;
        use std::os::unix::process::ExitStatusExt;
        if status.signal() != Some(9) {
            return Err("endpoint child was not reaped after SIGKILL".into());
        }
        let mut fresh = RuntimeLease::acquire()?;
        let intent = fs::read("/run/warper/control.intent")?;
        if endpoint::inspect(&fresh)? != endpoint::Inspection::Retirable
            || !Path::new("/run/warper/control.sock").exists()
            || fs::read("/run/warper/control.intent")? != intent
        {
            return Err("endpoint inspection changed stale publication".into());
        }
        if endpoint::recover(&mut fresh)? != Recovery::Retired
            || endpoint::recover(&mut fresh)? != Recovery::Absent
            || endpoint::inspect(&fresh)? != endpoint::Inspection::Absent
        {
            return Err("proven endpoint recovery did not retire idempotently".into());
        }
        ControlEndpoint::bind(fresh)?.close()?;
        println!(
            "PASS native control endpoint SIGKILL/reap, read-only inspection, fresh-lock recovery, repeated retirement and fresh publication"
        );
        Ok(())
    })();
    let mut cleanup: Vec<Failure> = Vec::new();
    if !reaped {
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = child.kill() {
                    cleanup.push(Box::new(error));
                }
                if let Err(error) = child.wait() {
                    cleanup.push(Box::new(error));
                }
            }
            Err(error) => cleanup.push(Box::new(error)),
        }
    }
    match fs::remove_file(READY) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => cleanup.push(Box::new(error)),
    }
    let primary = match outcome {
        Err(primary) => primary,
        Ok(()) if cleanup.is_empty() => return Ok(()),
        Ok(()) => cleanup.remove(0),
    };
    if cleanup.is_empty() {
        Err(primary)
    } else {
        Err(Box::new(RecoveryFailure { primary, cleanup }))
    }
}

#[derive(Debug)]
struct RecoveryFailure {
    primary: Failure,
    cleanup: Vec<Failure>,
}
impl std::fmt::Display for RecoveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; {} endpoint fixture cleanup failure(s)",
            self.primary,
            self.cleanup.len()
        )
    }
}
impl std::error::Error for RecoveryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.primary)
    }
}
