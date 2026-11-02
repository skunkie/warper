// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled native owner-process observation in the disposable fixture only.

use super::{Failure, isolated, join_native, preserve};
use std::{
    io::{self, Write},
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncReadExt;
use warper_control::runtime::{RuntimeLease, connection::ConnectionStore};
use warper_service::{
    linux::context::{Context, ProcessState, RecordedOwner},
    native::Workers,
};

fn capture() -> Result<Context, Failure> {
    let lease = Arc::new(RuntimeLease::acquire()?);
    let connection = ConnectionStore::open(&lease)?;
    Ok(Context::capture(lease, &connection)?)
}

pub(super) async fn peer(mount: &str, net: &str) -> Result<(), Failure> {
    isolated(mount, net)?;
    let jobs = Workers::new(1)?;
    let (owner, _) = tokio::sync::watch::channel(false);
    let mut preparing = jobs.try_reserve()?.start(|| -> Result<Context, Failure> {
        let context = capture()?;
        io::stdout().write_all(&context.recorded_owner().encode())?;
        io::stdout().flush()?;
        Ok(context)
    });
    let context = join_native(&mut preparing, &owner).await??;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut verifying = jobs.try_reserve()?.start(move || context.revalidate());
    join_native(&mut verifying, &owner).await??;
    Ok(())
}

pub(super) async fn exercise(mount: &str, net: &str) -> Result<(), Failure> {
    let jobs = Workers::new(1)?;
    let (owner, _) = tokio::sync::watch::channel(false);
    let mount = mount.to_owned();
    let net = net.to_owned();
    let mut spawning = jobs.try_reserve()?.start(move || -> Result<_, Failure> {
        Ok(Command::new(std::env::current_exe()?)
            .args(["--context-peer", &mount, &net])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?)
    });
    let mut child = join_native(&mut spawning, &owner).await??;
    let observed = async {
        let pipe = child
            .stdout
            .take()
            .ok_or("process owner readiness pipe missing")?;
        let mut input = tokio::net::unix::pipe::Receiver::from_owned_fd(pipe.into())?;
        let mut bytes = [0; 88];
        tokio::time::timeout(Duration::from_secs(2), input.read_exact(&mut bytes)).await??;
        let recorded = RecordedOwner::decode(&bytes)?;
        let mut verifying = jobs.try_reserve()?.start(|| -> Result<(), Failure> {
            if !matches!(
                RuntimeLease::acquire(),
                Err(warper_control::runtime::Error::AlreadyRunning)
            ) {
                return Err("live process peer did not retain runtime ownership".into());
            }
            Ok(())
        });
        join_native(&mut verifying, &owner).await??;
        Ok::<_, Failure>(recorded)
    }
    .await;
    // Kill/reap only the owned child, even after a malformed/expired readiness
    // response. Blocking process cleanup remains in a retained native job.
    let mut reaping = jobs.try_reserve()?.start(move || {
        let kill = child.kill().map_err(|error| Box::new(error) as Failure);
        let waited = child.wait().map_err(|error| Box::new(error) as Failure);
        let primary = waited.and_then(|status| {
            if status.signal() == Some(9) {
                Ok(())
            } else {
                Err("process peer did not terminate under controlled SIGKILL".into())
            }
        });
        preserve(primary, kill.err().into_iter().collect())
    });
    let reaped = join_native(&mut reaping, &owner).await?;
    let mut recorded = None;
    preserve(
        observed.map(|value| recorded = Some(value)),
        reaped.err().into_iter().collect(),
    )?;
    let recorded = recorded.ok_or("process peer owner observation missing")?;
    let mut inspecting = jobs.try_reserve()?.start(move || -> Result<(), Failure> {
        let context = capture()?;
        if context.owner_process(&recorded)? != ProcessState::Exited {
            return Err("reaped native owner was not observed exited".into());
        }
        Ok(())
    });
    join_native(&mut inspecting, &owner).await??;
    println!(
        "PASS native owner PIDFD observation after controlled SIGKILL/reap and runtime reacquisition"
    );
    Ok(())
}
