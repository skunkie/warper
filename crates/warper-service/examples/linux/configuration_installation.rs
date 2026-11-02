// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native configuration validation, administrative installation and lease fence.

use super::fixture::{Failure, preserve};
use std::{
    io::{self, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use warper_config::{managed::Snapshot, schema::Platform};
use warper_control::runtime::managed::ManagedStore;
use warper_core::configuration::paths::{Account, Paths};
use warper_service::linux::{
    configuration::{Configurations, Error, Status},
    context::Context,
};

const SAMPLE: &str = "tunnel: {ip: 198.18.0.1}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]";
const SOCKET: &str = "/run/warper/configuration-peer.sock";

fn encoded(sample: &str) -> Result<warper_config::schema::Secret<Vec<u8>>, Failure> {
    let paths = Paths::new(
        &Account {
            uid: 1000,
            name: "sample".into(),
            home: "/sample".into(),
        },
        Path::new("/sample"),
        Some("/sample/source.yaml"),
    )?;
    Ok(Snapshot::import(sample.as_bytes(), &paths, Platform::Linux)?.encode()?)
}

pub(super) fn peer() -> Result<(), Failure> {
    if nix::unistd::geteuid().as_raw() != 1000 {
        return Err("configuration peer requires controlled ordinary UID".into());
    }
    let mut peer = UnixStream::connect(SOCKET)?;
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut response = [0];
    peer.read_exact(&mut response)?;
    if response != [1] {
        return Err("configuration peer completion differs".into());
    }
    Ok(())
}

fn unauthorized(manager: &mut Configurations, bytes: &[u8]) -> Result<(), Failure> {
    let listener = UnixListener::bind(SOCKET)?;
    listener.set_nonblocking(true)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    let mut child = Command::new("/usr/bin/setpriv")
        .args(["--reuid", "1000", "--regid", "1000", "--clear-groups"])
        .arg(std::env::current_exe()?)
        .arg("--configuration-peer")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let outcome = (|| -> Result<(), Failure> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut peer = loop {
            match listener.accept() {
                Ok((peer, _)) => break peer,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(error.into()),
            }
        };
        for sample in [bytes, b"malformed".as_slice()] {
            if manager.install(&peer, 0, sample)
                != Err(Error::Authentication(
                    warper_control::Error::PermissionDenied,
                ))
            {
                return Err(
                    "ordinary configuration peer could pass administrative installation".into(),
                );
            }
        }
        if manager.status()?
            != (Status {
                generation: 0,
                present: false,
            })
        {
            return Err("unauthorized installation changed configuration".into());
        }
        peer.set_write_timeout(Some(Duration::from_secs(1)))?;
        peer.write_all(&[1])?;
        Ok(())
    })();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut cleanup = Vec::new();
    let mut reaped = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                reaped = true;
                if outcome.is_ok() && !status.success() {
                    cleanup.push("configuration peer failed".into());
                }
                break;
            }
            Ok(None) => {}
            Err(error) => {
                cleanup.push(Box::new(error) as Failure);
                break;
            }
        }
        if outcome.is_err() || Instant::now() >= deadline {
            if outcome.is_ok() {
                cleanup.push("configuration peer exceeded deadline".into());
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !reaped {
        if let Err(error) = child.kill() {
            cleanup.push(Box::new(error) as Failure);
        }
        if let Err(error) = child.wait() {
            cleanup.push(Box::new(error) as Failure);
        }
    }
    preserve(outcome, cleanup)
}

pub(super) fn exercise(
    context: Arc<Context>,
    runtime: &warper_control::runtime::RuntimeLease,
) -> Result<(), Failure> {
    let mut manager = Configurations::open(context.clone())?;
    if manager.status()?
        != (Status {
            generation: 0,
            present: false,
        })
        || manager.lease()?.is_some()
    {
        return Err("missing managed configuration became available".into());
    }
    let bytes = encoded(SAMPLE)?;
    unauthorized(&mut manager, bytes.expose())?;
    let (admin, _client) = UnixStream::pair()?;
    if !matches!(
        manager.install(&admin, 0, b"malformed"),
        Err(Error::Managed(_))
    ) || manager.status()?.generation != 0
    {
        return Err("malformed managed data changed protected state".into());
    }
    let unsupported = encoded(&SAMPLE.replace("127.0.0.1:1080", "proxy.example.test:1080"))?;
    if !matches!(
        manager.install(&admin, 0, unsupported.expose()),
        Err(Error::Preflight(_))
    ) || manager.status()?.generation != 0
    {
        return Err("unsupported managed data reached storage".into());
    }
    if manager.install(&admin, 0, bytes.expose())? != 1 {
        return Err("initial installed generation differs".into());
    }
    let lease = manager.lease()?.ok_or("approved configuration missing")?;
    if lease.generation() != 1 || lease.config().protocols.len() != 1 {
        return Err("approved lease data differs".into());
    }
    if manager.install(&admin, 1, bytes.expose()) != Err(Error::Busy) {
        return Err("active lease did not block installation".into());
    }
    let retained = lease.clone();
    drop(lease);
    if manager.install(&admin, 1, bytes.expose()) != Err(Error::Busy) {
        return Err("retained worker lease did not block installation".into());
    }
    drop(manager);
    if !matches!(Configurations::open(context.clone()), Err(Error::Busy)) {
        return Err("reopening bypassed a retained approved-configuration lease".into());
    }
    drop(retained);
    let mut manager = Configurations::open(context.clone())?;
    if manager.install(&admin, 0, bytes.expose()) != Err(Error::Conflict)
        || manager.status()?.generation != 1
    {
        return Err("stale installation changed generation".into());
    }
    if manager.install(&admin, 1, bytes.expose())? != 2 {
        return Err("released lease did not permit replacement".into());
    }
    drop(manager);
    let manager = Configurations::open(context.clone())?;
    if manager.status()?
        != (Status {
            generation: 2,
            present: true,
        })
    {
        return Err("approved configuration did not survive reopen".into());
    }
    let mut foreign = ManagedStore::open(runtime)?;
    foreign.replace(runtime, 2, bytes.expose())?;
    if !matches!(manager.status(), Err(Error::Storage(_)))
        || !matches!(manager.lease(), Err(Error::Storage(_)))
    {
        return Err("externally changed managed state was silently adopted".into());
    }
    drop(manager);
    let manager = Configurations::open(context)?;
    if manager.status()?.generation != 3 {
        return Err("explicit reopen lost validated managed state".into());
    }
    println!(
        "PASS administrative configuration installation, validation-before-mutation, retained lease Busy fence, generation conflicts and changed-state rejection"
    );
    Ok(())
}
