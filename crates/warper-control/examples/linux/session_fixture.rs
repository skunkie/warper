// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real protected endpoint, native root peer and enrolled owner/admin sessions.

use super::{Client, Failure};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::{net::UnixStream, sync::watch};
use warper_control::{
    OwnerPolicy, Role,
    admission::{Admission, Plan},
    runtime::{
        connection::ConnectionStore, endpoint::ControlEndpoint, enrollment::OwnerStore,
        managed::ManagedStore,
    },
    session::{Error, Session},
    unix,
    wire::{self, Frame, Kind},
};

fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(2)
}

pub(super) async fn client(mut stream: UnixStream, administrator: bool) -> Result<(), Failure> {
    unix::authenticate_service(&stream)?;
    let (_owner, mut cancel) = watch::channel(false);
    Frame::new(Kind::Hello, 1, vec![])?
        .write(&mut stream, deadline(), &mut cancel)
        .await?;
    let hello = Frame::read(&mut stream, deadline(), &mut cancel).await?;
    if hello.kind() != Kind::HelloReply || hello.request_id() != 1 || hello.body() == [0; 16] {
        return Err("native Hello reply differs".into());
    }
    Frame::new(Kind::Status, 2, vec![])?
        .write(&mut stream, deadline(), &mut cancel)
        .await?;
    let status = Frame::read(&mut stream, deadline(), &mut cancel).await?;
    if status.kind() != Kind::StatusReply
        || status.request_id() != 2
        || status.body()[9..17] != 1u64.to_be_bytes()
    {
        return Err("native status reply differs".into());
    }
    Frame::new(Kind::InspectRecovery, 3, vec![])?
        .write(&mut stream, deadline(), &mut cancel)
        .await?;
    let result = Frame::read(&mut stream, deadline(), &mut cancel).await;
    if administrator {
        let reply = result?;
        if reply.kind() != Kind::RecoveryReply || reply.request_id() != 3 || reply.body() != [0, 0]
        {
            return Err("native administrative recovery reply differs".into());
        }
    } else if !matches!(result, Err(wire::Error::Io(io::ErrorKind::UnexpectedEof))) {
        return Err("ordinary control owner received administrative metadata".into());
    }
    Ok(())
}

pub(super) fn exercise(endpoint: &ControlEndpoint) -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let store = OwnerStore::open(endpoint.runtime())?;
    if ManagedStore::open(endpoint.runtime())?
        .read(endpoint.runtime())?
        .is_some()
    {
        return Err("session fixture requires absent approved configuration".into());
    }
    let connection = ConnectionStore::open(endpoint.runtime())?;
    if connection.read(endpoint.runtime())?.is_some() {
        return Err("session fixture requires no network intent".into());
    }
    let instance = connection.instance_id();
    let admission = Admission::new(Plan::new(2, 1, 1024, 2048)?);
    for (uid, mode, role) in [
        (1000, "session-owner", Role::Owner),
        (0, "session-admin", Role::Administrator),
    ] {
        let mut child = Client::start(uid, mode)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let accepted = loop {
            let policy = store.read(endpoint.runtime())?.policy();
            match endpoint.accept(&policy)? {
                Some(accepted) => break accepted,
                None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                None => return Err("native session accept deadline expired".into()),
            }
        };
        if accepted.role != role {
            return Err("native session admission role differs".into());
        }
        accepted.stream.set_nonblocking(true)?;
        let mut session = runtime.block_on(async {
            Session::admitted(
                UnixStream::from_std(accepted.stream)?,
                instance,
                admission.try_client()?,
            )
            .map_err(|error| Box::new(error) as Failure)
        })?;
        let (_owner, mut cancel) = watch::channel(false);
        for kind in [Kind::Hello, Kind::Status, Kind::InspectRecovery] {
            let policy = store.read(endpoint.runtime())?.policy();
            runtime.block_on(session.receive(&policy, self::deadline(), &mut cancel))?;
            // Reload protected policy outside async I/O, after the entire frame.
            let current = store.read(endpoint.runtime())?;
            let policy: OwnerPolicy = current.policy();
            let authorized = session.authorize(&policy);
            if kind == Kind::InspectRecovery && uid == 1000 {
                if !matches!(
                    authorized,
                    Err(Error::Authentication(
                        warper_control::Error::PermissionDenied
                    ))
                ) || !session.is_closed()
                {
                    return Err("native owner session bypassed administrative dispatch".into());
                }
                break;
            }
            let authorized = authorized?;
            if authorized.frame().kind() != kind || authorized.role() != role {
                return Err("native request dispatch differs".into());
            }
            let (reply_kind, body) = match kind {
                Kind::Hello => (Kind::HelloReply, instance.to_vec()),
                Kind::Status => {
                    // The controlled fixture has no networking/configuration;
                    // enrollment is the only nonzero observed state revision.
                    let mut body = vec![0; 26];
                    body[9..17].copy_from_slice(&current.revision().to_be_bytes());
                    (Kind::StatusReply, body)
                }
                Kind::InspectRecovery => (Kind::RecoveryReply, vec![0; 2]),
                _ => return Err("unexpected native fixture request".into()),
            };
            let reply = authorized.reply(reply_kind, body)?;
            runtime.block_on(session.respond(reply, self::deadline(), &mut cancel))?;
        }
        drop(session);
        child.join()?;
    }
    println!(
        "PASS native root/owner authenticated Hello, correlated status, fresh protected policy and administrative session dispatch"
    );
    Ok(())
}
