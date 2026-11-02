// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real local Unix peers exercise handshake, authorization and I/O abandonment.

#![cfg(target_os = "linux")]

use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::watch,
    time::Instant,
};
use warper_control::{
    OwnerPolicy, Role,
    session::{AuthorizedRequest, Error, Session},
    wire::{self, Frame, Kind},
};

fn pair() -> (Session, UnixStream, OwnerPolicy) {
    let (server, client) = UnixStream::pair().unwrap();
    (
        Session::new(server, [7; 16], 1024).unwrap(),
        client,
        OwnerPolicy::new(Some(nix::unistd::geteuid().as_raw())).unwrap(),
    )
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
async fn submit(
    session: &mut Session,
    client: &mut UnixStream,
    policy: &OwnerPolicy,
    frame: Frame,
) -> Result<AuthorizedRequest, Error> {
    let (_owner, mut cancel) = watch::channel(false);
    frame.write(client, deadline(), &mut cancel).await.unwrap();
    session.receive(policy, deadline(), &mut cancel).await?;
    session.authorize(policy)
}
async fn respond(session: &mut Session, client: &mut UnixStream, frame: Frame) -> Frame {
    let (_owner, mut cancel) = watch::channel(false);
    session
        .respond(frame, deadline(), &mut cancel)
        .await
        .unwrap();
    Frame::read(client, deadline(), &mut cancel).await.unwrap()
}
async fn hello(session: &mut Session, client: &mut UnixStream, policy: &OwnerPolicy, id: u64) {
    let request = submit(
        session,
        client,
        policy,
        Frame::new(Kind::Hello, id, vec![]).unwrap(),
    )
    .await
    .unwrap();
    let reply = request
        .reply(Kind::HelloReply, session.instance_id().to_vec())
        .unwrap();
    let reply = respond(session, client, reply).await;
    assert_eq!(reply.request_id(), id);
    assert_eq!(reply.body(), &[7; 16]);
}
fn command(kind: Kind, id: u64) -> Frame {
    let operation = wire::operation_id(0, [1; 8]).unwrap();
    let body = match kind {
        Kind::Connect | Kind::Disconnect => {
            let mut body = operation.to_vec();
            body.extend_from_slice(&[0; 16]);
            body.extend_from_slice(&[7; 16]);
            body
        }
        Kind::Enroll => vec![0; 16],
        Kind::InstallConfig => vec![0; 9],
        Kind::OperationStatus => operation.to_vec(),
        _ => vec![],
    };
    Frame::new(kind, id, body).unwrap()
}

#[tokio::test]
async fn hello_and_status_replies_correlate_to_authorized_requests() {
    let (mut session, mut client, policy) = pair();
    hello(&mut session, &mut client, &policy, 1).await;
    let request = submit(&mut session, &mut client, &policy, command(Kind::Status, 2))
        .await
        .unwrap();
    assert_eq!(
        request.role(),
        if nix::unistd::geteuid().is_root() {
            Role::Administrator
        } else {
            Role::Owner
        }
    );
    assert_eq!(format!("{request:?}"), "AuthorizedRequest(<redacted>)");
    assert_eq!(format!("{session:?}"), "ControlSession(<redacted>)");
    assert!(matches!(
        request.reply(
            Kind::Accepted,
            wire::operation_id(0, [1; 8]).unwrap().to_vec()
        ),
        Err(Error::UnexpectedReply)
    ));
    let reply = request.reply(Kind::StatusReply, vec![0; 26]).unwrap();
    let reply = respond(&mut session, &mut client, reply).await;
    assert_eq!(reply.request_id(), 2);
    assert_eq!(reply.kind(), Kind::StatusReply);
    assert!(!session.is_closed());
    let request = submit(&mut session, &mut client, &policy, command(Kind::Status, 3))
        .await
        .unwrap();
    let reply = request
        .reply(
            Kind::ErrorReply,
            (wire::Code::Busy as u16).to_be_bytes().to_vec(),
        )
        .unwrap();
    assert_eq!(
        respond(&mut session, &mut client, reply).await.kind(),
        Kind::ErrorReply
    );
    assert!(!session.is_closed());
}

#[tokio::test]
async fn current_policy_is_checked_after_frame_read_before_dispatch() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let (mut session, mut client, policy) = pair();
    hello(&mut session, &mut client, &policy, 1).await;
    let (_owner, mut cancel) = watch::channel(false);
    command(Kind::Status, 2)
        .write(&mut client, deadline(), &mut cancel)
        .await
        .unwrap();
    session
        .receive(&policy, deadline(), &mut cancel)
        .await
        .unwrap();
    let revoked = OwnerPolicy::new(None).unwrap();
    assert!(matches!(
        session.authorize(&revoked),
        Err(Error::Authentication(
            warper_control::Error::PermissionDenied
        ))
    ));
    assert!(session.is_closed());
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn unauthorized_admission_does_not_wait_for_a_header() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let (mut session, mut client, _policy) = pair();
    let denied = OwnerPolicy::new(None).unwrap();
    let (_owner, mut cancel) = watch::channel(false);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        session.receive(&denied, deadline(), &mut cancel),
    )
    .await
    .unwrap();
    assert_eq!(
        result,
        Err(Error::Authentication(
            warper_control::Error::PermissionDenied
        ))
    );
    assert!(session.is_closed());
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn actual_owner_can_observe_and_operate_but_cannot_administer() {
    for kind in [
        Kind::Status,
        Kind::OperationStatus,
        Kind::Connect,
        Kind::Disconnect,
        Kind::Enroll,
        Kind::InstallConfig,
        Kind::InspectRecovery,
    ] {
        let (mut session, mut client, policy) = pair();
        hello(&mut session, &mut client, &policy, 1).await;
        let result = submit(&mut session, &mut client, &policy, command(kind, 2)).await;
        if !nix::unistd::geteuid().is_root()
            && matches!(
                kind,
                Kind::Enroll | Kind::InstallConfig | Kind::InspectRecovery
            )
        {
            assert!(
                matches!(
                    result,
                    Err(Error::Authentication(
                        warper_control::Error::PermissionDenied
                    ))
                ),
                "{kind:?}"
            );
            assert!(session.is_closed());
        } else {
            assert!(result.is_ok(), "{kind:?}");
        }
    }
}

#[tokio::test]
async fn missing_repeated_hello_reply_frames_and_reused_ids_close_the_session() {
    struct Case {
        id: &'static str,
        hello_id: Option<u64>,
        frame: Frame,
    }
    for case in [
        Case {
            id: "missing_hello",
            hello_id: None,
            frame: command(Kind::Status, 1),
        },
        Case {
            id: "repeated_hello",
            hello_id: Some(1),
            frame: command(Kind::Hello, 2),
        },
        Case {
            id: "reused_id",
            hello_id: Some(10),
            frame: command(Kind::Status, 10),
        },
        Case {
            id: "decreased_id",
            hello_id: Some(10),
            frame: command(Kind::Status, 9),
        },
        Case {
            id: "wrapped_id",
            hello_id: Some(u64::MAX),
            frame: command(Kind::Status, 1),
        },
        Case {
            id: "client_reply",
            hello_id: Some(1),
            frame: Frame::new(Kind::StatusReply, 2, vec![0; 26]).unwrap(),
        },
    ] {
        let (mut session, mut client, policy) = pair();
        if let Some(id) = case.hello_id {
            hello(&mut session, &mut client, &policy, id).await;
        }
        assert!(
            matches!(
                submit(&mut session, &mut client, &policy, case.frame).await,
                Err(Error::UnexpectedRequest)
            ),
            "{}",
            case.id
        );
        assert!(session.is_closed(), "{}", case.id);
    }
}

#[tokio::test]
async fn wrong_reply_kind_instance_or_id_cannot_complete_the_handshake() {
    for reply in [
        Frame::new(Kind::HelloReply, 2, vec![7; 16]).unwrap(),
        Frame::new(Kind::HelloReply, 1, vec![8; 16]).unwrap(),
        Frame::new(Kind::StatusReply, 1, vec![0; 26]).unwrap(),
    ] {
        let (mut session, mut client, policy) = pair();
        submit(&mut session, &mut client, &policy, command(Kind::Hello, 1))
            .await
            .unwrap();
        let (_owner, mut cancel) = watch::channel(false);
        assert_eq!(
            session.respond(reply, deadline(), &mut cancel).await,
            Err(Error::UnexpectedReply)
        );
        assert!(session.is_closed());
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn one_pending_frame_and_one_response_are_allowed_at_a_time() {
    for authorize in [false, true] {
        let (mut session, mut client, policy) = pair();
        let (_owner, mut cancel) = watch::channel(false);
        command(Kind::Hello, 1)
            .write(&mut client, deadline(), &mut cancel)
            .await
            .unwrap();
        session
            .receive(&policy, deadline(), &mut cancel)
            .await
            .unwrap();
        if authorize {
            session.authorize(&policy).unwrap();
        }
        assert_eq!(
            session.receive(&policy, deadline(), &mut cancel).await,
            Err(Error::Sequence)
        );
        assert!(session.is_closed());
    }
    let (mut session, _client, policy) = pair();
    assert!(matches!(session.authorize(&policy), Err(Error::Sequence)));
    assert!(session.is_closed());
}

#[tokio::test(start_paused = true)]
async fn abandoned_partial_read_cannot_resume_or_replay() {
    let (mut session, mut client, policy) = pair();
    client.write_all(b"WRPC\0\x02\0\x01").await.unwrap();
    let (_owner, mut cancel) = watch::channel(false);
    let mut reading = Box::pin(session.receive(&policy, deadline(), &mut cancel));
    assert!(
        tokio::time::timeout(Duration::from_millis(1), &mut reading)
            .await
            .is_err()
    );
    drop(reading);
    assert!(session.is_closed());
    assert_eq!(
        session.receive(&policy, deadline(), &mut cancel).await,
        Err(Error::Closed)
    );
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn cancellation_expiry_and_closed_owner_close_read_and_write_ownership() {
    for mode in 0..3 {
        let (mut session, _client, policy) = pair();
        let (owner, mut cancel) = watch::channel(mode == 0);
        let deadline = if mode == 1 {
            Instant::now()
        } else {
            deadline()
        };
        if mode == 2 {
            drop(owner);
        }
        let expected = if mode == 1 {
            wire::Error::Deadline
        } else {
            wire::Error::Cancelled
        };
        assert_eq!(
            session.receive(&policy, deadline, &mut cancel).await,
            Err(Error::Frame(expected))
        );
        assert!(session.is_closed());
    }
    let (mut session, mut client, policy) = pair();
    let request = submit(&mut session, &mut client, &policy, command(Kind::Hello, 1))
        .await
        .unwrap();
    let reply = request.reply(Kind::HelloReply, vec![7; 16]).unwrap();
    let (_owner, mut cancel) = watch::channel(false);
    assert_eq!(
        session.respond(reply, Instant::now(), &mut cancel).await,
        Err(Error::Frame(wire::Error::Deadline))
    );
    assert!(session.is_closed());
}

#[tokio::test]
async fn failed_hello_never_opens_the_session() {
    let (mut session, mut client, policy) = pair();
    let request = submit(&mut session, &mut client, &policy, command(Kind::Hello, 1))
        .await
        .unwrap();
    let reply = request
        .reply(
            Kind::ErrorReply,
            (wire::Code::Failed as u16).to_be_bytes().to_vec(),
        )
        .unwrap();
    assert_eq!(
        respond(&mut session, &mut client, reply).await.kind(),
        Kind::ErrorReply
    );
    assert!(session.is_closed());
}

#[tokio::test]
async fn invalid_limits_instance_and_oversized_input_fail_before_dispatch() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    assert_eq!(
        Session::new(stream, [0; 16], 1024).unwrap_err(),
        Error::InvalidInstance
    );
    for limit in [0, 67, usize::MAX] {
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert_eq!(
            Session::new(stream, [7; 16], limit).unwrap_err(),
            Error::InvalidLimits
        );
    }
    let (server, mut client) = UnixStream::pair().unwrap();
    let policy = OwnerPolicy::new(Some(nix::unistd::geteuid().as_raw())).unwrap();
    let mut session = Session::new(server, [7; 16], 68).unwrap();
    hello(&mut session, &mut client, &policy, 1).await;
    let (_owner, mut cancel) = watch::channel(false);
    Frame::new(Kind::InstallConfig, 2, vec![0; 128])
        .unwrap()
        .write(&mut client, deadline(), &mut cancel)
        .await
        .unwrap();
    assert_eq!(
        session.receive(&policy, deadline(), &mut cancel).await,
        Err(Error::Frame(wire::Error::InvalidLength))
    );
    assert!(session.is_closed());
}

#[tokio::test]
async fn abandoning_a_blocked_reply_closes_transport_without_replay() {
    use nix::sys::socket::{setsockopt, sockopt};
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };
    let (server, mut client) = UnixStream::pair().unwrap();
    setsockopt(&server, sockopt::SndBuf, &4096).unwrap();
    server.writable().await.unwrap();
    let mut filled = 0;
    let mut blocked = false;
    for _ in 0..128 {
        match server.try_write(&[b'x'; 8192]) {
            Ok(length) => filled += length,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                blocked = true;
                break;
            }
            Err(error) => panic!("fill controlled output: {error}"),
        }
    }
    assert!(
        blocked,
        "controlled socket output must reach bounded backpressure"
    );
    assert!(filled > 0, "backpressure must follow actual kernel writes");
    let mut session = Session::new(server, [7; 16], 1024).unwrap();
    let policy = OwnerPolicy::new(Some(nix::unistd::geteuid().as_raw())).unwrap();
    let request = submit(&mut session, &mut client, &policy, command(Kind::Hello, 1))
        .await
        .unwrap();
    let reply = request.reply(Kind::HelloReply, vec![7; 16]).unwrap();
    let (_owner, mut cancel) = watch::channel(false);
    let mut writing = Box::pin(session.respond(reply, deadline(), &mut cancel));
    poll_fn(|context| {
        assert!(writing.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(writing);
    assert!(session.is_closed());
    let mut received = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        (&mut client)
            .take(filled as u64 + 37)
            .read_to_end(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        received.len(),
        filled,
        "abandoned response must not emit a prefix or restart later"
    );
}

#[tokio::test]
async fn canceling_an_incomplete_header_closes_the_pending_read() {
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };
    let (mut session, mut client, policy) = pair();
    client.write_all(b"WRPC\0\x02\0\x01").await.unwrap();
    let (owner, mut cancel) = watch::channel(false);
    let mut reading = Box::pin(session.receive(&policy, deadline(), &mut cancel));
    poll_fn(|context| {
        assert!(reading.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    owner.send(true).unwrap();
    assert_eq!(reading.await, Err(Error::Frame(wire::Error::Cancelled)));
    assert!(session.is_closed());
    match client.read(&mut [0; 1]).await {
        Ok(length) => assert_eq!(length, 0),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
}

#[tokio::test]
async fn responses_require_dispatch_and_closed_sessions_cannot_be_reused() {
    let (mut session, _client, policy) = pair();
    let (_owner, mut cancel) = watch::channel(false);
    let frame = Frame::new(Kind::HelloReply, 1, vec![7; 16]).unwrap();
    assert_eq!(
        session.respond(frame, deadline(), &mut cancel).await,
        Err(Error::Sequence)
    );
    assert!(matches!(session.authorize(&policy), Err(Error::Closed)));
    let frame = Frame::new(Kind::HelloReply, 1, vec![7; 16]).unwrap();
    assert_eq!(
        session.respond(frame, deadline(), &mut cancel).await,
        Err(Error::Closed)
    );
}

#[tokio::test]
#[ignore = "controlled Unix control-session latency/CPU workload"]
async fn session_workload() {
    let (mut session, mut client, policy) = pair();
    hello(&mut session, &mut client, &policy, 1).await;
    let before_cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let started = std::time::Instant::now();
    let mut samples = Vec::with_capacity(100);
    for id in 2..=101 {
        let before = std::time::Instant::now();
        let request = submit(
            &mut session,
            &mut client,
            &policy,
            command(Kind::Status, id),
        )
        .await
        .unwrap();
        let reply = request.reply(Kind::StatusReply, vec![0; 26]).unwrap();
        let reply = respond(&mut session, &mut client, reply).await;
        assert_eq!(reply.request_id(), id);
        samples.push(before.elapsed().as_nanos());
    }
    let elapsed = started.elapsed().as_nanos();
    let after_cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let cpu = (i128::from(after_cpu.tv_sec) - i128::from(before_cpu.tv_sec)) * 1_000_000_000
        + i128::from(after_cpu.tv_nsec)
        - i128::from(before_cpu.tv_nsec);
    samples.sort_unstable();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let memory = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .unwrap();
    println!(
        "control_session iterations=100 concurrency=1 encoded_bytes=6600 elapsed_ns={elapsed} cpu_ns={cpu} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 kernel_drops=unmeasured {memory}",
        samples[49], samples[94], samples[98]
    );
    drop(session);
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}
