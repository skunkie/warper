// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Admission across real local streams and retained dispatch ownership.

#![cfg(target_os = "linux")]

use std::{future::poll_fn, task::Poll, time::Duration};
use tokio::{net::UnixStream, sync::watch, time::Instant};
use warper_control::{
    OwnerPolicy,
    admission::{Admission, Error, Plan},
    session::{Error as SessionError, Session},
    wire::{Frame, Kind},
};

#[test]
fn plans_reject_unsupported_and_insufficient_capacity() {
    let defaults = Plan::new(16, 64, 1_048_576, 8_388_608).unwrap();
    assert_eq!(defaults.clients(), 16);
    assert_eq!(defaults.requests(), 7);
    assert_eq!(defaults.max_encoded(), 1_048_576);
    assert_eq!(defaults.reserved_bytes(), 7 * 1_048_576 + 16 * 46);
    for (clients, requests, bytes, budget) in [
        (0, 1, 68, 1024),
        (65, 1, 68, 8192),
        (1, 0, 68, 1024),
        (1, 65, 68, 8192),
        (1, 1, 67, 1024),
        (1, 1, 20 + warper_control::wire::MAX_BODY + 1, usize::MAX),
        (1, 1, 68, 45),
        (1, 1, 68, 113),
        (usize::MAX, 1, 68, usize::MAX),
    ] {
        assert_eq!(
            Plan::new(clients, requests, bytes, budget),
            Err(Error::InvalidLimits)
        );
    }
    let exact = Plan::new(1, 64, 68, 114).unwrap();
    assert_eq!(exact.requests(), 1);
    assert_eq!(exact.reserved_bytes(), 114);
    let maximum = Plan::new(64, 64, 20 + warper_control::wire::MAX_BODY, usize::MAX).unwrap();
    assert_eq!(maximum.requests(), 64);
}

#[test]
fn client_capacity_is_retained_until_drop_and_closed_admission_stays_closed() {
    let admission = Admission::new(Plan::new(1, 1, 68, 114).unwrap());
    let client = admission.try_client().unwrap();
    assert!(matches!(admission.try_client(), Err(Error::Full)));
    drop(client);
    let client = admission.try_client().unwrap();
    admission.close();
    drop(client);
    assert!(matches!(admission.try_client(), Err(Error::Closed)));
}

fn pair(admission: &Admission) -> (Session, UnixStream, OwnerPolicy) {
    let (server, client) = UnixStream::pair().unwrap();
    (
        Session::admitted(server, [7; 16], admission.try_client().unwrap()).unwrap(),
        client,
        OwnerPolicy::new(Some(nix::unistd::geteuid().as_raw())).unwrap(),
    )
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

async fn pending<F: std::future::Future>(future: std::pin::Pin<&mut F>) {
    let mut future = future;
    poll_fn(|context| {
        assert!(future.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn retained_dispatch_keeps_request_capacity_after_session_drop() {
    let admission = Admission::new(Plan::new(1, 1, 68, 114).unwrap());
    let (mut first, mut peer, policy) = pair(&admission);
    let (_owner, mut cancel) = watch::channel(false);
    Frame::new(Kind::Hello, 1, vec![])
        .unwrap()
        .write(&mut peer, deadline(), &mut cancel)
        .await
        .unwrap();
    first
        .receive(&policy, deadline(), &mut cancel)
        .await
        .unwrap();
    let retained = first.authorize(&policy).unwrap();
    drop(first);
    let (mut second, mut peer, policy) = pair(&admission);
    Frame::new(Kind::Hello, 1, vec![])
        .unwrap()
        .write(&mut peer, deadline(), &mut cancel)
        .await
        .unwrap();
    {
        let receive = second.receive(&policy, deadline(), &mut cancel);
        tokio::pin!(receive);
        pending(receive.as_mut()).await;
        drop(retained);
        receive.await.unwrap();
    }
    drop(second.authorize(&policy).unwrap());
}

#[tokio::test]
async fn close_wakes_capacity_waiter_without_releasing_retained_work() {
    let admission = Admission::new(Plan::new(2, 1, 68, 160).unwrap());
    let (mut first, mut peer, policy) = pair(&admission);
    let (_owner, mut cancel) = watch::channel(false);
    Frame::new(Kind::Hello, 1, vec![])
        .unwrap()
        .write(&mut peer, deadline(), &mut cancel)
        .await
        .unwrap();
    first
        .receive(&policy, deadline(), &mut cancel)
        .await
        .unwrap();
    let retained = first.authorize(&policy).unwrap();
    let (mut second, _peer, policy) = pair(&admission);
    let receive = second.receive(&policy, deadline(), &mut cancel);
    tokio::pin!(receive);
    pending(receive.as_mut()).await;
    admission.close();
    assert_eq!(receive.await, Err(SessionError::Admission(Error::Closed)));
    assert_eq!(retained.frame().kind(), Kind::Hello);
}

#[tokio::test]
async fn abandoned_wait_and_malformed_frame_release_request_capacity() {
    let admission = Admission::new(Plan::new(2, 1, 68, 160).unwrap());
    let (mut first, _peer, policy) = pair(&admission);
    let (_owner, mut cancel) = watch::channel(false);
    {
        let receive = first.receive(&policy, deadline(), &mut cancel);
        tokio::pin!(receive);
        pending(receive.as_mut()).await;
    }
    assert!(first.is_closed());
    let (mut second, mut peer, policy) = pair(&admission);
    use tokio::io::AsyncWriteExt;
    peer.write_all(&[0; 20]).await.unwrap();
    assert_eq!(
        second.receive(&policy, deadline(), &mut cancel).await,
        Err(SessionError::Frame(
            warper_control::wire::Error::InvalidMagic
        ))
    );
    drop(first);
    drop(second);
    let (mut third, mut peer, policy) = pair(&admission);
    Frame::new(Kind::Hello, 1, vec![])
        .unwrap()
        .write(&mut peer, deadline(), &mut cancel)
        .await
        .unwrap();
    third
        .receive(&policy, deadline(), &mut cancel)
        .await
        .unwrap();
    drop(third.authorize(&policy).unwrap());
}
