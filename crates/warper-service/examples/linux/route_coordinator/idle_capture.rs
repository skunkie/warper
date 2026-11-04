// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Prove that the kernel notification wakes a parked, retained driver.

use super::{Completion, Controller, Error, Failure, Manager, Request, ip, ipv4, request, reserve};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::{
    sync::{Notify, watch},
    time::timeout,
};
use warper_service::linux::{
    change_monitor::Invalidation,
    dns_routes::queue::{Driver, Error as QueueError},
    tun,
};

struct Notification {
    observed: AtomicBool,
    ready: Notify,
}
impl Wake for Notification {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.observed.store(true, Ordering::Release);
        self.ready.notify_one();
    }
}

pub(super) async fn exercise(
    controller: &Controller,
    manager: &mut Manager,
    owner: &watch::Sender<bool>,
) -> Result<(), Failure> {
    let response = reserve(controller, &[ipv4(169)])?;
    manager.begin_commit(response, request(owner))?;
    // The guard keeps this capture live without new requests or expiry work.
    let response = match manager.wait(request(owner)).await? {
        Completion::Committed(response) => response,
        Completion::Retired => return Err("idle capture setup returned retirement".into()),
    };
    let (mailbox, mut driver) = Driver::new(manager, 1)?;
    let notification = Arc::new(Notification {
        observed: AtomicBool::new(false),
        ready: Notify::new(),
    });
    let waker = Waker::from(notification.clone());
    {
        let observation: Request = request(owner);
        let mut parked = std::pin::pin!(driver.run(observation));
        if !matches!(
            parked.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Pending
        ) {
            return Err("idle capture observation did not park".into());
        }
        // Dropping observation must preserve the subscription and ownership.
    }
    let mut parked = Box::pin(driver.run(request(owner)));
    if !matches!(
        parked.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Pending
    ) {
        return Err("resumed idle capture observation did not park".into());
    }
    notification.observed.store(false, Ordering::Release);
    // This address exists only in the disposable fixture's private namespace.
    // It does not change an owned route or the capture device's identity.
    ip(&["address", "add", "198.51.100.254/32", "dev", "lo"])?;
    let outcome = async {
        // Await a different future: never poll `parked` to make it discover
        // the event. The original observer deadline is ten seconds away.
        timeout(Duration::from_secs(1), async {
            while !notification.observed.load(Ordering::Acquire) {
                notification.ready.notified().await;
            }
        })
        .await?;
        let expected = Error::Native(tun::Error::CaptureChanged(Invalidation::NetworkChanged));
        if parked.as_mut().await != Err(QueueError::Operation(expected)) {
            return Err("idle capture change lost its typed failure".into());
        }
        Ok::<_, Failure>(())
    }
    .await;
    drop(parked);
    let removed = ip(&["address", "del", "198.51.100.254/32", "dev", "lo"]);
    let mut cleanup = Vec::new();
    if let Err(error) = removed {
        cleanup.push(error);
    }
    if let Some(failure) = driver.failure() {
        for error in failure.cleanup.into_iter().flatten() {
            cleanup.push(Box::new(error) as Failure);
        }
    }
    if let Some(error) = driver.join_error() {
        cleanup.push(Box::new(error) as Failure);
    }
    super::preserve(outcome, cleanup)?;
    if driver.failure().is_none() || !controller.is_closed()? {
        return Err("idle capture failure did not close routing admission cleanly".into());
    }
    if !matches!(
        mailbox.submit(response, request(owner)),
        Err(QueueError::Closed)
    ) {
        return Err("idle capture failure admitted a later command".into());
    }
    drop(driver);
    if manager.has_pending() {
        return Err("idle capture failure left accepted native work unjoined".into());
    }
    println!(
        "PASS parked DNS driver wakes on native capture change after dropped observation, closes admission and retains typed failure without another query"
    );
    Ok(())
}
