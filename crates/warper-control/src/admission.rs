// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Shared client and retained request reservations, independent of networking.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::{
    sync::{Notify, watch},
    time::{Instant, sleep_until},
};

use crate::{session::MIN_MESSAGE_BYTES, wire};

const MAX_CONCURRENCY: usize = 64;
const REPLY_BYTES: usize = 46;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    Full,
    Closed,
    Cancelled,
    Deadline,
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "ResourceLimit: invalid control admission limits",
            Self::Full => "Busy: control client capacity is exhausted",
            Self::Closed => "Cancelled: control admission is closed",
            Self::Cancelled => "Cancelled: control admission wait was cancelled",
            Self::Deadline => "Timeout: control admission deadline expired",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    clients: usize,
    requests: usize,
    max_encoded: usize,
    reserved_bytes: usize,
}
impl Plan {
    pub fn new(
        clients: usize,
        requests: usize,
        max_encoded: usize,
        buffered_bytes: usize,
    ) -> Result<Self, Error> {
        if !(1..=MAX_CONCURRENCY).contains(&clients)
            || !(1..=MAX_CONCURRENCY).contains(&requests)
            || !(MIN_MESSAGE_BYTES..=20 + wire::MAX_BODY).contains(&max_encoded)
        {
            return Err(Error::InvalidLimits);
        }
        let replies = clients
            .checked_mul(REPLY_BYTES)
            .ok_or(Error::InvalidLimits)?;
        let remaining = buffered_bytes
            .checked_sub(replies)
            .ok_or(Error::InvalidLimits)?;
        let requests = requests.min(remaining / max_encoded);
        if requests == 0 {
            return Err(Error::InvalidLimits);
        }
        let reserved_bytes = requests
            .checked_mul(max_encoded)
            .and_then(|bytes| bytes.checked_add(replies))
            .ok_or(Error::InvalidLimits)?;
        Ok(Self {
            clients,
            requests,
            max_encoded,
            reserved_bytes,
        })
    }

    pub fn clients(&self) -> usize {
        self.clients
    }
    pub fn requests(&self) -> usize {
        self.requests
    }
    pub fn max_encoded(&self) -> usize {
        self.max_encoded
    }
    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }
}

pub struct Admission {
    inner: Arc<Inner>,
}
struct Inner {
    state: Mutex<State>,
    changed: Notify,
}
struct State {
    plan: Plan,
    clients: usize,
    requests: usize,
    bytes: usize,
    closed: bool,
}
impl Inner {
    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> {
        // Poison remains fail-closed; never reconstruct potentially lost quota.
        let state = self.state.lock().map_err(|_| Error::Closed)?;
        if state.closed {
            return Err(Error::Closed);
        }
        Ok(state)
    }
}
impl Admission {
    pub fn new(plan: Plan) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    plan,
                    clients: 0,
                    requests: 0,
                    bytes: 0,
                    closed: false,
                }),
                changed: Notify::new(),
            }),
        }
    }

    pub fn try_client(&self) -> Result<ClientPermit, Error> {
        let mut state = self.inner.lock()?;
        if state.clients >= state.plan.clients
            || state.bytes + REPLY_BYTES > state.plan.reserved_bytes
        {
            return Err(Error::Full);
        }
        state.clients += 1;
        state.bytes += REPLY_BYTES;
        Ok(ClientPermit {
            lease: Arc::new(ClientLease {
                inner: self.inner.clone(),
            }),
        })
    }

    /// New reservations obey the new plan. Existing request buffers and their
    /// client leases retain their original byte charges until final release.
    /// Shrinking limits never cancels work or creates a second quota owner.
    pub fn reconfigure(&self, plan: Plan) -> Result<(), Error> {
        self.inner.lock()?.plan = plan;
        self.inner.changed.notify_waiters();
        Ok(())
    }

    pub fn close(&self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.closed = true;
        }
        // A poisoned mutex also permanently denies future reservations.
        self.inner.changed.notify_waiters();
    }
}
impl fmt::Debug for Admission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlAdmission(<redacted>)")
    }
}

pub struct ClientPermit {
    lease: Arc<ClientLease>,
}
struct ClientLease {
    inner: Arc<Inner>,
}
impl Drop for ClientLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock() {
            match (
                state.clients.checked_sub(1),
                state.bytes.checked_sub(REPLY_BYTES),
            ) {
                (Some(clients), Some(bytes)) => {
                    state.clients = clients;
                    state.bytes = bytes;
                }
                _ => state.closed = true,
            }
        }
        self.inner.changed.notify_waiters();
    }
}

pub(crate) struct RequestPermit {
    client: Arc<ClientLease>,
    max_encoded: usize,
}
impl RequestPermit {
    pub(crate) fn max_encoded(&self) -> usize {
        self.max_encoded
    }
}
impl Drop for RequestPermit {
    fn drop(&mut self) {
        let inner = &self.client.inner;
        if let Ok(mut state) = inner.state.lock() {
            match (
                state.requests.checked_sub(1),
                state.bytes.checked_sub(self.max_encoded),
            ) {
                (Some(requests), Some(bytes)) => {
                    state.requests = requests;
                    state.bytes = bytes;
                }
                _ => state.closed = true,
            }
        }
        inner.changed.notify_waiters();
        // The request retains its client reservation through queued/native work,
        // including after the session that admitted it has disconnected.
    }
}
impl ClientPermit {
    pub(crate) fn max_encoded(&self) -> Result<usize, Error> {
        Ok(self.lease.inner.lock()?.plan.max_encoded)
    }

    pub(crate) async fn request(
        &self,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<RequestPermit, Error> {
        let inner = &self.lease.inner;
        loop {
            let changed = inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if *cancel.borrow() || cancel.has_changed().is_err() {
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            let reservation = {
                let mut state = inner.lock()?;
                let bytes = state.plan.max_encoded;
                if state.clients <= state.plan.clients
                    && state.requests < state.plan.requests
                    && state.bytes + bytes <= state.plan.reserved_bytes
                {
                    state.requests += 1;
                    state.bytes += bytes;
                    Some(RequestPermit {
                        client: self.lease.clone(),
                        max_encoded: bytes,
                    })
                } else {
                    None
                }
            };
            if let Some(reservation) = reservation {
                // Recheck after mutex contention without nesting the watch lock
                // inside the quota lock. Dropping rolls back a late reservation.
                if *cancel.borrow() || cancel.has_changed().is_err() {
                    return Err(Error::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(Error::Deadline);
                }
                return Ok(reservation);
            }
            tokio::select! { biased;
                () = cancelled(cancel) => return Err(Error::Cancelled),
                () = sleep_until(deadline) => return Err(Error::Deadline),
                () = &mut changed => {}
            }
        }
    }
}
impl fmt::Debug for ClientPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlClientPermit(<redacted>)")
    }
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::poll_fn, task::Poll, time::Duration};

    #[tokio::test(start_paused = true)]
    async fn waiting_requests_honor_cancellation_owner_loss_and_deadlines() {
        let admission = Admission::new(Plan::new(2, 1, 68, 160).unwrap());
        let first = admission.try_client().unwrap();
        let second = admission.try_client().unwrap();
        let (owner, mut cancel) = watch::channel(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        let held = first.request(deadline, &mut cancel).await.unwrap();
        let mut other = cancel.clone();
        {
            let waiting = second.request(deadline, &mut other);
            tokio::pin!(waiting);
            poll_fn(|context| {
                assert!(waiting.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            owner.send(true).unwrap();
            assert!(matches!(waiting.await, Err(Error::Cancelled)));
        }
        owner.send(false).unwrap();
        assert!(matches!(
            second.request(deadline, &mut cancel).await,
            Err(Error::Deadline)
        ));
        drop(held);
        // Even immediately available capacity cannot bypass an expired deadline.
        assert!(matches!(
            first.request(deadline, &mut cancel).await,
            Err(Error::Deadline)
        ));
        let deadline = Instant::now() + Duration::from_secs(1);
        drop(owner);
        assert!(matches!(
            first.request(deadline, &mut cancel).await,
            Err(Error::Cancelled)
        ));
        let (_owner, mut fresh) = watch::channel(false);
        drop(first.request(deadline, &mut fresh).await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn released_capacity_cannot_resume_a_waiter_after_submillisecond_expiry() {
        let admission = Admission::new(Plan::new(2, 1, 68, 160).unwrap());
        let first = admission.try_client().unwrap();
        let second = admission.try_client().unwrap();
        let (_owner, mut cancel) = watch::channel(false);
        let held = first
            .request(Instant::now() + Duration::from_secs(1), &mut cancel)
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_micros(250);
        let waiting = second.request(deadline, &mut cancel);
        tokio::pin!(waiting);
        poll_fn(|context| {
            assert!(waiting.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_micros(300)).await;
        drop(held);
        assert!(matches!(waiting.await, Err(Error::Deadline)));
    }

    #[tokio::test(start_paused = true)]
    async fn shrinking_limits_preserves_old_charges_and_refreshes_request_size() {
        let admission = Admission::new(Plan::new(2, 1, 1000, 1092).unwrap());
        let first = admission.try_client().unwrap();
        let second = admission.try_client().unwrap();
        let (_owner, mut cancel) = watch::channel(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        let held = first.request(deadline, &mut cancel).await.unwrap();
        admission
            .reconfigure(Plan::new(2, 2, 68, 228).unwrap())
            .unwrap();
        let next = {
            let waiting = second.request(deadline, &mut cancel);
            tokio::pin!(waiting);
            poll_fn(|context| {
                assert!(waiting.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(held.max_encoded(), 1000);
            drop(held);
            waiting.await.unwrap()
        };
        assert_eq!(next.max_encoded(), 68);
        let last = first.request(deadline, &mut cancel).await.unwrap();
        assert_eq!(last.max_encoded(), 68);
        drop(next);
        drop(last);
    }

    #[tokio::test(start_paused = true)]
    async fn client_shrink_drains_old_leases_without_opening_another_quota() {
        let admission = Admission::new(Plan::new(2, 2, 68, 228).unwrap());
        let first = admission.try_client().unwrap();
        let second = admission.try_client().unwrap();
        admission
            .reconfigure(Plan::new(1, 1, 68, 114).unwrap())
            .unwrap();
        let (_owner, mut cancel) = watch::channel(false);
        let retained = {
            let waiting = second.request(Instant::now() + Duration::from_secs(1), &mut cancel);
            tokio::pin!(waiting);
            poll_fn(|context| {
                assert!(waiting.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(matches!(admission.try_client(), Err(Error::Full)));
            drop(first);
            waiting.await.unwrap()
        };
        drop(second);
        assert!(matches!(admission.try_client(), Err(Error::Full)));
        drop(retained);
        drop(admission.try_client().unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn expansion_uses_one_account_for_old_and_new_sized_reservations() {
        let admission = Admission::new(Plan::new(1, 1, 68, 114).unwrap());
        let first = admission.try_client().unwrap();
        let (_owner, mut cancel) = watch::channel(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        let held = first.request(deadline, &mut cancel).await.unwrap();
        admission
            .reconfigure(Plan::new(2, 2, 256, 604).unwrap())
            .unwrap();
        let second = admission.try_client().unwrap();
        let next = second.request(deadline, &mut cancel).await.unwrap();
        assert_eq!(held.max_encoded(), 68);
        assert_eq!(next.max_encoded(), 256);
        assert_eq!(first.max_encoded(), Ok(256));
        drop(held);
        let newest = first.request(deadline, &mut cancel).await.unwrap();
        assert_eq!(newest.max_encoded(), 256);
        drop(next);
        drop(newest);
        admission.close();
        assert_eq!(
            admission.reconfigure(Plan::new(1, 1, 68, 114).unwrap()),
            Err(Error::Closed)
        );
    }

    #[test]
    fn poisoned_accounting_cannot_grant_or_reconfigure_capacity() {
        let admission = Admission::new(Plan::new(1, 1, 68, 114).unwrap());
        let inner = admission.inner.clone();
        let worker = std::thread::spawn(move || {
            let _state = inner.state.lock().unwrap();
            panic!("injected failure while holding accounting state");
        });
        assert!(worker.join().is_err());
        assert!(matches!(admission.try_client(), Err(Error::Closed)));
        assert_eq!(
            admission.reconfigure(Plan::new(1, 1, 68, 114).unwrap()),
            Err(Error::Closed)
        );
        admission.close();
    }
}
