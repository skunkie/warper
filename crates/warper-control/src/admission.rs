// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Shared client and retained request reservations, independent of networking.

use std::{fmt, sync::Arc};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, watch},
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
    plan: Plan,
    clients: Arc<Semaphore>,
    requests: Arc<Semaphore>,
}
impl Admission {
    pub fn new(plan: Plan) -> Self {
        Self {
            inner: Arc::new(Inner {
                plan,
                clients: Arc::new(Semaphore::new(plan.clients)),
                requests: Arc::new(Semaphore::new(plan.requests)),
            }),
        }
    }

    pub fn try_client(&self) -> Result<ClientPermit, Error> {
        let permit =
            self.inner
                .clients
                .clone()
                .try_acquire_owned()
                .map_err(|error| match error {
                    TryAcquireError::Closed => Error::Closed,
                    TryAcquireError::NoPermits => Error::Full,
                })?;
        Ok(ClientPermit {
            inner: self.inner.clone(),
            _permit: permit,
        })
    }

    pub fn close(&self) {
        self.inner.clients.close();
        self.inner.requests.close();
    }
}
impl fmt::Debug for Admission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlAdmission(<redacted>)")
    }
}

pub struct ClientPermit {
    inner: Arc<Inner>,
    _permit: OwnedSemaphorePermit,
}
impl ClientPermit {
    pub(crate) fn max_encoded(&self) -> usize {
        self.inner.plan.max_encoded
    }

    pub(crate) async fn request(
        &self,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<OwnedSemaphorePermit, Error> {
        tokio::select! { biased;
            () = cancelled(cancel) => Err(Error::Cancelled),
            () = sleep_until(deadline) => Err(Error::Deadline),
            result = self.inner.requests.clone().acquire_owned() => {
                // Timer readiness can round past a submillisecond deadline.
                if Instant::now() >= deadline { return Err(Error::Deadline); }
                result.map_err(|_| Error::Closed)
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
}
