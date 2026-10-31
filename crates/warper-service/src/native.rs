// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded ownership of blocking native jobs. A caller wait is not cancellation
//! of accepted service work; the supervisor must retain and join every task.

use std::{fmt, sync::Arc};
use tokio::{
    runtime::Handle,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::sleep_until,
};
use warper_core::transport::Request;

const MAX_JOBS: usize = 4;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimit,
    NoRuntime,
    Busy,
    WaitCancelled,
    Deadline,
    AlreadyJoined,
    WorkerPanicked,
    WorkerCancelled,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "ResourceLimit: native worker limit must be between one and four",
            Self::NoRuntime => "SystemConfiguration: native job requires an active runtime",
            Self::Busy => "ResourceLimit: native worker admission exhausted",
            Self::WaitCancelled => "Cancelled: native wait ended while work remains owned",
            Self::Deadline => "Timeout: native wait ended while work remains owned",
            Self::AlreadyJoined => "Conflict: native job result was already joined",
            Self::WorkerPanicked => "WorkerFailed: native job panicked",
            Self::WorkerCancelled => "WorkerFailed: runtime cancelled a native job",
        })
    }
}
impl std::error::Error for Error {}

/// Admission includes running jobs and results awaiting join. There is no
/// internal waiting queue. Reserve before moving an existing native resource.
pub struct Workers {
    slots: Arc<Semaphore>,
}
impl Workers {
    pub fn new(limit: usize) -> Result<Self, Error> {
        if !(1..=MAX_JOBS).contains(&limit) {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            slots: Arc::new(Semaphore::new(limit)),
        })
    }
    pub fn try_reserve(&self) -> Result<Reservation, Error> {
        let runtime = Handle::try_current().map_err(|_| Error::NoRuntime)?;
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        Ok(Reservation {
            slot: Arc::new(slot),
            runtime,
        })
    }
}

pub struct Reservation {
    slot: Arc<OwnedSemaphorePermit>,
    runtime: Handle,
}
impl Reservation {
    /// No namespace/credential changes are permitted in a reusable blocking
    /// runtime thread. Native operations must revalidate their captured context.
    pub fn start<F, T>(self, work: F) -> Task<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let slot = self.slot.clone();
        let handle = self.runtime.spawn_blocking(move || Completion {
            value: work(),
            _slot: slot,
        });
        Task {
            handle: Some(handle),
            slot: Some(self.slot),
        }
    }
}

struct Completion<T> {
    // Drop a discarded native result before releasing its worker reservation.
    value: T,
    _slot: Arc<OwnedSemaphorePermit>,
}

/// Cancellation-safe waits borrow the retained handle. Drop does not stop
/// already-started blocking I/O or join it; explicit supervisor drain is required.
/// Work and any result retain admission even if this owner is unexpectedly lost.
pub struct Task<T> {
    handle: Option<JoinHandle<Completion<T>>>,
    slot: Option<Arc<OwnedSemaphorePermit>>,
}
impl<T: Send + 'static> Task<T> {
    pub async fn wait(&mut self, mut request: Request) -> Result<T, Error> {
        let handle = self.handle.as_mut().ok_or(Error::AlreadyJoined)?;
        let result = tokio::select! {biased;
            _=request.cancellation.wait_for(|cancelled|*cancelled)=>return Err(Error::WaitCancelled),
            ()=sleep_until(request.deadline)=>return Err(Error::Deadline),
            result=handle=>result,
        };
        self.handle.take();
        self.slot.take();
        match result {
            Ok(completed) => Ok(completed.value),
            Err(error) if error.is_panic() => Err(Error::WorkerPanicked),
            Err(_) => Err(Error::WorkerCancelled),
        }
    }
    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }
}
impl<T> fmt::Debug for Task<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeTask(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};
    use tokio::{sync::watch, time::Instant};

    fn request() -> (watch::Sender<bool>, Request) {
        let (owner, cancellation) = watch::channel(false);
        (
            owner,
            Request {
                deadline: Instant::now() + Duration::from_secs(2),
                cancellation,
            },
        )
    }
    #[test]
    fn worker_admission_rejects_invalid_limits_and_missing_runtime() {
        for limit in [0, MAX_JOBS + 1] {
            assert!(matches!(Workers::new(limit), Err(Error::InvalidLimit)));
        }
        assert!(matches!(
            Workers::new(1).unwrap().try_reserve(),
            Err(Error::NoRuntime)
        ));
    }
    #[tokio::test]
    async fn caller_cancellation_retains_work_and_admission_until_join() {
        let workers = Workers::new(1).unwrap();
        let (release, blocked) = mpsc::sync_channel(1);
        let mut task = workers.try_reserve().unwrap().start(move || {
            blocked.recv().unwrap();
            42
        });
        let (owner, request) = request();
        owner.send(true).unwrap();
        let cancelled = task.wait(request).await;
        let stayed_busy = matches!(workers.try_reserve(), Err(Error::Busy));
        // Release and join before assertions so an unexpected wait result cannot
        // leave a blocked runtime worker behind the test's panic.
        release.send(()).unwrap();
        let (_owner, request) = self::request();
        let result = task.wait(request).await;
        assert_eq!(cancelled, Err(Error::WaitCancelled));
        assert!(stayed_busy);
        assert_eq!(result, Ok(42));
        assert!(workers.try_reserve().is_ok());
        let (_owner, request) = self::request();
        assert_eq!(task.wait(request).await, Err(Error::AlreadyJoined));
    }
    #[tokio::test]
    async fn deadline_and_owner_loss_leave_the_same_result_available() {
        let workers = Workers::new(1).unwrap();
        let (release, blocked) = mpsc::sync_channel(1);
        let mut task = workers.try_reserve().unwrap().start(move || {
            blocked.recv().unwrap();
            7
        });
        let (_owner, mut request) = request();
        request.deadline = Instant::now();
        let timeout = task.wait(request).await;
        let (owner, request) = self::request();
        drop(owner);
        let owner_lost = task.wait(request).await;
        release.send(()).unwrap();
        let (_owner, request) = self::request();
        let result = task.wait(request).await;
        assert_eq!(timeout, Err(Error::Deadline));
        assert_eq!(owner_lost, Err(Error::WaitCancelled));
        assert_eq!(result, Ok(7));
    }
    #[tokio::test]
    async fn worker_panic_is_joined_and_releases_admission() {
        let workers = Workers::new(1).unwrap();
        let mut task = workers
            .try_reserve()
            .unwrap()
            .start(|| -> () { panic!("invented native worker failure") });
        let stayed_busy = matches!(workers.try_reserve(), Err(Error::Busy));
        let (_owner, request) = request();
        let result = task.wait(request).await;
        assert!(stayed_busy);
        assert_eq!(result, Err(Error::WorkerPanicked));
        assert!(task.is_finished());
        assert!(workers.try_reserve().is_ok());
    }
}
