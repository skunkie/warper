// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One bounded DNS response's TCP acknowledgment, independent of route authority.

use futures::task::AtomicWaker;
use std::{
    fmt, io,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use warper_core::transport::{Error as RequestError, Request};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedCapability,
    Busy,
    InvalidRequest,
    ResourceLimit,
    Closed,
    Reset,
    Cancelled,
    Deadline,
    Poisoned,
    WaitCancelled,
    WaitDeadline,
    AlreadyJoined,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS TCP output: {self:?}")
    }
}
impl std::error::Error for Error {}

struct State {
    accepted: u64,
    enqueued: u64,
    acknowledged: u64,
    start: u64,
    request: Option<Request>,
    outstanding: bool,
    failure: Option<Error>,
}
pub(super) struct Progress {
    state: Mutex<State>,
    changed: Notify,
    wake: Arc<AtomicWaker>,
}
impl Progress {
    pub(super) fn new(wake: Arc<AtomicWaker>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                accepted: 0,
                enqueued: 0,
                acknowledged: 0,
                start: 0,
                request: None,
                outstanding: false,
                failure: None,
            }),
            changed: Notify::new(),
            wake,
        })
    }
    pub(super) fn write(
        &self,
        maximum: usize,
        write: impl FnOnce() -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(io_error(Error::Poisoned))),
        };
        let checked = (|| {
            if let Some(error) = state.failure {
                return Err(error);
            }
            if state.outstanding {
                return Err(Error::Busy);
            }
            if let Some(request) = &state.request {
                check(request)?;
            }
            state
                .accepted
                .checked_add(maximum as u64)
                .ok_or(Error::ResourceLimit)?;
            Ok(())
        })();
        if let Err(error) = checked {
            return Poll::Ready(Err(io_error(error)));
        }
        // This synchronous duplex-buffer poll contains no await or external I/O.
        // Keep the accounting and accepted byte count in the same critical section.
        let result = write();
        if let Poll::Ready(Ok(count)) = result {
            state.accepted += count as u64;
        }
        result
    }
    pub(super) fn enqueued(&self, bytes: usize) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(error) = state.failure {
            return Err(error);
        }
        let next = state
            .enqueued
            .checked_add(bytes as u64)
            .ok_or(Error::ResourceLimit)?;
        if next > state.accepted {
            return Err(Error::ResourceLimit);
        }
        state.enqueued = next;
        Ok(())
    }
    /// Call only for a live socket, before any abort/reset clears its buffer.
    pub(super) fn acknowledge(&self, queued: usize) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(error) = state.failure {
            return Err(error);
        }
        if let Some(request) = &state.request {
            check(request)?;
        }
        let acknowledged = state
            .enqueued
            .checked_sub(queued as u64)
            .ok_or(Error::ResourceLimit)?;
        if acknowledged < state.acknowledged {
            return Err(Error::ResourceLimit);
        }
        if acknowledged > state.acknowledged {
            state.acknowledged = acknowledged;
            self.changed.notify_one();
        }
        Ok(())
    }
    pub(super) fn close(&self, error: Error) {
        if let Ok(mut state) = self.state.lock() {
            state.failure.get_or_insert(error);
        }
        // A poisoned state is also terminal and every reader returns Poisoned.
        self.changed.notify_one();
        self.wake.wake();
    }
}

/// Control for the local DNS stream, not a grant to publish positive answers.
#[derive(Clone)]
pub struct OutputControl(Arc<Progress>);
impl OutputControl {
    pub(super) fn new(progress: Arc<Progress>) -> Self {
        Self(progress)
    }
    pub fn begin(&self, request: Request) -> Result<(), Error> {
        check(&request)?;
        if request.deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(30) {
            return Err(Error::InvalidRequest);
        }
        let mut state = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(error) = state.failure {
            return Err(error);
        }
        if state.request.is_some() || state.outstanding || state.accepted != state.acknowledged {
            return Err(Error::Busy);
        }
        state.start = state.accepted;
        state.request = Some(request);
        Ok(())
    }
    /// Snapshot only after the entire framed reply has entered the stream.
    pub fn receipt(&self) -> Result<Receipt, Error> {
        let mut state = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if let Some(error) = state.failure {
            return Err(error);
        }
        let request = state.request.clone().ok_or(Error::InvalidRequest)?;
        if state.outstanding || state.accepted == state.start {
            return Err(Error::Busy);
        }
        state.outstanding = true;
        Ok(Receipt {
            progress: self.0.clone(),
            target: state.accepted,
            request,
            joined: false,
        })
    }
}

#[must_use = "retain through acknowledgment or joined connection/native cleanup"]
pub struct Receipt {
    progress: Arc<Progress>,
    target: u64,
    request: Request,
    joined: bool,
}
impl Receipt {
    pub async fn wait(&mut self, observer: Request) -> Result<(), Error> {
        if self.joined {
            return Err(Error::AlreadyJoined);
        }
        let result = observer.run(async { Ok(self.wait_owned().await) }).await;
        match result {
            Err(RequestError::Cancelled) => Err(Error::WaitCancelled),
            Err(RequestError::Timeout) => Err(Error::WaitDeadline),
            Err(_) => Err(Error::InvalidRequest),
            Ok(result) => {
                self.joined = true;
                result
            }
        }
    }
    async fn wait_owned(&self) -> Result<(), Error> {
        let mut cancellation = self.request.cancellation.clone();
        loop {
            let changed = self.progress.changed.notified();
            {
                let mut state = self.progress.state.lock().map_err(|_| Error::Poisoned)?;
                if state.acknowledged >= self.target {
                    state.outstanding = false;
                    state.request = None;
                    return Ok(());
                }
                if let Some(error) = state.failure {
                    return Err(error);
                }
            }
            if let Err(error) = check(&self.request) {
                self.progress.close(error);
                return Err(error);
            }
            tokio::select! { biased;
                _ = cancellation.wait_for(|cancelled| *cancelled) => {
                    self.progress.close(Error::Cancelled);
                    return Err(Error::Cancelled);
                }
                () = tokio::time::sleep_until(self.request.deadline) => {
                    self.progress.close(Error::Deadline);
                    return Err(Error::Deadline);
                }
                () = changed => {}
            }
        }
    }
}

fn check(request: &Request) -> Result<(), Error> {
    if *request.cancellation.borrow() || request.cancellation.has_changed().is_err() {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= request.deadline {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn io_error(error: Error) -> io::Error {
    match error {
        Error::Cancelled => io::ErrorKind::Interrupted.into(),
        Error::Deadline => io::ErrorKind::TimedOut.into(),
        Error::Reset => io::ErrorKind::ConnectionReset.into(),
        Error::Closed => io::ErrorKind::BrokenPipe.into(),
        _ => io::ErrorKind::InvalidInput.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    fn request(owner: &watch::Sender<bool>, duration: Duration) -> Request {
        Request {
            deadline: Instant::now() + duration,
            cancellation: owner.subscribe(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn observation_timeout_preserves_confirmed_result_after_close() {
        let progress = Progress::new(Arc::new(AtomicWaker::new()));
        let control = OutputControl::new(progress.clone());
        let (owner, _) = watch::channel(false);
        let original = request(&owner, Duration::from_secs(10));
        control.begin(original).unwrap();
        assert!(matches!(control.receipt(), Err(Error::Busy)));
        assert!(matches!(
            progress.write(3, || Poll::Ready(Ok(3))),
            Poll::Ready(Ok(3))
        ));
        let mut receipt = control.receipt().unwrap();
        assert!(matches!(
            progress.write(1, || unreachable!()),
            Poll::Ready(Err(_))
        ));
        progress.enqueued(3).unwrap();
        assert_eq!(
            receipt
                .wait(request(&owner, Duration::from_millis(1)))
                .await,
            Err(Error::WaitDeadline)
        );
        progress.acknowledge(1).unwrap();
        assert_eq!(
            receipt
                .wait(request(&owner, Duration::from_millis(1)))
                .await,
            Err(Error::WaitDeadline)
        );
        progress.acknowledge(0).unwrap();
        progress.close(Error::Reset);
        owner.send_replace(true);
        let (observer, _) = watch::channel(false);
        assert_eq!(
            receipt
                .wait(request(&observer, Duration::from_secs(1)))
                .await,
            Ok(())
        );
        assert_eq!(
            control.begin(request(&observer, Duration::from_secs(1))),
            Err(Error::Reset)
        );
    }

    #[tokio::test]
    async fn original_cancellation_is_terminal_without_a_host_poll() {
        let progress = Progress::new(Arc::new(AtomicWaker::new()));
        let control = OutputControl::new(progress.clone());
        let (owner, _) = watch::channel(false);
        let (observer, _) = watch::channel(false);
        control
            .begin(request(&owner, Duration::from_secs(1)))
            .unwrap();
        assert!(matches!(
            progress.write(1, || Poll::Ready(Ok(1))),
            Poll::Ready(Ok(1))
        ));
        let mut receipt = control.receipt().unwrap();
        owner.send_replace(true);
        assert_eq!(
            receipt
                .wait(request(&observer, Duration::from_secs(1)))
                .await,
            Err(Error::Cancelled)
        );
        assert_eq!(
            control.begin(request(&observer, Duration::from_secs(1))),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn invalid_request_and_counter_bounds_leave_state_unchanged() {
        let progress = Progress::new(Arc::new(AtomicWaker::new()));
        let control = OutputControl::new(progress.clone());
        let (owner, _) = watch::channel(false);
        assert_eq!(
            control.begin(request(&owner, Duration::from_secs(31))),
            Err(Error::InvalidRequest)
        );
        assert!(matches!(control.receipt(), Err(Error::InvalidRequest)));
        control
            .begin(request(&owner, Duration::from_secs(1)))
            .unwrap();
        assert_eq!(progress.enqueued(1), Err(Error::ResourceLimit));
        assert_eq!(progress.acknowledge(1), Err(Error::ResourceLimit));
        assert!(matches!(
            progress.write(2, || Poll::Ready(Ok(2))),
            Poll::Ready(Ok(2))
        ));
        progress.enqueued(2).unwrap();
        progress.acknowledge(0).unwrap();
        assert_eq!(progress.acknowledge(1), Err(Error::ResourceLimit));
    }
}
