// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Retained, joined notification worker for the isolated path experiment.

use std::{
    sync::{Arc, Condvar, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::Result;

use crate::link_monitor::Error;

#[derive(Clone, Copy)]
enum State {
    Running,
    Changed,
    Failed(Error),
    Stopped,
}

#[derive(Clone)]
pub(super) struct Observer(Arc<(Mutex<State>, Condvar)>);

impl Observer {
    pub(super) fn poll(&self) -> Result<bool, Error> {
        let state = self.0.0.lock().map_err(|_| Error::Lost)?;
        match *state {
            State::Running => Ok(false),
            State::Changed => Ok(true),
            State::Failed(error) => Err(error),
            State::Stopped => Err(Error::Lost),
        }
    }

    pub(super) fn wait(&self, timeout: Duration) -> Result<Option<bool>, Error> {
        let state = self.0.0.lock().map_err(|_| Error::Lost)?;
        let (state, _) = self
            .0
            .1
            .wait_timeout_while(state, timeout, |state| matches!(state, State::Running))
            .map_err(|_| Error::Lost)?;
        match *state {
            State::Running => Ok(None),
            State::Changed => Ok(Some(true)),
            State::Failed(error) => Err(error),
            State::Stopped => Err(Error::Lost),
        }
    }
}

struct Worker {
    stop: mpsc::SyncSender<()>,
    handle: Option<JoinHandle<Result<(), Error>>>,
}

impl Worker {
    fn finish(&mut self) -> Result<(), Error> {
        // A disconnected worker is accounted for by its join result; a full
        // channel already contains a stop request.
        let _ = self.stop.try_send(());
        match self.handle.take() {
            Some(handle) => handle.join().map_err(|_| Error::WorkerFailed)?,
            None => Ok(()),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Explicit finish reports failures. This fallback also joins during
        // unwinding, when the primary panic is already being propagated.
        if let Err(error) = self.finish() {
            eprintln!("path watcher cleanup failed during unwinding: {error}");
        }
    }
}

pub(super) fn run<T>(
    mut poll: impl FnMut() -> Result<bool, Error> + Send + 'static,
    operation: impl FnOnce(Observer) -> Result<T>,
) -> Result<T> {
    let observer = Observer(Arc::new((Mutex::new(State::Running), Condvar::new())));
    let worker_state = observer.clone();
    let (stop, stop_receiver) = mpsc::sync_channel(1);
    let handle = thread::Builder::new()
        .name("path-watch".into())
        .spawn(move || {
            loop {
                let outcome = match poll() {
                    Ok(false) => None,
                    Ok(true) => Some(Ok(())),
                    Err(error) => Some(Err(error)),
                };
                if let Some(outcome) = outcome {
                    let mut state = worker_state.0.0.lock().map_err(|_| Error::Lost)?;
                    *state = match outcome {
                        Ok(()) => State::Changed,
                        Err(error) => State::Failed(error),
                    };
                    worker_state.0.1.notify_all();
                    return outcome;
                }
                match stop_receiver.recv_timeout(Duration::from_millis(5)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let mut state = worker_state.0.0.lock().map_err(|_| Error::Lost)?;
                        *state = State::Stopped;
                        worker_state.0.1.notify_all();
                        return Ok(());
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        })?;
    let mut worker = Worker {
        stop,
        handle: Some(handle),
    };
    let result = operation(observer);
    let cleanup = worker.finish();
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(error)) => {
            Err(primary.context(format!("path watcher cleanup also failed: {error}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};

    #[test]
    fn worker_observes_idle_change_and_joins() {
        let signal = Arc::new(AtomicU8::new(0));
        let worker_signal = Arc::clone(&signal);
        run(
            move || Ok(worker_signal.load(Ordering::SeqCst) != 0),
            |observer| {
                assert_eq!(observer.wait(Duration::from_millis(20))?, None);
                signal.store(1, Ordering::SeqCst);
                assert_eq!(observer.wait(Duration::from_secs(1))?, Some(true));
                assert!(observer.poll()?);
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn worker_surfaces_failure_and_stops_on_cancellation() {
        let error = run(
            || Err(Error::Lost),
            |observer| {
                assert_eq!(observer.wait(Duration::from_secs(1)), Err(Error::Lost));
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.downcast_ref::<Error>(), Some(&Error::Lost));
        run(|| Ok(false), |_observer| Ok(())).unwrap();
    }
    #[test]
    fn stopped_or_poisoned_observer_fails_closed() {
        let stopped = run(|| Ok(false), Ok).unwrap();
        assert_eq!(stopped.poll(), Err(Error::Lost));
        assert_eq!(stopped.wait(Duration::ZERO), Err(Error::Lost));

        let poisoned = Observer(Arc::new((Mutex::new(State::Running), Condvar::new())));
        let worker = poisoned.clone();
        assert!(
            thread::spawn(move || {
                let _guard = worker.0.0.lock().unwrap();
                panic!("synthetic poisoned state");
            })
            .join()
            .is_err()
        );
        assert_eq!(poisoned.poll(), Err(Error::Lost));
        assert_eq!(poisoned.wait(Duration::ZERO), Err(Error::Lost));
    }

    #[test]
    fn operation_failure_joins_worker_before_returning() {
        struct ExitSignal(Arc<AtomicU8>);
        impl Drop for ExitSignal {
            fn drop(&mut self) {
                self.0.store(1, Ordering::SeqCst);
            }
        }
        let signal = Arc::new(AtomicU8::new(0));
        let guard = ExitSignal(Arc::clone(&signal));
        let result = run(
            move || {
                let _ = &guard;
                Ok(false)
            },
            |_observer| Err::<(), _>(std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
        );
        assert!(matches!(result, Err(error) if error.downcast_ref::<std::io::Error>().is_some()));
        assert_eq!(signal.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn worker_panic_is_reported_alongside_primary_failure() {
        let error = run(
            || -> Result<bool, Error> { panic!("synthetic worker panic") },
            |observer| {
                let _ = observer.wait(Duration::from_millis(20));
                Err::<(), _>(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(format!("{error:#}").contains("WorkerFailed"));
    }
}
