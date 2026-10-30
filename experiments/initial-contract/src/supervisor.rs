// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Retained service tasks and bounded shutdown without losing an initial error.

use std::future::Future;

use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout_at},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimit,
    ResourceLimit,
    Worker,
    Panicked,
    Deadline,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Failure {
    pub primary: Option<Error>,
    pub cleanup: Vec<Error>,
}

pub struct Supervisor {
    tasks: JoinSet<Result<(), Error>>,
    cancellation: watch::Sender<bool>,
    limit: usize,
}

impl Supervisor {
    pub fn new(limit: usize) -> Result<Self, Error> {
        if limit == 0 || limit > 64 {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            tasks: JoinSet::new(),
            cancellation: watch::channel(false).0,
            limit,
        })
    }

    pub fn spawn(
        &mut self,
        task: impl Future<Output = Result<(), Error>> + Send + 'static,
    ) -> Result<(), Error> {
        if self.tasks.len() >= self.limit {
            return Err(Error::ResourceLimit);
        }
        self.tasks.spawn(task);
        Ok(())
    }

    pub fn cancellation(&self) -> watch::Receiver<bool> {
        self.cancellation.subscribe()
    }

    pub async fn next_failure(&mut self) -> Option<Error> {
        while let Some(result) = self.tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Some(error),
                Err(_) => return Some(Error::Panicked),
            }
        }
        None
    }

    pub async fn shutdown(
        mut self,
        deadline: Instant,
        primary: Option<Error>,
    ) -> Result<(), Failure> {
        self.cancellation.send_replace(true);
        // Bounded by the task limit plus one shutdown deadline diagnostic.
        let mut cleanup = Vec::with_capacity(self.tasks.len() + 1);
        let mut aborting = false;
        while !self.tasks.is_empty() {
            let result = if aborting {
                self.tasks.join_next().await
            } else {
                match timeout_at(deadline, self.tasks.join_next()).await {
                    Ok(result) => result,
                    Err(_) => {
                        cleanup.push(Error::Deadline);
                        self.tasks.abort_all();
                        aborting = true;
                        continue;
                    }
                }
            };
            match result {
                Some(Ok(Ok(()))) | None => {}
                Some(Ok(Err(error))) => cleanup.push(error),
                Some(Err(error)) if aborting && error.is_cancelled() => {}
                Some(Err(_)) => cleanup.push(Error::Panicked),
            }
        }
        if primary.is_some() || !cleanup.is_empty() {
            Err(Failure { primary, cleanup })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use super::*;

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_aborts_and_joins_stalled_task_preserving_initial_failure() {
        let mut supervisor = Supervisor::new(1).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&dropped));
        supervisor
            .spawn(async move {
                let _guard = guard;
                pending().await
            })
            .unwrap();
        assert_eq!(
            supervisor.spawn(async { Ok(()) }),
            Err(Error::ResourceLimit)
        );
        let failure = supervisor
            .shutdown(Instant::now() + Duration::from_secs(1), Some(Error::Worker))
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            Failure {
                primary: Some(Error::Worker),
                cleanup: vec![Error::Deadline]
            }
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "shutdown must join after abort"
        );
    }

    #[tokio::test]
    async fn worker_failure_is_observed_and_remaining_workers_are_joined() {
        let mut supervisor = Supervisor::new(2).unwrap();
        let mut cancellation = supervisor.cancellation();
        supervisor
            .spawn(async move {
                cancellation
                    .wait_for(|cancelled| *cancelled)
                    .await
                    .map_err(|_| Error::Worker)?;
                Err(Error::Worker)
            })
            .unwrap();
        supervisor.spawn(async { Err(Error::Worker) }).unwrap();
        assert_eq!(supervisor.next_failure().await, Some(Error::Worker));
        let failure = supervisor
            .shutdown(Instant::now() + Duration::from_secs(1), Some(Error::Worker))
            .await
            .unwrap_err();
        assert_eq!(failure.primary, Some(Error::Worker));
        assert_eq!(failure.cleanup, [Error::Worker]);
    }
}
