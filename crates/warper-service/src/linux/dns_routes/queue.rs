// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Count-bounded native commits with retained observation and completion.

use super::{Completion, Error as NativeError, Failure, Manager};
use std::{fmt, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use warper_core::{
    dns::lease::Response,
    transport::{Error as ObserverError, Request},
};

const MAX_REQUESTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimit,
    Full,
    Closed,
    WaitCancelled,
    WaitDeadline,
    AlreadyJoined,
    WorkerStopped,
    Observer(ObserverError),
    Operation(NativeError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "InvalidConfig: DNS commit mailbox limit is invalid",
            Self::Full => "ResourceLimit: DNS commit mailbox is full",
            Self::Closed => "Cancelled: DNS commit mailbox is closed",
            Self::WaitCancelled => "Cancelled: DNS commit observation ended",
            Self::WaitDeadline => "Timeout: DNS commit observation ended",
            Self::AlreadyJoined => "Conflict: DNS commit result was already joined",
            Self::WorkerStopped => "WorkerFailed: DNS commit result owner disappeared",
            Self::Observer(_) => "WorkerFailed: DNS commit observer failed",
            Self::Operation(_) => "SystemConfiguration: DNS native commit failed",
        })
    }
}
impl std::error::Error for Error {}

type Reply = Result<Response, NativeError>;
struct Finished {
    // Drop an abandoned reservation before releasing its admission permit.
    reply: Reply,
    _permit: Arc<OwnedSemaphorePermit>,
}
struct Command {
    response: Response,
    operation: Request,
    completion: Active,
}
struct Active {
    sender: oneshot::Sender<Finished>,
    _permit: Arc<OwnedSemaphorePermit>,
}
impl Active {
    fn finish(self, reply: Reply) {
        // An abandoned observer does not invalidate completed native work.
        // Explicitly drop its returned reservation; never replay the command.
        if let Err(abandoned) = self.sender.send(Finished {
            reply,
            _permit: self._permit,
        }) {
            drop(abandoned);
        }
    }
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Command>,
    admission: Arc<Semaphore>,
    limit: usize,
}
impl Mailbox {
    pub fn submit(&self, response: Response, operation: Request) -> Result<Receipt, Error> {
        super::check_operation(&operation).map_err(Error::Operation)?;
        let permit = Arc::new(
            self.admission
                .clone()
                .try_acquire_owned()
                .map_err(|error| match error {
                    tokio::sync::TryAcquireError::Closed => Error::Closed,
                    tokio::sync::TryAcquireError::NoPermits => Error::Full,
                })?,
        );
        let (sender, receiver) = oneshot::channel();
        let command = Command {
            response,
            operation,
            completion: Active {
                sender,
                _permit: permit.clone(),
            },
        };
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Error::Full,
            mpsc::error::TrySendError::Closed(_) => Error::Closed,
        })?;
        Ok(Receipt {
            receiver: Some(receiver),
            permit: Some(permit),
        })
    }
    pub fn active(&self) -> usize {
        self.limit - self.admission.available_permits()
    }
}

#[must_use = "retain commit receipt through native completion or supervised cleanup"]
pub struct Receipt {
    receiver: Option<oneshot::Receiver<Finished>>,
    permit: Option<Arc<OwnedSemaphorePermit>>,
}
impl Receipt {
    pub async fn wait(&mut self, observer: Request) -> Result<Response, Error> {
        let receiver = self.receiver.as_mut().ok_or(Error::AlreadyJoined)?;
        let result = observer
            .run(async { Ok(receiver.await) })
            .await
            .map_err(observer_error)?;
        self.receiver.take();
        self.permit.take();
        let Finished { reply, _permit } = result.map_err(|_| Error::WorkerStopped)?;
        drop(_permit);
        reply.map_err(Error::Operation)
    }
}

/// The manager remains borrowed across every interrupted observation. The
/// service must retain this driver and its manager through accepted native join.
#[must_use = "retain the driver and join accepted commits before native cleanup"]
pub struct Driver<'a> {
    manager: &'a mut Manager,
    inbox: mpsc::Receiver<Command>,
    admission: Arc<Semaphore>,
    active: Option<Active>,
    failure: Option<Failure>,
    join_error: Option<NativeError>,
    closure_pending: bool,
}
impl<'a> Driver<'a> {
    pub fn new(manager: &'a mut Manager, limit: usize) -> Result<(Mailbox, Self), Error> {
        if manager.has_pending() {
            return Err(Error::Operation(NativeError::Busy));
        }
        if manager.failure().is_some() {
            return Err(Error::Operation(NativeError::Failed));
        }
        let (mailbox, inbox) = channel(limit)?;
        let driver = Self {
            manager,
            inbox,
            admission: mailbox.admission.clone(),
            active: None,
            failure: None,
            join_error: None,
            closure_pending: false,
        };
        Ok((mailbox, driver))
    }
    pub async fn run(&mut self, observer: Request) -> Result<(), Error> {
        loop {
            super::check_wait(&observer).map_err(native_error)?;
            if let Some(failure) = self.failure {
                if self.closure_pending {
                    match self.manager.controller.close() {
                        Err(crate::dns::routes::Error::Busy) => {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        Err(error) => {
                            if let Some(stored) = &mut self.failure {
                                stored.cleanup[0] = Some(NativeError::Metadata(error));
                            }
                            self.closure_pending = false;
                        }
                        Ok(()) => self.closure_pending = false,
                    }
                }
                if self.manager.has_pending() {
                    match self.manager.wait(observer.clone()).await {
                        Err(NativeError::WaitCancelled) => return Err(Error::WaitCancelled),
                        Err(NativeError::WaitDeadline) => return Err(Error::WaitDeadline),
                        Ok(Completion::Committed(response)) => drop(response),
                        Ok(Completion::Retired) => {}
                        Err(error) => {
                            if self.join_error.is_none() {
                                self.join_error = Some(error);
                            }
                        }
                    }
                }
                if !self.manager.has_pending()
                    && let Some(active) = self.active.take()
                {
                    active.finish(Err(failure.primary));
                }
                return Err(Error::Operation(failure.primary));
            }
            if self.active.is_none() {
                let Some(command) = observer
                    .clone()
                    .run(async { Ok(self.inbox.recv().await) })
                    .await
                    .map_err(observer_error)?
                else {
                    self.admission.close();
                    return Ok(());
                };
                let Command {
                    response,
                    operation,
                    completion,
                } = command;
                match self.manager.begin_commit(response, operation) {
                    Ok(()) => self.active = Some(completion),
                    Err(error) => {
                        completion.finish(Err(error));
                        continue;
                    }
                }
            }
            match self.manager.wait(observer.clone()).await {
                Err(NativeError::WaitCancelled) => return Err(Error::WaitCancelled),
                Err(NativeError::WaitDeadline) => return Err(Error::WaitDeadline),
                Ok(Completion::Committed(response)) => {
                    self.active
                        .take()
                        .ok_or(Error::WorkerStopped)?
                        .finish(Ok(response));
                }
                Ok(Completion::Retired) => {
                    self.fail(NativeError::InvalidState);
                    continue;
                }
                Err(error) => {
                    if self.manager.failure().is_some() || self.manager.has_pending() {
                        self.fail(error);
                        continue;
                    }
                    self.active
                        .take()
                        .ok_or(Error::WorkerStopped)?
                        .finish(Err(error));
                }
            }
        }
    }
    pub fn close(&mut self) {
        self.admission.close();
        self.inbox.close();
    }
    pub fn failure(&self) -> Option<Failure> {
        self.failure.or_else(|| self.manager.failure())
    }
    pub fn join_error(&self) -> Option<NativeError> {
        self.join_error
    }

    fn fail(&mut self, primary: NativeError) {
        self.close();
        self.failure = Some(match self.manager.failure() {
            Some(failure) => failure,
            None => {
                let closure = match self.manager.controller.close() {
                    Err(crate::dns::routes::Error::Busy) => {
                        self.closure_pending = true;
                        None
                    }
                    Err(error) => Some(NativeError::Metadata(error)),
                    Ok(()) => None,
                };
                Failure {
                    primary,
                    cleanup: [closure, None],
                }
            }
        });
        while let Ok(command) = self.inbox.try_recv() {
            command.completion.finish(Err(NativeError::Failed));
            drop(command.response);
        }
        if !self.manager.has_pending()
            && let Some(active) = self.active.take()
        {
            active.finish(Err(primary));
        }
    }
}

fn channel(limit: usize) -> Result<(Mailbox, mpsc::Receiver<Command>), Error> {
    if !(1..=MAX_REQUESTS).contains(&limit) {
        return Err(Error::InvalidLimit);
    }
    let (sender, inbox) = mpsc::channel(limit);
    Ok((
        Mailbox {
            sender,
            admission: Arc::new(Semaphore::new(limit)),
            limit,
        },
        inbox,
    ))
}
fn observer_error(error: ObserverError) -> Error {
    match error {
        ObserverError::Cancelled => Error::WaitCancelled,
        ObserverError::Timeout => Error::WaitDeadline,
        other => Error::Observer(other),
    }
}
fn native_error(error: NativeError) -> Error {
    match error {
        NativeError::WaitCancelled => Error::WaitCancelled,
        NativeError::WaitDeadline => Error::WaitDeadline,
        other => Error::Operation(other),
    }
}

#[cfg(test)]
mod tests;
