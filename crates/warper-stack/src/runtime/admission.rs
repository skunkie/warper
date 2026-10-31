// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Retained single-command admission control; observer loss is not cancellation.

use super::Error;
use std::{fmt, sync::Arc};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::sleep_until,
};
use warper_core::transport::Request;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub active_flows: usize,
    pub retained_streams: usize,
}

#[derive(Clone)]
pub struct AdmissionControl {
    sender: mpsc::Sender<Command>,
    slots: Arc<Semaphore>,
}
impl AdmissionControl {
    pub(super) fn new() -> (Self, mpsc::Receiver<Command>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                sender,
                slots: Arc::new(Semaphore::new(1)),
            },
            receiver,
        )
    }
    pub fn quiesce(&self) -> Result<Quiescence, Error> {
        let reservation = Arc::new(
            self.slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ControlBusy)?,
        );
        let permit = self.sender.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Error::ControlBusy,
            mpsc::error::TrySendError::Closed(_) => Error::ControlClosed,
        })?;
        let (reply, receiver) = oneshot::channel();
        permit.send(Command {
            reply,
            reservation: reservation.clone(),
        });
        Ok(Quiescence {
            receiver: Some(receiver),
            reservation: Some(reservation),
        })
    }
}

pub struct Quiescence {
    receiver: Option<oneshot::Receiver<Completion>>,
    reservation: Option<Arc<OwnedSemaphorePermit>>,
}
impl Quiescence {
    /// Wait cancellation/deadline borrows the retained result. A later wait can
    /// still join it; dropping this receipt does not retract an accepted command.
    pub async fn wait(&mut self, mut request: Request) -> Result<Snapshot, Error> {
        let receiver = self.receiver.as_mut().ok_or(Error::AlreadyJoined)?;
        let result = tokio::select! {biased;
            _=request.cancellation.wait_for(|cancelled|*cancelled)=>return Err(Error::WaitCancelled),
            ()=sleep_until(request.deadline)=>return Err(Error::WaitDeadline),
            result=receiver=>result,
        };
        self.receiver.take();
        self.reservation.take();
        result
            .map(|completion| completion.snapshot)
            .map_err(|_| Error::ControlOwnerLost)
    }
}
impl fmt::Debug for Quiescence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Quiescence(<retained receipt>)")
    }
}

pub(super) struct Command {
    reply: oneshot::Sender<Completion>,
    reservation: Arc<OwnedSemaphorePermit>,
}
impl Command {
    pub(super) fn complete(self, snapshot: Snapshot) {
        // An observer may have detached. The mutation is already applied;
        // failed delivery drops only that unread completion and reservation.
        if let Err(completion) = self.reply.send(Completion {
            snapshot,
            _reservation: self.reservation,
        }) {
            drop(completion);
        }
    }
}
struct Completion {
    snapshot: Snapshot,
    _reservation: Arc<OwnedSemaphorePermit>,
}
