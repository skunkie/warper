// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native output completion, independent of DNS parsing and route ownership.

use std::{fmt, ops::Deref, sync::Arc};
use tokio::{
    sync::{OwnedSemaphorePermit, oneshot, watch},
    time::sleep_until,
};
use warper_core::transport::Request;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Cancelled,
    Deadline,
    Uncertain,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WaitCancelled,
    WaitDeadline,
    AlreadyJoined,
    OwnerLost,
    Delivery(Failure),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WaitCancelled => "Cancelled: packet delivery observation ended",
            Self::WaitDeadline => "Timeout: packet delivery observation ended",
            Self::AlreadyJoined => "Conflict: packet delivery was already joined",
            Self::OwnerLost => "WorkerFailed: packet delivery observer disappeared",
            Self::Delivery(Failure::Cancelled) => {
                "Cancelled: packet output cancelled before delivery"
            }
            Self::Delivery(Failure::Deadline) => "Timeout: packet output expired before delivery",
            Self::Delivery(Failure::Uncertain) => "NativeUncertain: packet delivery is unverified",
        })
    }
}
impl std::error::Error for Error {}

#[must_use = "retain through native output and explicit receipt completion"]
pub struct Packet {
    bytes: Vec<u8>,
    request: Option<Request>,
    cancellation: Option<watch::Receiver<bool>>,
    receipt: Option<oneshot::Sender<Result<(), Failure>>>,
    _admission: Option<Arc<OwnedSemaphorePermit>>,
}
impl Packet {
    pub fn untracked(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            request: None,
            cancellation: None,
            receipt: None,
            _admission: None,
        }
    }
    pub(crate) fn tracked(
        bytes: Vec<u8>,
        request: Request,
        admission: Arc<OwnedSemaphorePermit>,
        cancellation: watch::Receiver<bool>,
    ) -> (Self, Receipt) {
        let (sender, receiver) = oneshot::channel();
        (
            Self {
                bytes,
                request: Some(request),
                cancellation: Some(cancellation),
                receipt: Some(sender),
                _admission: Some(admission.clone()),
            },
            Receipt {
                receiver: Some(receiver),
                admission: Some(admission),
            },
        )
    }
    pub fn request(&self) -> Option<&Request> {
        self.request.as_ref()
    }
    /// Attach stream lifetime and original operation checks without allocating
    /// a per-segment receipt. TCP acknowledgment joins delivery at stream level.
    pub(crate) fn constrain(&mut self, request: Request, cancellation: watch::Receiver<bool>) {
        if self.request.is_none() {
            self.request = Some(request);
            self.cancellation = Some(cancellation);
        }
    }
    pub fn cancellation(&self) -> Option<&watch::Receiver<bool>> {
        self.cancellation.as_ref()
    }
    /// Only the native writer calls this after a full write or a known failure.
    pub fn complete(mut self, result: Result<(), Failure>) -> Result<(), Error> {
        match self.receipt.take() {
            Some(sender) => sender.send(result).map_err(|_| Error::OwnerLost),
            None => Ok(()),
        }
    }
    /// Discard receipt ownership without asserting delivery. A tracked packet's
    /// waiter observes uncertainty; use only for untracked controlled peers.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutputPacket([redacted])")
    }
}

#[must_use = "retain and resume cancelled waits until native delivery joins"]
pub struct Receipt {
    receiver: Option<oneshot::Receiver<Result<(), Failure>>>,
    admission: Option<Arc<OwnedSemaphorePermit>>,
}
impl Receipt {
    pub async fn wait(&mut self, mut observer: Request) -> Result<(), Error> {
        let receiver = self.receiver.as_mut().ok_or(Error::AlreadyJoined)?;
        let result = tokio::select! { biased;
            _=observer.cancellation.wait_for(|cancelled|*cancelled)=>return Err(Error::WaitCancelled),
            ()=sleep_until(observer.deadline)=>return Err(Error::WaitDeadline),
            result=receiver=>result.unwrap_or(Err(Failure::Uncertain)),
        };
        self.receiver.take();
        self.admission.take();
        result.map_err(Error::Delivery)
    }
}
impl fmt::Debug for Receipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PacketDelivery([redacted])")
    }
}
