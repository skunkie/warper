// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Routed UDP output whose route ownership survives cancelled observation.

use std::{fmt, sync::Arc, time::Duration};
use tokio::time::Instant;
use warper_core::{dns::lease, transport::Request};
use warper_stack::runtime::{delivery, udp_dns};

use super::{
    Error as PacketError, Packet,
    routes::{self, Controller},
};

pub struct RoutedReply {
    pub packet: Packet,
    pub received_at: Instant,
    pub udp_payload_limit: usize,
    pub reservation: lease::Response,
    pub grace: Duration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidTime,
    Packet(PacketError),
    Metadata(routes::Error),
    Submission(udp_dns::Error),
    WaitCancelled,
    WaitDeadline,
    AlreadyJoined,
    Delivery(delivery::Failure),
    Receipt(delivery::Error),
    #[cfg(target_os = "linux")]
    Commit(crate::linux::dns_routes::queue::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidTime => "InvalidConfig: routed DNS output time is invalid",
            Self::Packet(_) => "DnsProtocol: routed DNS output preparation failed",
            Self::Metadata(_) => "SystemConfiguration: routed DNS output metadata failed",
            Self::Submission(_) => "NativeIo: routed DNS output submission failed",
            Self::WaitCancelled => "Cancelled: routed DNS output observation ended",
            Self::WaitDeadline => "Timeout: routed DNS output observation ended",
            Self::AlreadyJoined => "Conflict: routed DNS output was already joined",
            Self::Delivery(delivery::Failure::Cancelled) => {
                "Cancelled: routed DNS output was not delivered"
            }
            Self::Delivery(delivery::Failure::Deadline) => {
                "Timeout: routed DNS output was not delivered"
            }
            Self::Delivery(delivery::Failure::Uncertain) => {
                "NativeUncertain: routed DNS output requires session cleanup"
            }
            Self::Receipt(_) => "WorkerFailed: routed DNS delivery receipt failed",
            #[cfg(target_os = "linux")]
            Self::Commit(_) => "SystemConfiguration: routed DNS publication failed",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub primary: Error,
    pub closure: Option<routes::Error>,
}
enum State {
    #[cfg(target_os = "linux")]
    Committing,
    Waiting,
    Delivered,
    Closing,
    Finished,
}

#[cfg(target_os = "linux")]
struct Queued {
    receipt: crate::linux::dns_routes::queue::Receipt,
    packet: Box<Packet>,
    received_at: Instant,
    udp_payload_limit: usize,
    grace: Duration,
    operation: Request,
}

#[must_use = "retain routed output through native join and metadata completion or session cleanup"]
pub struct UdpOutput {
    controller: Arc<Controller>,
    output: Option<lease::Output>,
    receipt: Option<delivery::Receipt>,
    retention: Duration,
    state: State,
    failure: Option<Failure>,
    #[cfg(target_os = "linux")]
    queued: Option<Queued>,
    #[cfg(target_os = "linux")]
    unsubmitted: Option<udp_dns::Datagram>,
}
impl UdpOutput {
    pub fn begin(
        controller: Arc<Controller>,
        datagram: &mut Option<udp_dns::Datagram>,
        mut reply: RoutedReply,
        operation: Request,
    ) -> Result<Self, Error> {
        let (wire, retention) = prepare_reply(&controller, datagram, &mut reply, &operation, true)?;
        let output = controller
            .begin_output(reply.reservation)
            .map_err(Error::Metadata)?;
        // Failure here is definitively before queue admission and Native I/O.
        let receipt = datagram
            .take()
            .ok_or(Error::AlreadyJoined)?
            .respond(&wire, operation)
            .map_err(Error::Submission)?;
        Ok(Self {
            controller,
            output: Some(output),
            receipt: Some(receipt),
            retention,
            state: State::Waiting,
            failure: None,
            #[cfg(target_os = "linux")]
            queued: None,
            #[cfg(target_os = "linux")]
            unsubmitted: None,
        })
    }

    /// Retain one request through native route commit, packet delivery and
    /// grace publication. The caller must also retain and run the native driver.
    #[cfg(target_os = "linux")]
    pub fn begin_queued(
        controller: Arc<Controller>,
        datagram: &mut Option<udp_dns::Datagram>,
        mut reply: RoutedReply,
        mailbox: &crate::linux::dns_routes::queue::Mailbox,
        operation: Request,
    ) -> Result<Self, Error> {
        // Reject invalid/oversized output before native route mutation. TTLs
        // are aged against the original observation only after its ACK joins.
        prepare_reply(&controller, datagram, &mut reply, &operation, false)?;
        let RoutedReply {
            packet,
            received_at,
            udp_payload_limit,
            reservation,
            grace,
        } = reply;
        let receipt = mailbox
            .submit(reservation, operation.clone())
            .map_err(Error::Commit)?;
        Ok(Self {
            controller,
            output: None,
            receipt: None,
            retention: Duration::ZERO,
            state: State::Committing,
            failure: None,
            queued: Some(Queued {
                receipt,
                packet: Box::new(packet),
                received_at,
                udp_payload_limit,
                grace,
                operation,
            }),
            unsubmitted: datagram.take(),
        })
    }

    pub async fn wait(&mut self, observer: Request) -> Result<(), Error> {
        loop {
            check_wait(&observer)?;
            match self.state {
                #[cfg(target_os = "linux")]
                State::Committing => {
                    use crate::linux::dns_routes::queue::Error as CommitError;
                    let result = self
                        .queued
                        .as_mut()
                        .ok_or(Error::AlreadyJoined)?
                        .receipt
                        .wait(observer.clone())
                        .await;
                    let reservation = match result {
                        Err(CommitError::WaitCancelled) => return Err(Error::WaitCancelled),
                        Err(CommitError::WaitDeadline) => return Err(Error::WaitDeadline),
                        Err(error) => {
                            self.queued.take();
                            self.state = State::Finished;
                            return Err(Error::Commit(error));
                        }
                        Ok(reservation) => reservation,
                    };
                    let queued = self.queued.take().ok_or(Error::AlreadyJoined)?;
                    let reply = RoutedReply {
                        packet: *queued.packet,
                        received_at: queued.received_at,
                        udp_payload_limit: queued.udp_payload_limit,
                        reservation,
                        grace: queued.grace,
                    };
                    match Self::begin(
                        self.controller.clone(),
                        &mut self.unsubmitted,
                        reply,
                        queued.operation,
                    ) {
                        Ok(output) => *self = output,
                        Err(error) => {
                            self.state = State::Finished;
                            return Err(error);
                        }
                    }
                }
                State::Waiting => {
                    let result = self
                        .receipt
                        .as_mut()
                        .ok_or(Error::AlreadyJoined)?
                        .wait(observer.clone())
                        .await;
                    match result {
                        Err(delivery::Error::WaitCancelled) => return Err(Error::WaitCancelled),
                        Err(delivery::Error::WaitDeadline) => return Err(Error::WaitDeadline),
                        Ok(()) => {
                            self.receipt.take();
                            self.state = State::Delivered;
                        }
                        Err(delivery::Error::Delivery(
                            failure @ (delivery::Failure::Cancelled | delivery::Failure::Deadline),
                        )) => {
                            self.receipt.take();
                            self.output.take();
                            self.state = State::Finished;
                            return Err(Error::Delivery(failure));
                        }
                        Err(delivery::Error::Delivery(delivery::Failure::Uncertain)) => {
                            self.receipt.take();
                            self.fail(Error::Delivery(delivery::Failure::Uncertain));
                        }
                        Err(error) => {
                            self.receipt.take();
                            self.fail(Error::Receipt(error));
                        }
                    }
                }
                State::Delivered => {
                    let output = self.output.as_mut().ok_or(Error::AlreadyJoined)?;
                    match self.controller.complete_output(output, self.retention) {
                        Ok(()) => {
                            self.output.take();
                            self.state = State::Finished;
                            return Ok(());
                        }
                        Err(routes::Error::Busy) => tokio::task::yield_now().await,
                        Err(error) => self.fail(Error::Metadata(error)),
                    }
                }
                State::Closing => {
                    match self.controller.close() {
                        Ok(()) => {}
                        Err(routes::Error::Busy) => {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        Err(error) => {
                            if let Some(failure) = &mut self.failure {
                                failure.closure = Some(error);
                            }
                        }
                    }
                    self.state = State::Finished;
                    return Err(self.failure.ok_or(Error::AlreadyJoined)?.primary);
                }
                State::Finished => return Err(Error::AlreadyJoined),
            }
        }
    }
    pub fn failure(&self) -> Option<Failure> {
        self.failure
    }
    pub fn has_pending(&self) -> bool {
        !matches!(self.state, State::Finished)
    }

    /// A failed, joined commit or pre-output rejection may still permit a
    /// bounded SERVFAIL/TC reply under the caller's original request.
    #[cfg(target_os = "linux")]
    pub fn take_unsubmitted_datagram(&mut self) -> Option<udp_dns::Datagram> {
        if matches!(self.state, State::Finished) {
            self.unsubmitted.take()
        } else {
            None
        }
    }

    fn fail(&mut self, primary: Error) {
        let closure = match self.controller.close() {
            Ok(()) | Err(routes::Error::Busy) => None,
            Err(error) => Some(error),
        };
        self.failure = Some(Failure { primary, closure });
        self.state = State::Closing;
    }
}

impl fmt::Debug for UdpOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RoutedUdpOutput([redacted])")
    }
}

fn prepare_reply(
    controller: &Controller,
    datagram: &Option<udp_dns::Datagram>,
    reply: &mut RoutedReply,
    operation: &Request,
    update_ttl: bool,
) -> Result<(Vec<u8>, Duration), Error> {
    if !(12..=udp_dns::MAX_PAYLOAD).contains(&reply.udp_payload_limit) {
        return Err(Error::Packet(PacketError::InvalidLimits));
    }
    reply
        .packet
        .correlate_request(datagram.as_ref().ok_or(Error::AlreadyJoined)?.payload())
        .map_err(Error::Packet)?;
    let elapsed = Instant::now()
        .checked_duration_since(reply.received_at)
        .ok_or(Error::InvalidTime)?;
    let retention = reply.grace.max(
        reply
            .packet
            .age_response(if update_ttl { elapsed } else { Duration::ZERO })
            .map_err(Error::Packet)?,
    );
    if operation.deadline.checked_add(retention).is_none()
        || controller
            .elapsed(operation.deadline)
            .checked_add(retention)
            .is_none()
    {
        return Err(Error::InvalidTime);
    }
    let wire = reply
        .packet
        .encode_limited(reply.udp_payload_limit.min(reply.packet.limit_bytes()))
        .map_err(Error::Packet)?;
    Ok((wire, retention))
}

fn check_wait(request: &Request) -> Result<(), Error> {
    if *request.cancellation.borrow() || request.cancellation.has_changed().is_err() {
        return Err(Error::WaitCancelled);
    }
    if Instant::now() >= request.deadline {
        return Err(Error::WaitDeadline);
    }
    Ok(())
}
