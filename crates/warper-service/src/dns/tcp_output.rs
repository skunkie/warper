// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! A framed TCP reply retains routing through native commit and peer ACK.

use std::{fmt, sync::Arc, time::Duration};
use tokio::time::Instant;
use warper_core::{dns::lease, transport::Request};
use warper_stack::host::{AcceptedStream, DnsOutputControl, DnsOutputError, DnsOutputReceipt};

use super::{
    Packet,
    connection::{self, Completion, Connection},
    routes::{self, Controller},
};
use crate::linux::dns_routes::queue::{self, Mailbox};

pub struct Reply {
    pub packet: Packet,
    pub received_at: Instant,
    pub reservation: lease::Response,
    pub grace: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidTime,
    InvalidState,
    Packet(super::Error),
    Framing(connection::Error),
    Commit(queue::Error),
    Output(DnsOutputError),
    Metadata(routes::Error),
    WaitCancelled,
    WaitDeadline,
    AlreadyJoined,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "routed DNS TCP output: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub primary: Error,
    pub closure: Option<routes::Error>,
}
enum State {
    Committing,
    Writing,
    Acknowledging,
    Delivered,
    Closing,
    Finished,
}

struct PendingReply {
    packet: Packet,
    received_at: Instant,
    grace: Duration,
}

#[must_use = "retain routing through acknowledgment or joined connection/native cleanup"]
pub struct TcpOutput {
    controller: Arc<Controller>,
    connection: Option<Connection<AcceptedStream>>,
    control: Option<DnsOutputControl>,
    commit: Option<queue::Receipt>,
    reply: Option<PendingReply>,
    operation: Option<Request>,
    output: Option<lease::Output>,
    acknowledgment: Option<DnsOutputReceipt>,
    retention: Duration,
    state: State,
    failure: Option<Failure>,
}
impl TcpOutput {
    /// Validate the reply before native admission. The supervisor must retain
    /// and drive the mailbox owner alongside this output.
    pub fn begin_queued(
        controller: Arc<Controller>,
        connection: &mut Option<Connection<AcceptedStream>>,
        query: &Packet,
        mut reply: Reply,
        mailbox: &Mailbox,
        operation: Request,
    ) -> Result<Self, Error> {
        let borrowed = connection.as_ref().ok_or(Error::InvalidState)?;
        validate(&controller, borrowed, query, &mut reply, &operation)?;
        let control = borrowed.stream().dns_output().map_err(Error::Output)?;
        control.check_begin(&operation).map_err(Error::Output)?;
        let Reply {
            packet,
            received_at,
            reservation,
            grace,
        } = reply;
        let owned = connection.take().ok_or(Error::InvalidState)?;
        let commit = match mailbox.submit(reservation, operation.clone()) {
            Ok(commit) => commit,
            Err(error) => {
                *connection = Some(owned);
                return Err(Error::Commit(error));
            }
        };
        // The mailbox owns the reservation until its receipt joins. Keep only
        // the immutable response data here; no positive bytes have been written.
        Ok(Self {
            controller,
            connection: Some(owned),
            control: Some(control),
            commit: Some(commit),
            reply: Some(PendingReply {
                packet,
                received_at,
                grace,
            }),
            operation: Some(operation),
            output: None,
            acknowledgment: None,
            retention: Duration::ZERO,
            state: State::Committing,
            failure: None,
        })
    }

    pub async fn wait(&mut self, observer: Request) -> Result<(), Error> {
        loop {
            check_wait(&observer)?;
            match self.state {
                State::Committing => {
                    let result = self
                        .commit
                        .as_mut()
                        .ok_or(Error::InvalidState)?
                        .wait(observer.clone())
                        .await;
                    let reservation = match result {
                        Err(queue::Error::WaitCancelled) => return Err(Error::WaitCancelled),
                        Err(queue::Error::WaitDeadline) => return Err(Error::WaitDeadline),
                        Err(error) => {
                            self.commit.take();
                            self.fail(Error::Commit(error));
                            continue;
                        }
                        Ok(reservation) => reservation,
                    };
                    self.commit.take();
                    let mut reply = self.reply.take().ok_or(Error::InvalidState)?;
                    let prepared = (|| {
                        let elapsed = Instant::now()
                            .checked_duration_since(reply.received_at)
                            .ok_or(Error::InvalidTime)?;
                        self.retention = reply
                            .grace
                            .max(reply.packet.age_response(elapsed).map_err(Error::Packet)?);
                        self.output = Some(
                            self.controller
                                .begin_output(reservation)
                                .map_err(Error::Metadata)?,
                        );
                        self.control
                            .as_ref()
                            .ok_or(Error::InvalidState)?
                            .begin(self.operation.clone().ok_or(Error::InvalidState)?)
                            .map_err(Error::Output)?;
                        self.connection
                            .as_mut()
                            .ok_or(Error::InvalidState)?
                            .begin_reply(
                                &reply.packet,
                                self.operation.clone().ok_or(Error::InvalidState)?,
                            )
                            .map_err(Error::Framing)
                    })();
                    if let Err(error) = prepared {
                        self.fail(error);
                    } else {
                        self.state = State::Writing;
                    }
                }
                State::Writing => {
                    let result = self
                        .connection
                        .as_mut()
                        .ok_or(Error::InvalidState)?
                        .wait(observer.clone())
                        .await;
                    match result {
                        Err(connection::Error::WaitCancelled) => return Err(Error::WaitCancelled),
                        Err(connection::Error::WaitDeadline) => return Err(Error::WaitDeadline),
                        Ok(Completion::Written) => {
                            match self.control.as_ref().ok_or(Error::InvalidState)?.receipt() {
                                Ok(receipt) => {
                                    self.acknowledgment = Some(receipt);
                                    self.state = State::Acknowledging;
                                }
                                Err(error) => self.fail(Error::Output(error)),
                            }
                        }
                        Ok(_) => self.fail(Error::InvalidState),
                        Err(error) => self.fail(Error::Framing(error)),
                    }
                }
                State::Acknowledging => {
                    let result = self
                        .acknowledgment
                        .as_mut()
                        .ok_or(Error::InvalidState)?
                        .wait(observer.clone())
                        .await;
                    match result {
                        Err(DnsOutputError::WaitCancelled) => return Err(Error::WaitCancelled),
                        Err(DnsOutputError::WaitDeadline) => return Err(Error::WaitDeadline),
                        Ok(()) => {
                            self.acknowledgment.take();
                            self.state = State::Delivered;
                        }
                        Err(error) => {
                            self.acknowledgment.take();
                            self.fail(Error::Output(error));
                        }
                    }
                }
                State::Delivered => {
                    match self.controller.complete_output(
                        self.output.as_mut().ok_or(Error::InvalidState)?,
                        self.retention,
                    ) {
                        Ok(()) => {
                            self.output.take();
                            self.control.take();
                            self.operation.take();
                            self.state = State::Finished;
                            return Ok(());
                        }
                        Err(routes::Error::Busy) => tokio::task::yield_now().await,
                        Err(error) => self.fail(Error::Metadata(error)),
                    }
                }
                State::Closing => {
                    match self.controller.close() {
                        Err(routes::Error::Busy) => {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        Err(error) => {
                            if let Some(failure) = &mut self.failure {
                                failure.closure = Some(error);
                            }
                        }
                        Ok(()) => {}
                    }
                    self.state = State::Finished;
                    return Err(self.failure.ok_or(Error::InvalidState)?.primary);
                }
                State::Finished => return Err(Error::AlreadyJoined),
            }
        }
    }

    pub fn has_pending(&self) -> bool {
        !matches!(self.state, State::Finished)
    }

    pub fn failure(&self) -> Option<Failure> {
        self.failure
    }

    pub fn take_connection(&mut self) -> Option<Connection<AcceptedStream>> {
        if matches!(self.state, State::Finished) && self.failure.is_none() {
            self.connection.take()
        } else {
            None
        }
    }

    fn fail(&mut self, primary: Error) {
        // Drop the stream immediately to invalidate queued TCP payloads. Keep
        // the output guard and control until the supervisor joins native I/O.
        self.connection.take();
        self.reply.take();
        let closure = match self.controller.close() {
            Ok(()) | Err(routes::Error::Busy) => None,
            Err(error) => Some(error),
        };
        self.failure = Some(Failure { primary, closure });
        self.state = State::Closing;
    }
}

fn validate(
    controller: &Controller,
    connection: &Connection<AcceptedStream>,
    query: &Packet,
    reply: &mut Reply,
    operation: &Request,
) -> Result<(), Error> {
    if query.is_response()
        || !reply.packet.is_response()
        || query.id() != reply.packet.id()
        || query.question() != reply.packet.question()
    {
        return Err(Error::Packet(super::Error::MismatchedResponse));
    }
    connection
        .check_reply(&reply.packet, operation)
        .map_err(Error::Framing)?;
    Instant::now()
        .checked_duration_since(reply.received_at)
        .ok_or(Error::InvalidTime)?;
    let retention = reply.grace.max(
        reply
            .packet
            .age_response(Duration::ZERO)
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
    Ok(())
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

#[cfg(test)]
mod tests;
