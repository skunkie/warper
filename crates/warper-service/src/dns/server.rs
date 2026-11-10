// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Supervised DNS request work with output retained outside task lifetimes.

use std::{fmt, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::{
    sync::{Mutex, watch},
    task::JoinSet,
    time::{Instant, timeout_at},
};
use warper_core::transport::Request;
use warper_stack::host::{AcceptedDnsFlow, AcceptedStream, DnsOutputError};
use warper_stack::runtime::{delivery, udp_dns};

use super::{
    Limits as PacketLimits, LocalReply, Packet, QueryBudget,
    dispatch::{self, Dispatcher},
    output::{self, RoutedReply, UdpOutput},
    prepare::Prepared,
    routes::{self, Controller},
};
use super::{
    connection::{self, Completion as Frame, Connection},
    tcp_output::{self, TcpOutput},
};
use crate::linux::dns_routes::queue::Mailbox;

#[derive(Clone, Copy)]
pub struct Limits {
    pub requests: usize,
    pub request_timeout: Duration,
    pub cleanup_timeout: Duration,
    pub attempts: usize,
    pub grace: Duration,
    pub packet: PacketLimits,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    Full,
    Stopping,
    Expired,
    InvalidState,
    WorkerStopped,
    ShutdownDeadline,
    Packet(super::Error),
    Dispatch(dispatch::Error),
    Output(output::Error),
    Submission(udp_dns::Error),
    Delivery(delivery::Error),
    Routes(routes::Error),
    Framing(connection::Error),
    TcpOutput(tcp_output::Error),
    Acknowledgment(DnsOutputError),
    Io(std::io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS request worker: {self:?}")
    }
}
impl std::error::Error for Error {}

enum Pending {
    Routed(Box<UdpOutput>),
    Plain(delivery::Receipt),
    Tcp(Box<TcpOutput>),
}
struct Slot {
    active: bool,
    pending: Arc<Mutex<Option<Pending>>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestFailure {
    Dispatch(dispatch::Error),
    Preparation(output::Error),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub slot: usize,
    pub outcome: Result<Option<RequestFailure>, Error>,
}

#[must_use = "retain outside tasks through task join and native output cleanup"]
pub struct Workers {
    dispatcher: Arc<Dispatcher>,
    controller: Arc<Controller>,
    mailbox: Option<Mailbox>,
    limits: Limits,
    slots: Vec<Slot>,
    tasks: JoinSet<Completion>,
    cancellation: watch::Sender<bool>,
    stopping: bool,
    first_request_failure: Option<RequestFailure>,
    first_request_error: Option<Error>,
    shutdown_error: Option<Error>,
}
impl Workers {
    pub fn new(
        dispatcher: Arc<Dispatcher>,
        controller: Arc<Controller>,
        mailbox: Mailbox,
        limits: Limits,
    ) -> Result<Self, Error> {
        if !(1..=64).contains(&limits.requests)
            || Instant::now().checked_add(limits.grace).is_none()
            || limits.attempts == 0
            || limits.attempts > 65536
            || [limits.request_timeout, limits.cleanup_timeout]
                .iter()
                .any(|duration| duration.is_zero() || *duration > Duration::from_secs(30))
        {
            return Err(Error::InvalidLimits);
        }
        Ok(Self {
            dispatcher,
            controller,
            mailbox: Some(mailbox),
            limits,
            slots: (0..limits.requests)
                .map(|_| Slot {
                    active: false,
                    pending: Arc::new(Mutex::new(None)),
                })
                .collect(),
            tasks: JoinSet::new(),
            cancellation: watch::channel(false).0,
            stopping: false,
            first_request_failure: None,
            first_request_error: None,
            shutdown_error: None,
        })
    }

    pub fn admit_udp(&mut self, datagram: udp_dns::Datagram) -> Result<(), Error> {
        if self.stopping {
            return Err(Error::Stopping);
        }
        if self.controller.is_closed().map_err(Error::Routes)? {
            return Err(Error::Stopping);
        }
        let deadline = datagram
            .received_at()
            .checked_add(self.limits.request_timeout)
            .ok_or(Error::InvalidLimits)?;
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.active)
            .ok_or(Error::Full)?;
        let slot = &mut self.slots[index];
        slot.active = true;
        let pending = slot.pending.clone();
        let dispatcher = self.dispatcher.clone();
        let controller = self.controller.clone();
        let mailbox = self.mailbox.as_ref().ok_or(Error::Stopping)?.clone();
        let limits = self.limits;
        let operation = Request {
            deadline,
            cancellation: self.cancellation.subscribe(),
        };
        self.tasks.spawn(async move {
            let outcome = work(
                datagram, dispatcher, controller, mailbox, limits, operation, pending,
            )
            .await;
            Completion {
                slot: index,
                outcome,
            }
        });
        Ok(())
    }

    pub fn admit_tcp(&mut self, flow: AcceptedDnsFlow) -> Result<(), Error> {
        if self.stopping || *self.cancellation.borrow() {
            return Err(Error::Stopping);
        }
        if self.controller.is_closed().map_err(Error::Routes)? {
            return Err(Error::Stopping);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.active)
            .ok_or(Error::Full)?;
        let slot = &mut self.slots[index];
        slot.active = true;
        let pending = slot.pending.clone();
        let dispatcher = self.dispatcher.clone();
        let controller = self.controller.clone();
        let mailbox = self.mailbox.as_ref().ok_or(Error::Stopping)?.clone();
        let limits = self.limits;
        let cancellation = self.cancellation.subscribe();
        self.tasks.spawn(async move {
            let outcome = work_tcp(
                flow,
                dispatcher,
                controller,
                mailbox,
                limits,
                cancellation,
                pending,
            )
            .await;
            Completion {
                slot: index,
                outcome,
            }
        });
        Ok(())
    }

    pub async fn join_next(&mut self) -> Option<Result<Completion, Error>> {
        let joined = self.tasks.join_next().await?;
        match joined {
            Ok(completion) => {
                if let Err(error) = completion.outcome {
                    self.first_request_error.get_or_insert(error);
                }
                if let Ok(Some(failure)) = completion.outcome {
                    self.first_request_failure.get_or_insert(failure);
                }
                let slot = &mut self.slots[completion.slot];
                let mut pending = slot.pending.lock().await;
                if completion.outcome.is_ok() {
                    pending.take();
                }
                if pending.is_none() {
                    slot.active = false;
                } else {
                    drop(pending);
                    self.stop();
                }
                Some(Ok(completion))
            }
            Err(_) => {
                self.stop();
                Some(Err(Error::WorkerStopped))
            }
        }
    }

    pub fn stop(&mut self) {
        self.stopping = true;
        self.cancellation.send_replace(true);
        self.mailbox.take();
    }
    pub fn active(&self) -> usize {
        self.slots.iter().filter(|slot| slot.active).count()
    }
    pub fn stopping(&self) -> bool {
        self.stopping
    }

    pub fn first_request_failure(&self) -> Option<RequestFailure> {
        self.first_request_failure
    }
    pub fn first_request_error(&self) -> Option<Error> {
        self.first_request_error
    }
    pub fn shutdown_error(&self) -> Option<Error> {
        self.shutdown_error
    }
    pub async fn join(&mut self, deadline: Instant) -> Result<(), Error> {
        self.stop();
        let mut primary = None;
        while !self.tasks.is_empty() {
            match timeout_at(deadline, self.join_next()).await {
                Ok(Some(Err(error))) => {
                    primary.get_or_insert(error);
                }
                Ok(Some(Ok(completion))) => {
                    if let Err(error) = completion.outcome {
                        self.first_request_error.get_or_insert(error);
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    self.shutdown_error = Some(Error::ShutdownDeadline);
                    self.tasks.abort_all();
                    while let Some(result) = self.tasks.join_next().await {
                        match result {
                            Err(error) if !error.is_cancelled() => {
                                primary.get_or_insert(Error::WorkerStopped);
                            }
                            Ok(completion) => match completion.outcome {
                                Err(error) => {
                                    self.first_request_error.get_or_insert(error);
                                }
                                Ok(Some(failure)) => {
                                    self.first_request_failure.get_or_insert(failure);
                                }
                                Ok(None) => {}
                            },
                            Err(_) => {}
                        }
                    }
                    return Err(primary.unwrap_or(Error::ShutdownDeadline));
                }
            }
        }
        primary.map_or(Ok(()), Err)
    }

    /// Call only after the parent joins native packet I/O and destroys queued
    /// frames. This releases references; it asserts no native cleanup itself.
    pub async fn release_after_native_join(&mut self) -> Result<(), Error> {
        if !self.stopping || !self.tasks.is_empty() {
            return Err(Error::InvalidState);
        }
        for slot in &mut self.slots {
            slot.pending.lock().await.take();
            slot.active = false;
        }
        Ok(())
    }
}

async fn work(
    datagram: udp_dns::Datagram,
    dispatcher: Arc<Dispatcher>,
    controller: Arc<Controller>,
    mailbox: Mailbox,
    limits: Limits,
    operation: Request,
    pending: Arc<Mutex<Option<Pending>>>,
) -> Result<Option<RequestFailure>, Error> {
    let query = Packet::request(datagram.payload(), limits.packet).map_err(Error::Packet)?;
    let budget = QueryBudget::new(limits.attempts).map_err(|_| Error::InvalidLimits)?;
    let prepared = dispatcher.prepare(&query, operation.clone(), &budget).await;
    let mut request_failure = prepared
        .as_ref()
        .err()
        .copied()
        .map(RequestFailure::Dispatch);
    let mut datagram = Some(datagram);
    let mut slot = pending.lock().await;
    match prepared {
        Ok(Prepared::Upstream {
            packet,
            received_at,
            udp_payload_limit,
            reservation: Some(reservation),
        }) => {
            let reply = RoutedReply {
                packet: *packet,
                received_at,
                udp_payload_limit,
                reservation,
                grace: limits.grace,
            };
            match UdpOutput::begin_queued(
                controller,
                &mut datagram,
                reply,
                &mailbox,
                operation.clone(),
            ) {
                Ok(output) => *slot = Some(Pending::Routed(Box::new(output))),
                Err(error) => {
                    request_failure = Some(RequestFailure::Preparation(error));
                    let kind =
                        if matches!(error, output::Error::Packet(super::Error::ResourceLimit)) {
                            LocalReply::Truncated
                        } else {
                            LocalReply::ServFail
                        };
                    let wire = query.local_reply(kind).map_err(Error::Packet)?;
                    *slot = Some(Pending::Plain(
                        datagram
                            .take()
                            .ok_or(Error::InvalidState)?
                            .respond(&wire, operation.clone())
                            .map_err(Error::Submission)?,
                    ));
                }
            }
        }
        prepared => {
            let wire = match prepared {
                Ok(Prepared::Local(wire)) => wire,
                Ok(Prepared::Upstream {
                    mut packet,
                    received_at,
                    reservation: None,
                    udp_payload_limit,
                }) => {
                    packet
                        .age_response(
                            Instant::now()
                                .checked_duration_since(received_at)
                                .ok_or(Error::Expired)?,
                        )
                        .map_err(Error::Packet)?;
                    match packet.encode_limited(udp_payload_limit.min(udp_dns::MAX_PAYLOAD)) {
                        Ok(wire) => wire,
                        Err(super::Error::ResourceLimit) => query
                            .local_reply(LocalReply::Truncated)
                            .map_err(Error::Packet)?,
                        Err(error) => return Err(Error::Packet(error)),
                    }
                }
                Err(_) => query
                    .local_reply(LocalReply::ServFail)
                    .map_err(Error::Packet)?,
                Ok(Prepared::Upstream {
                    reservation: Some(_),
                    ..
                }) => return Err(Error::InvalidState),
            };
            *slot = Some(Pending::Plain(
                datagram
                    .take()
                    .ok_or(Error::InvalidState)?
                    .respond(&wire, operation)
                    .map_err(Error::Submission)?,
            ));
        }
    }
    let (observer_owner, cancellation) = watch::channel(false);
    let observer = Request {
        deadline: Instant::now() + limits.cleanup_timeout,
        cancellation,
    };
    let result = match slot.as_mut().ok_or(Error::InvalidState)? {
        Pending::Routed(output) => output.wait(observer).await.map_err(Error::Output),
        Pending::Plain(receipt) => receipt.wait(observer).await.map_err(Error::Delivery),
        Pending::Tcp(_) => Err(Error::InvalidState),
    };
    drop(observer_owner);
    result.map(|()| request_failure)
}

async fn work_tcp(
    flow: AcceptedDnsFlow,
    dispatcher: Arc<Dispatcher>,
    controller: Arc<Controller>,
    mailbox: Mailbox,
    limits: Limits,
    cancellation: watch::Receiver<bool>,
    pending: Arc<Mutex<Option<Pending>>>,
) -> Result<Option<RequestFailure>, Error> {
    let mut connection = Connection::new(flow.stream, limits.packet);
    let (observer_owner, _) = watch::channel(false);
    let observer = || Request {
        deadline: Instant::now() + limits.cleanup_timeout,
        cancellation: observer_owner.subscribe(),
    };
    let mut first_failure = None;
    loop {
        let operation = Request {
            deadline: Instant::now() + limits.request_timeout,
            cancellation: cancellation.clone(),
        };
        connection
            .begin_read(operation.clone())
            .map_err(Error::Framing)?;
        let query = match connection.wait(observer()).await.map_err(Error::Framing)? {
            Frame::Query(query) => query,
            Frame::End => {
                let mut stream = connection.into_inner();
                observer()
                    .run(async {
                        stream
                            .shutdown()
                            .await
                            .map_err(|error| warper_core::transport::Error::Io(error.kind()))
                    })
                    .await
                    .map_err(|error| match error {
                        warper_core::transport::Error::Io(kind) => Error::Io(kind),
                        other => Error::Dispatch(dispatch::Error::Request(other)),
                    })?;
                return Ok(first_failure);
            }
            Frame::Written => return Err(Error::InvalidState),
        };
        let budget = QueryBudget::new(limits.attempts).map_err(|_| Error::InvalidLimits)?;
        let prepared = dispatcher.prepare(&query, operation.clone(), &budget).await;
        match prepared {
            Ok(Prepared::Upstream {
                packet,
                received_at,
                reservation: Some(reservation),
                ..
            }) => {
                let mut slot = pending.lock().await;
                *slot = Some(Pending::Tcp(Box::new(
                    TcpOutput::begin_queued(
                        controller.clone(),
                        connection,
                        &query,
                        tcp_output::Reply {
                            packet: *packet,
                            received_at,
                            reservation,
                            grace: limits.grace,
                        },
                        &mailbox,
                        operation,
                    )
                    .map_err(Error::TcpOutput)?,
                )));
                let Some(Pending::Tcp(output)) = slot.as_mut() else {
                    return Err(Error::InvalidState);
                };
                output.wait(observer()).await.map_err(Error::TcpOutput)?;
                connection = output.take_connection().ok_or(Error::InvalidState)?;
                slot.take();
            }
            prepared => {
                let packet = match prepared {
                    Ok(Prepared::Local(wire)) => {
                        Packet::response(&wire, &query, limits.packet).map_err(Error::Packet)?
                    }
                    Ok(Prepared::Upstream {
                        mut packet,
                        received_at,
                        reservation: None,
                        ..
                    }) => {
                        packet
                            .age_response(
                                Instant::now()
                                    .checked_duration_since(received_at)
                                    .ok_or(Error::Expired)?,
                            )
                            .map_err(Error::Packet)?;
                        *packet
                    }
                    Err(error) => {
                        first_failure.get_or_insert(RequestFailure::Dispatch(error));
                        Packet::response(
                            &query
                                .local_reply(LocalReply::ServFail)
                                .map_err(Error::Packet)?,
                            &query,
                            limits.packet,
                        )
                        .map_err(Error::Packet)?
                    }
                    Ok(Prepared::Upstream {
                        reservation: Some(_),
                        ..
                    }) => return Err(Error::InvalidState),
                };
                write_plain(&mut connection, &packet, operation, observer()).await?;
            }
        }
    }
}

async fn write_plain(
    connection: &mut Connection<AcceptedStream>,
    packet: &Packet,
    operation: Request,
    observer: Request,
) -> Result<(), Error> {
    let control = connection
        .stream()
        .dns_output()
        .map_err(Error::Acknowledgment)?;
    control
        .begin(operation.clone())
        .map_err(Error::Acknowledgment)?;
    connection
        .begin_reply(packet, operation)
        .map_err(Error::Framing)?;
    if !matches!(
        connection
            .wait(observer.clone())
            .await
            .map_err(Error::Framing)?,
        Frame::Written
    ) {
        return Err(Error::InvalidState);
    }
    let mut receipt = control.receipt().map_err(Error::Acknowledgment)?;
    receipt.wait(observer).await.map_err(Error::Acknowledgment)
}
