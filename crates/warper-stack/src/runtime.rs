// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Wake-driven host packet owner. Kernel I/O and flow relays belong to the service.

use crate::{
    Seed,
    host::{AcceptedFlow, AdmissionError, HostAdapter, Limits, MTU, Statistics},
};
use std::{
    fmt,
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Wake, Waker},
};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::{Instant, sleep_until},
};
use warper_core::routing::{FlowSelector, Policy};

mod admission;
pub mod delivery;
mod publication;
pub mod udp_dns;
pub use admission::{AdmissionControl, Quiescence, Snapshot as AdmissionSnapshot};
pub use publication::Publication;

const OUTPUT_BATCH: usize = 8;
const MAX_QUEUE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCapacity,
    PacketTooLarge,
    QueueFull,
    IngressClosed,
    EgressClosed,
    ConsumerClosed,
    ShutdownOwnerLost,
    InvalidClock,
    ControlBusy,
    ControlClosed,
    ControlOwnerLost,
    WaitCancelled,
    WaitDeadline,
    AlreadyJoined,
    Host(AdmissionError),
    Dns(udp_dns::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host TCP runtime: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Default, Debug)]
pub struct Report {
    pub turns: u64,
    pub timer_wakes: u64,
    pub admitted_packets: u64,
    pub rejected_packets: u64,
    pub unsupported_packets: u64,
    pub emitted_packets: u64,
    pub discarded_ingress: u64,
    pub retained_streams: usize,
    pub tcp: Statistics,
    pub udp_dns: udp_dns::Statistics,
}
#[derive(Debug)]
pub struct Failure {
    pub cause: Error,
    pub report: Box<Report>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cause)
    }
}
impl std::error::Error for Failure {}

#[derive(Clone)]
pub struct Ingress {
    sender: mpsc::Sender<Vec<u8>>,
}
impl Ingress {
    pub fn try_inject(&self, packet: &[u8]) -> Result<(), Error> {
        if packet.len() > MTU {
            return Err(Error::PacketTooLarge);
        }
        let permit = self.sender.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Error::QueueFull,
            mpsc::error::TrySendError::Closed(_) => Error::IngressClosed,
        })?;
        permit.send(packet.to_vec());
        Ok(())
    }
}

pub struct Channels {
    pub ingress: Ingress,
    pub packets: Egress,
    pub tcp: mpsc::Receiver<AcceptedFlow>,
    pub udp_dns: Option<udp_dns::Endpoint>,
    pub admission: AdmissionControl,
    pub publication: Publication,
    pub shutdown: oneshot::Sender<()>,
}
pub struct Egress {
    receiver: mpsc::Receiver<delivery::Packet>,
    stopped: Arc<AtomicBool>,
}
impl Egress {
    pub async fn recv(&mut self) -> Option<delivery::Packet> {
        if self.stopped.load(Ordering::Acquire) {
            self.discard();
            return None;
        }
        let packet = self.receiver.recv().await;
        if self.stopped.load(Ordering::Acquire) {
            self.discard();
            None
        } else {
            packet
        }
    }
    /// Discard at most one queue capacity without closing packet ownership.
    /// The supervisor separately joins in-flight I/O and handles later resets.
    pub fn discard_pending(&mut self) -> usize {
        let mut discarded = 0;
        for _ in 0..self.receiver.max_capacity() {
            if self.receiver.try_recv().is_err() {
                break;
            }
            discarded += 1;
        }
        discarded
    }
    fn discard(&mut self) {
        self.receiver.close();
        self.discard_pending();
    }
}

struct ApplicationWake(Arc<Notify>);
impl Wake for ApplicationWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

pub struct Runtime {
    host: HostAdapter,
    input: mpsc::Receiver<Vec<u8>>,
    pending: Option<Vec<u8>>,
    output: mpsc::Sender<delivery::Packet>,
    dns: Option<udp_dns::Driver>,
    dns_turn: bool,
    commands: mpsc::Receiver<admission::Command>,
    shutdown: oneshot::Receiver<()>,
    wake: Arc<ApplicationWake>,
    stopped: Arc<AtomicBool>,
    quiescent: Arc<AtomicBool>,
    buffer_capacity: usize,
    report: Report,
}
impl Runtime {
    pub fn new(
        limits: Limits,
        policy: Arc<Policy>,
        capacity: usize,
        seed: Seed,
    ) -> Result<(Self, Channels), Error> {
        Self::with_selector(limits, policy, capacity, seed)
    }

    pub fn with_selector(
        limits: Limits,
        policy: Arc<dyn FlowSelector>,
        capacity: usize,
        seed: Seed,
    ) -> Result<(Self, Channels), Error> {
        Self::build(limits, policy, capacity, seed, None)
    }

    pub fn with_udp_dns(
        limits: Limits,
        policy: Arc<dyn FlowSelector>,
        capacity: usize,
        seed: Seed,
        dns: udp_dns::Config,
    ) -> Result<(Self, Channels), Error> {
        Self::build(limits, policy, capacity, seed, Some(dns))
    }

    fn build(
        limits: Limits,
        policy: Arc<dyn FlowSelector>,
        capacity: usize,
        seed: Seed,
        dns: Option<udp_dns::Config>,
    ) -> Result<(Self, Channels), Error> {
        let mut buffer_capacity = Self::required_buffer_capacity(limits, capacity)?;
        let notify = Arc::new(Notify::new());
        let (dns, udp_dns) = if let Some(config) = dns {
            buffer_capacity += config.required_buffer_capacity().map_err(Error::Dns)?;
            let (driver, endpoint) =
                udp_dns::Driver::new(config, notify.clone()).map_err(Error::Dns)?;
            (Some(driver), Some(endpoint))
        } else {
            (None, None)
        };
        let (host, tcp) =
            HostAdapter::with_selector(limits, policy.clone(), seed).map_err(Error::Host)?;
        let (input, receiver) = mpsc::channel(capacity);
        let (output, packets) = mpsc::channel(capacity);
        let (admission, commands) = AdmissionControl::new();
        let (shutdown, stopping) = oneshot::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let quiescent = Arc::new(AtomicBool::new(false));
        let publication = Publication::new(
            policy,
            input.clone(),
            host.lifetime_pool(),
            limits.flows,
            quiescent.clone(),
            stopped.clone(),
        );
        Ok((
            Self {
                host,
                input: receiver,
                pending: None,
                output,
                dns,
                dns_turn: true,
                commands,
                shutdown: stopping,
                wake: Arc::new(ApplicationWake(notify)),
                stopped: stopped.clone(),
                quiescent,
                buffer_capacity,
                report: Report::default(),
            },
            Channels {
                ingress: Ingress { sender: input },
                packets: Egress {
                    receiver: packets,
                    stopped,
                },
                tcp,
                udp_dns,
                admission,
                publication,
                shutdown,
            },
        ))
    }

    /// Payload-buffer reservation, including both packet queues and pending
    /// ingress. Caller adds kernel I/O, relay buffers and allocator/socket state.
    pub fn required_buffer_capacity(limits: Limits, capacity: usize) -> Result<usize, Error> {
        limits.validate().map_err(Error::Host)?;
        if !(1..=MAX_QUEUE).contains(&capacity) {
            return Err(Error::InvalidCapacity);
        }
        Ok(limits.flows * crate::device::BYTE_CAPACITY * 4
            + crate::device::PACKET_CAPACITY * MTU * 2
            + (capacity * 2 + 1) * MTU)
    }
    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    /// This future is the sole owner; the service must retain/join its task.
    pub async fn run(mut self) -> Result<Report, Failure> {
        let outcome = self.drive().await;
        self.input.close();
        if self.pending.take().is_some() {
            self.report.discarded_ingress += 1;
        }
        while self.input.try_recv().is_ok() {
            self.report.discarded_ingress += 1;
        }
        self.report.tcp = *self.host.statistics();
        if let Some(dns) = &mut self.dns {
            dns.cancel();
            self.report.udp_dns = dns.statistics;
        }
        self.host.cancel();
        self.report.retained_streams = self.host.retained_flows();
        self.stopped.store(true, Ordering::Release);
        let report = std::mem::take(&mut self.report);
        match outcome {
            Ok(()) => Ok(report),
            Err(cause) => Err(Failure {
                cause,
                report: Box::new(report),
            }),
        }
    }

    async fn drive(&mut self) -> Result<(), Error> {
        let origin = Instant::now();
        let waker = Waker::from(self.wake.clone());
        let output = self.output.clone();
        let accepted = self.host.accept_sender().ok_or(Error::ConsumerClosed)?;
        let dns_consumer = self.dns.as_ref().map(udp_dns::Driver::consumer);
        let mut commands_open = true;
        loop {
            match self.shutdown.try_recv() {
                Ok(()) => return Ok(()),
                Err(oneshot::error::TryRecvError::Closed) => return Err(Error::ShutdownOwnerLost),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            if commands_open {
                match self.commands.try_recv() {
                    Ok(command) => self.apply_admission(command)?,
                    Err(mpsc::error::TryRecvError::Empty) => {}
                    Err(mpsc::error::TryRecvError::Disconnected) => commands_open = false,
                }
            }
            let now = origin.elapsed();
            {
                let mut cx = Context::from_waker(&waker);
                self.host.poll_io(&mut cx, now).map_err(Error::Host)?;
            }
            // Advance timers before admitting input that may have waited through
            // an arbitrarily long idle period.
            if let Some(packet) = self.pending.take() {
                let admitted = match &mut self.dns {
                    Some(dns) => match dns.inject(&packet) {
                        Ok(true) => Ok(()),
                        Ok(false) => self.host.inject(&packet).map(|_| ()),
                        Err(error) => Err(error),
                    },
                    None => self.host.inject(&packet).map(|_| ()),
                };
                match admitted {
                    Ok(_) => {
                        self.report.admitted_packets =
                            self.report.admitted_packets.saturating_add(1)
                    }
                    Err(
                        error @ (AdmissionError::Cancelled
                        | AdmissionError::InvalidLimits
                        | AdmissionError::InvalidTime
                        | AdmissionError::SelectionUnavailable),
                    ) => return Err(Error::Host(error)),
                    Err(error) => {
                        self.report.rejected_packets =
                            self.report.rejected_packets.saturating_add(1);
                        if error == AdmissionError::UnsupportedProtocol {
                            self.report.unsupported_packets =
                                self.report.unsupported_packets.saturating_add(1);
                        }
                    }
                }
                self.wake.0.notify_one();
            }
            self.report.turns = self.report.turns.saturating_add(1);
            self.drain_output();
            let blocked = self.output.capacity() == 0;
            let deadline = self
                .host
                .next_deadline(!blocked)
                .map(|elapsed| origin.checked_add(elapsed).ok_or(Error::InvalidClock))
                .transpose()?;
            tokio::select! {
                result=&mut self.shutdown=>return result.map_err(|_|Error::ShutdownOwnerLost),
                command=self.commands.recv(),if commands_open=>{
                    match command {Some(command)=>self.apply_admission(command)?,None=>commands_open=false}
                },
                ()=output.closed()=>return Err(Error::EgressClosed),
                ()=accepted.closed()=>return Err(Error::ConsumerClosed),
                ()=async {match &dns_consumer {Some(sender)=>sender.closed().await,None=>pending().await}}=>return Err(Error::ConsumerClosed),
                permit=output.reserve(),if blocked=>{drop(permit.map_err(|_|Error::EgressClosed)?);},
                packet=self.input.recv()=>{self.pending=Some(packet.ok_or(Error::IngressClosed)?);},
                ()=self.wake.0.notified()=>{},
                ()=async {match deadline {Some(deadline)=>sleep_until(deadline).await,None=>pending().await}}=>{
                    self.report.timer_wakes=self.report.timer_wakes.saturating_add(1);
                },
            }
        }
    }
    fn apply_admission(&mut self, command: admission::Command) -> Result<(), Error> {
        if let Some(dns) = &mut self.dns {
            if command.cancel_flows {
                dns.cancel();
            } else {
                dns.quiesce();
            }
        }
        if command.cancel_flows {
            self.host.cancel_flows().map_err(Error::Host)?;
            if self.pending.take().is_some() {
                self.report.discarded_ingress = self.report.discarded_ingress.saturating_add(1);
            }
            for _ in 0..self.input.max_capacity() {
                if self.input.try_recv().is_err() {
                    break;
                }
                self.report.discarded_ingress = self.report.discarded_ingress.saturating_add(1);
            }
        } else {
            self.host.quiesce().map_err(Error::Host)?;
        }
        self.quiescent.store(true, Ordering::Release);
        command.complete(AdmissionSnapshot {
            active_flows: self.host.active_flows(),
            retained_streams: self.host.retained_flows(),
        });
        Ok(())
    }
    fn drain_output(&mut self) {
        for _ in 0..OUTPUT_BATCH {
            let Ok(permit) = self.output.try_reserve() else {
                break;
            };
            self.dns_turn = !self.dns_turn;
            let packet = if self.dns_turn {
                self.dns
                    .as_mut()
                    .and_then(udp_dns::Driver::take_reply)
                    .or_else(|| self.host.take_packet().map(delivery::Packet::untracked))
            } else {
                self.host
                    .take_packet()
                    .map(delivery::Packet::untracked)
                    .or_else(|| self.dns.as_mut().and_then(udp_dns::Driver::take_reply))
            };
            let Some(packet) = packet else {
                break;
            };
            permit.send(packet);
            self.report.emitted_packets = self.report.emitted_packets.saturating_add(1);
        }
        if self.output.capacity() > 0
            && (self.host.has_packet()
                || self.dns.as_ref().is_some_and(udp_dns::Driver::has_replies))
        {
            self.wake.0.notify_one();
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(dns) = &mut self.dns {
            dns.cancel();
        }
        self.host.cancel();
    }
}

#[cfg(test)]
mod tests;
