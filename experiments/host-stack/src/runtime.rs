// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Experimental wake-driven combined host adapter owner; no kernel I/O.

use std::{
    fmt,
    future::pending,
    net::SocketAddr,
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

use crate::{
    adapter::{self, AcceptedFlow, AdmissionError, BackendId, HostAdapter},
    packet_peer::MTU,
    reassembly::{self, Outcome, Reassembler},
    udp_adapter::{self, Association, UdpAdapter},
};

const OUTPUT_BATCH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCapacity,
    PacketTooLarge,
    QueueFull,
    IngressClosed,
    EgressClosed,
    ShutdownOwnerLost,
    InvalidClock,
    Pmtu,
    Tcp(AdmissionError),
    Udp(udp_adapter::Error),
    Reassembly(reassembly::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "host runtime experiment: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Default, Debug)]
pub struct Report {
    pub turns: u64,
    pub timer_wakes: u64,
    pub admitted: u64,
    pub rejected: u64,
    pub emitted_tcp: u64,
    pub emitted_udp: u64,
    pub tcp_timed_out: u64,
    pub udp_timed_out: u64,
    pub udp_application_closed: u64,
    pub discarded_packets: u64,
    pub reassembled: u64,
    pub fragment_timeouts: u64,
    pub pmtu_feedback: u64,
    pub pmtu_reductions: u64,
    pub pmtu_deferred: u64,
    pub pmtu_expired: u64,
    pub pmtu_unsupported: u64,
}

#[derive(Debug)]
pub struct Failure {
    pub cause: Error,
    pub report: Box<Report>,
    pub pmtu: Option<adapter::PmtuError>,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (admitted={}, rejected={})",
            self.cause, self.report.admitted, self.report.rejected
        )
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.pmtu
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone)]
pub struct Ingress {
    sender: mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

impl Ingress {
    pub fn try_inject(&self, packet: &[u8]) -> Result<(), Error> {
        if packet.len() > self.mtu {
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
    pub udp: mpsc::Receiver<Association>,
    pub shutdown: oneshot::Sender<()>,
}

pub struct Egress {
    receiver: mpsc::Receiver<Vec<u8>>,
    stopped: Arc<AtomicBool>,
}

impl Egress {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
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

    pub(crate) fn receiver_try_recv(&mut self) -> Result<Vec<u8>, mpsc::error::TryRecvError> {
        if self.stopped.load(Ordering::Acquire) {
            self.discard();
        }
        self.receiver.try_recv()
    }

    fn discard(&mut self) {
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
    }
}

struct ApplicationWake(Notify);

impl Wake for ApplicationWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

pub struct Runtime {
    tcp: HostAdapter,
    udp: UdpAdapter,
    reassembly: Reassembler,
    input: mpsc::Receiver<Vec<u8>>,
    pending: Option<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    shutdown: oneshot::Receiver<()>,
    application_wake: Arc<ApplicationWake>,
    stopped: Arc<AtomicBool>,
    udp_first: bool,
    report: Report,
    pmtu_failure: Option<adapter::PmtuError>,
}

impl Runtime {
    pub fn new(
        tcp_limits: adapter::Limits,
        udp_limits: udp_adapter::Limits,
        select_backend: fn(SocketAddr) -> Option<BackendId>,
        capacity: usize,
    ) -> Result<(Self, Channels), Error> {
        Self::build(tcp_limits, udp_limits, select_backend, capacity, None)
    }

    pub fn with_pmtu(
        tcp_limits: adapter::Limits,
        udp_limits: udp_adapter::Limits,
        select_backend: fn(SocketAddr) -> Option<BackendId>,
        capacity: usize,
        pmtu: adapter::PmtuConfig,
    ) -> Result<(Self, Channels), Error> {
        Self::build(tcp_limits, udp_limits, select_backend, capacity, Some(pmtu))
    }

    fn build(
        tcp_limits: adapter::Limits,
        udp_limits: udp_adapter::Limits,
        select_backend: fn(SocketAddr) -> Option<BackendId>,
        capacity: usize,
        pmtu: Option<adapter::PmtuConfig>,
    ) -> Result<(Self, Channels), Error> {
        if !(1..=64).contains(&capacity) {
            return Err(Error::InvalidCapacity);
        }
        let mtu = pmtu.as_ref().map_or(MTU, |config| config.link_mtu);
        let (mut tcp, accepted_tcp) =
            HostAdapter::with_mtu(tcp_limits, select_backend, mtu).map_err(Error::Tcp)?;
        if let Some(config) = pmtu {
            tcp.enable_pmtu(config).map_err(Error::Tcp)?;
        }
        let (udp, accepted_udp) =
            UdpAdapter::new(udp_limits, select_backend).map_err(Error::Udp)?;
        let reassembly =
            Reassembler::new(reassembly::Limits::default()).map_err(Error::Reassembly)?;
        let (input, receiver) = mpsc::channel(capacity);
        let (output, packets) = mpsc::channel(capacity);
        let (shutdown, stopping) = oneshot::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        Ok((
            Self {
                tcp,
                udp,
                reassembly,
                input: receiver,
                pending: None,
                output,
                shutdown: stopping,
                application_wake: Arc::new(ApplicationWake(Notify::new())),
                stopped: stopped.clone(),
                udp_first: false,
                report: Report::default(),
                pmtu_failure: None,
            },
            Channels {
                ingress: Ingress { sender: input, mtu },
                packets: Egress {
                    receiver: packets,
                    stopped,
                },
                tcp: accepted_tcp,
                udp: accepted_udp,
                shutdown,
            },
        ))
    }

    pub async fn run(mut self) -> Result<Report, Failure> {
        let outcome = self.drive().await;
        self.input.close();
        if self.pending.take().is_some() {
            self.report.discarded_packets = self.report.discarded_packets.saturating_add(1);
        }
        while self.input.try_recv().is_ok() {
            self.report.discarded_packets = self.report.discarded_packets.saturating_add(1);
        }
        // Local cleanup cannot fail. Closing adapter senders publishes terminal
        // reasons before waking application receivers. No task is detached here.
        self.report.tcp_timed_out = self.tcp.statistics().timed_out;
        self.report.udp_timed_out = self.udp.statistics().timed_out;
        self.report.udp_application_closed = self.udp.statistics().application_closed;
        self.report.reassembled = self.reassembly.statistics().completed;
        self.report.fragment_timeouts = self.reassembly.statistics().timed_out;
        let statistics = self.tcp.statistics();
        self.report.pmtu_feedback = statistics.pmtu_feedback;
        self.report.pmtu_reductions = statistics.pmtu_reductions;
        self.report.pmtu_deferred = statistics.pmtu_deferred;
        self.report.pmtu_expired = statistics.pmtu_expired;
        self.report.pmtu_unsupported = statistics.pmtu_unsupported;
        self.tcp.cancel();
        self.udp.cancel();
        self.reassembly.cancel();
        self.stopped.store(true, Ordering::Release);
        let report = std::mem::take(&mut self.report);
        match outcome {
            Ok(()) => Ok(report),
            Err(cause) => Err(Failure {
                cause,
                report: Box::new(report),
                pmtu: self.pmtu_failure.take(),
            }),
        }
    }

    async fn drive(&mut self) -> Result<(), Error> {
        let origin = Instant::now();
        let waker = Waker::from(self.application_wake.clone());
        let output = self.output.clone();
        loop {
            // A queued stop wins before any further adapter or output work.
            match self.shutdown.try_recv() {
                Ok(()) => return Ok(()),
                Err(oneshot::error::TryRecvError::Closed) => return Err(Error::ShutdownOwnerLost),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            let now = origin.elapsed();
            self.reassembly.advance(now).map_err(Error::Reassembly)?;
            if let Err(error) = self.tcp.poll_pmtu(now) {
                self.pmtu_failure = Some(error);
                return Err(Error::Pmtu);
            }
            {
                let mut cx = Context::from_waker(&waker);
                self.tcp.poll_io(&mut cx, now).map_err(Error::Tcp)?;
                self.udp.poll_io(&mut cx, now).map_err(Error::Udp)?;
            }
            // Input may have waited through a long idle period. Admit only
            // after every adapter clock has advanced to the wake timestamp.
            if let Some(packet) = self.pending.take() {
                self.admit(&packet, now)?;
                self.application_wake.0.notify_one();
            }
            self.report.turns = self.report.turns.saturating_add(1);
            self.drain_output();
            let blocked = self.output.capacity() == 0;
            let next = self
                .tcp
                .next_deadline(!blocked)
                .into_iter()
                .chain(self.udp.next_deadline(!blocked))
                .chain(self.reassembly.next_deadline())
                .min();
            let deadline = next
                .map(|elapsed| origin.checked_add(elapsed).ok_or(Error::InvalidClock))
                .transpose()?;
            // Every ready branch returns to one bounded turn. Tokio's select
            // varies packet/application/timer priority; shutdown is checked first.
            tokio::select! {
                result = &mut self.shutdown => return result.map_err(|_| Error::ShutdownOwnerLost),
                _ = output.closed() => return Err(Error::EgressClosed),
                permit = output.reserve(), if blocked => {
                    drop(permit.map_err(|_| Error::EgressClosed)?);
                }
                packet = self.input.recv() => {
                    self.pending = Some(packet.ok_or(Error::IngressClosed)?);
                }
                _ = self.application_wake.0.notified() => {}
                _ = async {
                    match deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => pending().await,
                    }
                } => self.report.timer_wakes = self.report.timer_wakes.saturating_add(1),
            }
        }
    }

    fn drain_output(&mut self) {
        for _ in 0..OUTPUT_BATCH {
            let Ok(permit) = self.output.try_reserve() else {
                break;
            };
            let udp = self.udp.has_packet() && (self.udp_first || !self.tcp.has_packet());
            let packet = if udp {
                self.udp.take_packet()
            } else {
                self.tcp.take_packet()
            };
            let Some(packet) = packet else { break };
            permit.send(packet);
            if udp {
                self.report.emitted_udp = self.report.emitted_udp.saturating_add(1);
            } else {
                self.report.emitted_tcp = self.report.emitted_tcp.saturating_add(1);
            }
            self.udp_first = !udp;
        }
        // More output can remain after the per-turn budget even with channel
        // capacity available. Continue cooperatively instead of stranding it.
        if self.output.capacity() > 0 && (self.tcp.has_packet() || self.udp.has_packet()) {
            self.application_wake.0.notify_one();
        }
    }

    fn admit(&mut self, packet: &[u8], now: std::time::Duration) -> Result<(), Error> {
        let complete;
        let plain_tcp = match packet.first().map(|byte| byte >> 4) {
            Some(4) if packet.len() >= 20 => {
                packet[0] == 0x45
                    && packet[9] == 6
                    && u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len()
                    && u16::from_be_bytes([packet[6], packet[7]]) & 0xbfff == 0
            }
            Some(6) if packet.len() >= 40 => {
                packet[6] == 6
                    && u16::from_be_bytes([packet[4], packet[5]]) as usize + 40 == packet.len()
            }
            _ => false,
        };
        let packet = match if plain_tcp {
            Ok(Outcome::Pass)
        } else {
            self.reassembly.accept(packet, now)
        } {
            Ok(Outcome::Pass) => packet,
            Ok(Outcome::Pending) => return Ok(()),
            Ok(Outcome::Complete(bytes)) => {
                complete = bytes;
                complete.as_slice()
            }
            Err(
                error @ (reassembly::Error::Cancelled
                | reassembly::Error::InvalidTime
                | reassembly::Error::InvalidLimits),
            ) => return Err(Error::Reassembly(error)),
            Err(_) => {
                self.report.rejected = self.report.rejected.saturating_add(1);
                return Ok(());
            }
        };
        let protocol = match packet.first().map(|byte| byte >> 4) {
            Some(4) if packet.len() >= 20 => packet[9],
            Some(6) if packet.len() >= 40 => packet[6],
            _ => 0,
        };
        let admitted = match protocol {
            6 => match self.tcp.inject(packet) {
                Ok(_) => true,
                Err(
                    error @ (AdmissionError::Cancelled
                    | AdmissionError::InvalidLimits
                    | AdmissionError::InvalidTime),
                ) => return Err(Error::Tcp(error)),
                Err(_) => false,
            },
            1 | 58 => self.tcp.receive_pmtu(packet).map_err(Error::Tcp)?,
            17 => match self.udp.inject(packet) {
                Ok(_) => true,
                Err(
                    error @ (udp_adapter::Error::Cancelled
                    | udp_adapter::Error::InvalidLimits
                    | udp_adapter::Error::InvalidTime),
                ) => return Err(Error::Udp(error)),
                Err(_) => false,
            },
            _ => false,
        };
        if admitted {
            self.report.admitted = self.report.admitted.saturating_add(1);
        } else {
            self.report.rejected = self.report.rejected.saturating_add(1);
        }
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        // Also covers cancellation by the caller dropping/aborting this future.
        self.tcp.cancel();
        self.udp.cancel();
        self.reassembly.cancel();
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
