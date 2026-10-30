// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Owned, bounded PMTU feedback for the host TCP runner.

use std::{fmt, io, net::IpAddr, time::Duration};

use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollIngressSingleResult},
    socket::tcp,
    time::Instant,
    wire::HardwareAddress,
};

use super::{FlowMetadata, HostAdapter, Termination, tcp_metadata};
use crate::{packet_peer::PacketDevice, pmtu_feedback::Tracker};

const HISTORY: usize = 16;
const LIFETIME: Duration = Duration::from_secs(3);
const RETRY: Duration = Duration::from_millis(10);

pub struct Config {
    pub link_mtu: usize,
    pub reporter: fn(FlowMetadata) -> Option<IpAddr>,
    pub seed: Box<dyn FnMut() -> io::Result<u64> + Send>,
}

#[derive(Debug)]
pub enum Error {
    InvalidTime,
    Cancelled,
    Seed(io::Error),
    Rebuild(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTime => formatter.write_str("invalid PMTU clock"),
            Self::Cancelled => formatter.write_str("PMTU owner cancelled"),
            Self::Seed(error) => write!(formatter, "PMTU entropy: {:?}", error.kind()),
            Self::Rebuild(error) => write!(formatter, "PMTU sizing: {:?}", error.kind()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Seed(error) | Self::Rebuild(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) struct Owner {
    pub config: Config,
    pub mtu: usize,
    retry_at: Duration,
}

impl Owner {
    pub fn new(config: Config) -> Self {
        let mtu = config.link_mtu;
        Self {
            config,
            mtu,
            retry_at: Duration::ZERO,
        }
    }
}

pub(super) struct Flow {
    reporter: IpAddr,
    history: [Tracker; HISTORY],
    next: usize,
    pending: Option<(usize, Duration, usize)>,
}

impl Flow {
    pub fn new(reporter: IpAddr) -> Self {
        Self {
            reporter,
            history: std::array::from_fn(|_| Tracker::default()),
            next: 0,
            pending: None,
        }
    }

    fn record(&mut self, packet: &[u8], now: Duration) {
        let mut candidate = Tracker::default();
        if candidate
            .reserve(packet, self.reporter, now, LIFETIME)
            .is_ok()
        {
            for offset in 0..HISTORY {
                let index = (self.next + offset) % HISTORY;
                if self.history[index]
                    .next_deadline()
                    .is_none_or(|expires| now >= expires)
                {
                    self.history[index] = candidate;
                    self.next = (index + 1) % HISTORY;
                    return;
                }
            }
            // All live hints remain protected until accepted ACK or expiry.
            // Untracked output is still owned by the TCP send buffer.
        }
    }

    fn feedback(
        &mut self,
        packet: &[u8],
        now: Duration,
    ) -> Result<bool, crate::pmtu_feedback::Error> {
        for (index, tracker) in self.history.iter_mut().enumerate() {
            match tracker.reduction(packet, now) {
                Ok(Some(mtu)) => {
                    let expires = tracker
                        .next_deadline()
                        .ok_or(crate::pmtu_feedback::Error::Expired)?;
                    self.pending = Some(match self.pending {
                        Some((previous, deadline, previous_index)) if previous <= mtu => {
                            (previous, deadline, previous_index)
                        }
                        _ => (mtu, expires, index),
                    });
                    return Ok(true);
                }
                Err(crate::pmtu_feedback::Error::Expired) | Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    }
}

impl HostAdapter {
    pub fn enable_pmtu(&mut self, config: Config) -> Result<(), super::AdmissionError> {
        if self.cancelled {
            return Err(super::AdmissionError::Cancelled);
        }
        if self.active_flows() != 0 || config.link_mtu != self.device_mtu() || self.pmtu.is_some() {
            return Err(super::AdmissionError::InvalidLimits);
        }
        self.pmtu = Some(Owner::new(config));
        Ok(())
    }

    pub fn receive_pmtu(&mut self, packet: &[u8]) -> Result<bool, super::AdmissionError> {
        if self.cancelled {
            return Err(super::AdmissionError::Cancelled);
        }
        for slot in &mut self.slots {
            let Some(flow) = &mut slot.flow else { continue };
            if !live(flow, self.sockets.get::<tcp::Socket>(slot.socket)) {
                continue;
            }
            let Some(pmtu) = &mut flow.pmtu else { continue };
            match pmtu.feedback(packet, self.now) {
                Ok(true) => {
                    self.statistics.pmtu_feedback = self.statistics.pmtu_feedback.saturating_add(1);
                    return Ok(true);
                }
                Ok(false) => {}
                Err(crate::pmtu_feedback::Error::UnsupportedMtu) => {
                    flow.lifetime.termination.store(
                        Termination::Unsupported as u8,
                        std::sync::atomic::Ordering::Release,
                    );
                    self.sockets.get_mut::<tcp::Socket>(slot.socket).abort();
                    flow.pmtu = None;
                    self.statistics.pmtu_unsupported =
                        self.statistics.pmtu_unsupported.saturating_add(1);
                    return Ok(true);
                }
                Err(_) => return Err(super::AdmissionError::InvalidTime),
            }
        }
        Ok(false)
    }

    pub fn poll_pmtu(&mut self, now: Duration) -> Result<(), Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if now < self.now || now.as_millis() > crate::MAX_CLOCK_MILLIS {
            return Err(Error::InvalidTime);
        }
        self.now = now;
        let Some(owner) = &mut self.pmtu else {
            return Ok(());
        };
        let mut minimum = owner.mtu;
        for slot in &mut self.slots {
            let Some(flow) = &mut slot.flow else { continue };
            let live = live(flow, self.sockets.get::<tcp::Socket>(slot.socket))
                && now - flow.created < self.limits.max_age
                && now - flow.progress < self.limits.idle_timeout;
            let Some(pmtu) = &mut flow.pmtu else { continue };
            if let Some((mtu, expires, _)) = pmtu.pending {
                if !live || now >= expires {
                    pmtu.pending = None;
                    self.statistics.pmtu_expired = self.statistics.pmtu_expired.saturating_add(1);
                } else if mtu >= owner.mtu {
                    pmtu.pending = None;
                } else {
                    minimum = minimum.min(mtu);
                }
            }
        }
        if minimum == owner.mtu || now < owner.retry_at {
            return Ok(());
        }
        owner.retry_at = now.checked_add(RETRY).ok_or(Error::InvalidTime)?;
        if !self.device.outgoing.is_empty() {
            self.statistics.pmtu_deferred = self.statistics.pmtu_deferred.saturating_add(1);
            return Ok(());
        }
        let seed = match (owner.config.seed)() {
            Ok(seed) => seed,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.statistics.pmtu_deferred = self.statistics.pmtu_deferred.saturating_add(1);
                return Ok(());
            }
            Err(error) => return Err(Error::Seed(error)),
        };
        rebuild_egress(&mut self.interface, minimum, now.as_millis() as i64, seed)
            .map_err(Error::Rebuild)?;
        owner.mtu = minimum;
        self.statistics.pmtu_reductions = self.statistics.pmtu_reductions.saturating_add(1);
        for flow in self.slots.iter_mut().filter_map(|slot| slot.flow.as_mut()) {
            if let Some(pmtu) = &mut flow.pmtu {
                pmtu.pending = None;
                for tracker in &mut pmtu.history {
                    tracker.commit();
                }
            }
        }
        Ok(())
    }

    pub(super) fn record_pmtu(&mut self, packet: &[u8]) {
        let Ok((source, destination, _)) = tcp_metadata(packet) else {
            return;
        };
        for flow in self.slots.iter_mut().filter_map(|slot| slot.flow.as_mut()) {
            if flow.metadata.source == destination && flow.metadata.destination == source {
                if let Some(pmtu) = &mut flow.pmtu {
                    pmtu.record(packet, self.now);
                }
                break;
            }
        }
    }

    pub(super) fn pmtu_deadline(&self, transport_ready: bool) -> Option<Duration> {
        let owner = self.pmtu.as_ref()?;
        self.slots
            .iter()
            .filter_map(|slot| {
                let (_, expires, _) = slot.flow.as_ref()?.pmtu.as_ref()?.pending?;
                Some(if transport_ready {
                    expires.min(owner.retry_at.max(self.now))
                } else {
                    expires
                })
            })
            .min()
    }

    pub(super) fn pmtu_pending(&self) -> bool {
        self.slots.iter().any(|slot| {
            slot.flow
                .as_ref()
                .and_then(|flow| flow.pmtu.as_ref())
                .is_some_and(|pmtu| pmtu.pending.is_some())
        })
    }

    pub(super) fn poll_with_pmtu(&mut self, timestamp: i64) -> Result<(), super::AdmissionError> {
        let instant = Instant::from_millis(timestamp);
        self.interface.poll_maintenance(instant);
        for _ in 0..crate::packet_peer::PACKET_CAPACITY {
            // Observe one packet, then verify its ACK actually advanced this
            // socket's send queue before retiring any feedback reservation.
            let acknowledgement = self.device.incoming.front().and_then(|packet| {
                let (source, destination, _) = tcp_metadata(packet).ok()?;
                let header = if packet[0] >> 4 == 6 {
                    40
                } else {
                    usize::from(packet[0] & 15) * 4
                };
                let tcp = smoltcp::wire::TcpPacket::new_checked(&packet[header..]).ok()?;
                if !tcp.ack() {
                    return None;
                }
                let index = self.slots.iter().position(|slot| {
                    slot.flow.as_ref().is_some_and(|flow| {
                        flow.metadata.source == source && flow.metadata.destination == destination
                    })
                })?;
                Some((
                    index,
                    tcp.ack_number().0 as u32,
                    self.sockets
                        .get::<tcp::Socket>(self.slots[index].socket)
                        .send_queue(),
                    self.sockets
                        .get::<tcp::Socket>(self.slots[index].socket)
                        .state(),
                ))
            });
            if self
                .interface
                .poll_ingress_single(instant, &mut self.device, &mut self.sockets)
                == PollIngressSingleResult::None
            {
                break;
            }
            if let Some((index, sequence, before, previous_state)) = acknowledgement {
                let slot = &mut self.slots[index];
                let socket = self.sockets.get::<tcp::Socket>(slot.socket);
                let fin_acknowledged = matches!(
                    (previous_state, socket.state()),
                    (
                        tcp::State::FinWait1,
                        tcp::State::FinWait2 | tcp::State::TimeWait
                    ) | (tcp::State::Closing, tcp::State::TimeWait)
                        | (tcp::State::LastAck, tcp::State::Closed)
                );
                if (socket.send_queue() < before || fin_acknowledged)
                    && let Some(flow) = &mut slot.flow
                    && let Some(pmtu) = &mut flow.pmtu
                {
                    for tracker in &mut pmtu.history {
                        // The stack accepted this exact packet, not a
                        // later/larger ACK merely sharing the tuple.
                        let retired = tracker.acknowledge(
                            flow.metadata.destination,
                            flow.metadata.source,
                            sequence,
                            self.now,
                        );
                        match retired {
                            Ok(()) | Err(crate::pmtu_feedback::Error::Expired) => {}
                            Err(error) => return Err(super::AdmissionError::Pmtu(error)),
                        }
                    }
                    if pmtu.pending.is_some_and(|(_, _, tracked)| {
                        pmtu.history[tracked].next_deadline().is_none()
                    }) {
                        pmtu.pending = None;
                    }
                }
            }
        }
        if !self.pmtu_pending() {
            self.interface
                .poll_egress(instant, &mut self.device, &mut self.sockets);
        }
        Ok(())
    }

    fn device_mtu(&self) -> usize {
        smoltcp::phy::Device::capabilities(&self.device).max_transmission_unit
    }
}

fn live(flow: &super::FlowState, socket: &tcp::Socket<'_>) -> bool {
    let reason = flow
        .lifetime
        .termination
        .load(std::sync::atomic::Ordering::Acquire);
    flow.pending.is_none()
        && socket.state() != tcp::State::Closed
        && (reason == Termination::Running as u8
            || (reason == Termination::ApplicationClosed as u8 && flow.network_eof))
}

/// Replace only cached egress capabilities. The owning link device, its ingress
/// MTU and both packet queues remain untouched. Socket sets live in the caller.
fn rebuild_egress(
    original: &mut Interface,
    mtu: usize,
    now: i64,
    random_seed: u64,
) -> io::Result<()> {
    let mut sizing = PacketDevice::with_mtu(mtu)?;
    let mut config = InterfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = random_seed;
    let mut replacement = Interface::new(config, &mut sizing, Instant::from_millis(now));
    replacement.update_ip_addrs(|entries| {
        for address in original.ip_addrs() {
            entries
                .push(*address)
                .expect("identical fixed interface address capacity");
        }
    });
    original.routes_mut().update(|entries| {
        replacement
            .routes_mut()
            .update(|target| *target = entries.clone());
    });
    replacement.set_any_ip(original.any_ip());
    *original = replacement;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Waker},
    };

    use smoltcp::{
        phy::Device,
        wire::{Icmpv4Packet, Icmpv6Packet, Ipv4Packet, Ipv6Packet, TcpPacket},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        accepted_probe::{select_backend, source},
        adapter::{AcceptedFlow, Limits},
        packet_peer::Peer,
    };

    async fn outstanding(
        ipv6: bool,
        seed: Box<dyn FnMut() -> io::Result<u64> + Send>,
    ) -> (HostAdapter, AcceptedFlow, Peer, Vec<u8>) {
        let (mut host, mut accepted) =
            HostAdapter::with_mtu(Limits::default(), select_backend, 1500).unwrap();
        host.enable_pmtu(Config {
            link_mtu: 1500,
            reporter: |metadata| Some(metadata.source.ip()),
            seed,
        })
        .unwrap();
        let client = source(ipv6, 2).unwrap();
        let destination = std::net::SocketAddr::new(source(ipv6, 91).unwrap().ip(), 9100);
        let mut peer = Peer::with_mtu(client.ip(), client.port(), 1500).unwrap();
        peer.sockets
            .get_mut::<tcp::Socket>(peer.tcp)
            .connect(peer.interface.context(), destination, client)
            .unwrap();
        let mut flow = None;
        for step in 0..100 {
            peer.poll(step);
            while let Some(packet) = peer.device.outgoing.pop_front() {
                host.inject(&packet).unwrap();
            }
            host.poll_io(
                &mut Context::from_waker(Waker::noop()),
                Duration::from_millis(step as u64),
            )
            .unwrap();
            while let Some(packet) = host.take_packet() {
                peer.device.inject(packet).unwrap();
            }
            if let Ok(accepted) = accepted.try_recv() {
                flow = Some(accepted);
                break;
            }
            tokio::task::yield_now().await;
        }
        let mut flow = flow.expect("controlled handshake");
        flow.stream.write_all(&[0x61; 8192]).await.unwrap();
        for step in 100..1000 {
            peer.poll(step);
            while let Some(packet) = peer.device.outgoing.pop_front() {
                host.inject(&packet).unwrap();
            }
            host.poll_io(
                &mut Context::from_waker(Waker::noop()),
                Duration::from_millis(step as u64),
            )
            .unwrap();
            while let Some(packet) = host.take_packet() {
                if packet.len() > 1400 {
                    return (host, flow, peer, packet);
                }
                peer.device.inject(packet).unwrap();
            }
            tokio::task::yield_now().await;
        }
        panic!("no oversized owned TCP output");
    }

    fn refill_report(packet: &mut [u8], ipv6: bool) {
        if ipv6 {
            let ip = Ipv6Packet::new_checked(&*packet).unwrap();
            let (source, destination) = (ip.src_addr(), ip.dst_addr());
            Icmpv6Packet::new_unchecked(&mut packet[40..]).fill_checksum(&source, &destination);
        } else {
            Ipv4Packet::new_unchecked(&mut *packet).fill_checksum();
            Icmpv4Packet::new_unchecked(&mut packet[20..]).fill_checksum();
        }
    }

    #[test]
    fn missing_or_invalid_reporter_rejects_admission_before_publishing_a_flow() {
        struct Case {
            name: &'static str,
            reporter: fn(FlowMetadata) -> Option<IpAddr>,
        }
        for case in [
            Case {
                name: "missing",
                reporter: |_| None,
            },
            Case {
                name: "wrong_family",
                reporter: |_| Some(std::net::Ipv6Addr::LOCALHOST.into()),
            },
            Case {
                name: "unspecified",
                reporter: |_| Some(std::net::Ipv4Addr::UNSPECIFIED.into()),
            },
            Case {
                name: "multicast",
                reporter: |_| Some(std::net::Ipv4Addr::new(224, 0, 0, 1).into()),
            },
        ] {
            let (mut host, mut accepted) =
                HostAdapter::with_mtu(Limits::default(), select_backend, 1500).unwrap();
            host.enable_pmtu(Config {
                link_mtu: 1500,
                reporter: case.reporter,
                seed: Box::new(|| Ok(1)),
            })
            .unwrap();
            let client = source(false, 2).unwrap();
            let mut peer = Peer::with_mtu(client.ip(), client.port(), 1500).unwrap();
            peer.sockets
                .get_mut::<tcp::Socket>(peer.tcp)
                .connect(
                    peer.interface.context(),
                    std::net::SocketAddr::new(source(false, 91).unwrap().ip(), 9100),
                    client,
                )
                .unwrap();
            peer.poll(0);
            let syn = peer.device.outgoing.pop_front().unwrap();
            assert_eq!(
                host.inject(&syn),
                Err(super::super::AdmissionError::Pmtu(
                    crate::pmtu_feedback::Error::InvalidReporter
                )),
                "{}",
                case.name
            );
            assert_eq!(host.active_flows(), 0, "{}", case.name);
            assert_eq!(
                host.lifetimes.available_permits(),
                Limits::default().flows,
                "{}",
                case.name
            );
            assert!(
                matches!(
                    accepted.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "{}",
                case.name
            );
        }
    }

    #[tokio::test]
    async fn invalid_reports_preserve_history_and_do_not_request_entropy() {
        for ipv6 in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let source_calls = calls.clone();
            let (mut host, _flow, _peer, quote) = outstanding(
                ipv6,
                Box::new(move || {
                    source_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(3)
                }),
            )
            .await;
            let report = crate::pmtu_fixture::too_big(&quote, ipv6, 1280).unwrap();
            let mut corrupted = report.clone();
            corrupted[if ipv6 { 42 } else { 22 }] ^= 1;
            assert_eq!(host.receive_pmtu(&corrupted), Ok(false));
            let mut foreign = report.clone();
            foreign[if ipv6 { 8 } else { 12 }] ^= 1;
            refill_report(&mut foreign, ipv6);
            assert_eq!(host.receive_pmtu(&foreign), Ok(false));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(host.receive_pmtu(&report), Ok(true));
            assert_eq!(host.statistics().pmtu_feedback, 1);
        }
    }

    #[tokio::test]
    async fn busy_output_and_transient_seed_retry_preserve_queues_and_ingress_mtu() {
        for ipv6 in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let source_calls = calls.clone();
            let (mut host, _flow, _peer, quote) = outstanding(
                ipv6,
                Box::new(move || {
                    if source_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(io::ErrorKind::WouldBlock.into())
                    } else {
                        Ok(7)
                    }
                }),
            )
            .await;
            let report = crate::pmtu_fixture::too_big(&quote, ipv6, 1280).unwrap();
            assert_eq!(host.receive_pmtu(&report), Ok(true));
            // The duplicate remains a network-owned packet, not application replay.
            host.device.outgoing.push_back(quote);
            let queued = host.device.outgoing.clone();
            let send_queues: Vec<_> = host
                .slots
                .iter()
                .map(|slot| host.sockets.get::<tcp::Socket>(slot.socket).send_queue())
                .collect();
            let now = host.now;
            host.poll_pmtu(now).unwrap();
            assert_eq!(host.device.outgoing, queued);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            while host.take_packet().is_some() {}
            host.poll_pmtu(now + RETRY).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            host.poll_pmtu(now + RETRY + Duration::from_millis(9))
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            host.poll_pmtu(now + RETRY * 2).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(host.statistics().pmtu_reductions, 1);
            assert_eq!(
                host.device.capabilities().max_transmission_unit,
                1500,
                "path sizing must not shrink link ingress"
            );
            assert_eq!(
                host.slots
                    .iter()
                    .map(|slot| host.sockets.get::<tcp::Socket>(slot.socket).send_queue())
                    .collect::<Vec<_>>(),
                send_queues
            );
        }
    }

    #[tokio::test]
    async fn expiry_and_retirement_cancel_pending_changes_without_seed_work() {
        for retired in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let source_calls = calls.clone();
            let (mut host, flow, _peer, quote) = outstanding(
                false,
                Box::new(move || {
                    source_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(7)
                }),
            )
            .await;
            let report = crate::pmtu_fixture::too_big(&quote, false, 1280).unwrap();
            host.receive_pmtu(&report).unwrap();
            let now = host.now;
            if retired {
                drop(flow);
                host.poll_pmtu(now).unwrap();
            } else {
                host.poll_pmtu(now + LIFETIME).unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(host.statistics().pmtu_reductions, 0);
            assert!(!host.pmtu_pending());
            host.cancel();
            assert_eq!(
                host.enable_pmtu(Config {
                    link_mtu: 1280,
                    reporter: |metadata| Some(metadata.source.ip()),
                    seed: Box::new(|| Ok(1)),
                }),
                Err(super::super::AdmissionError::Cancelled)
            );
            assert!(matches!(
                host.poll_pmtu(now + LIFETIME),
                Err(Error::Cancelled)
            ));
            assert_eq!(
                host.receive_pmtu(&report),
                Err(super::super::AdmissionError::Cancelled)
            );
        }
    }

    #[tokio::test]
    async fn flow_deadlines_win_over_pending_feedback_before_sizing() {
        for idle in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let source_calls = calls.clone();
            let (mut host, mut flow, _peer, quote) = outstanding(
                false,
                Box::new(move || {
                    source_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(9)
                }),
            )
            .await;
            while host.take_packet().is_some() {}
            let report = crate::pmtu_fixture::too_big(&quote, false, 1280).unwrap();
            assert_eq!(host.receive_pmtu(&report), Ok(true));
            let now = host.now;
            let active = host
                .slots
                .iter()
                .find_map(|slot| slot.flow.as_ref())
                .unwrap();
            if idle {
                host.limits.idle_timeout = now - active.progress + Duration::from_millis(1);
            } else {
                host.limits.max_age = now - active.created + Duration::from_millis(1);
            }
            let expired = now + Duration::from_millis(1);
            host.poll_pmtu(expired).unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "expired flows cannot request a sizing seed"
            );
            assert_eq!(host.statistics().pmtu_reductions, 0);
            assert!(!host.pmtu_pending());
            host.poll_io(&mut Context::from_waker(Waker::noop()), expired)
                .unwrap();
            assert_eq!(host.active_flows(), 0);
            assert_eq!(
                flow.stream.read(&mut [0]).await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }

    #[tokio::test]
    async fn permanent_seed_failure_retains_the_original_cause() {
        let (mut host, _flow, _peer, quote) = outstanding(
            false,
            Box::new(|| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic entropy refusal",
                ))
            }),
        )
        .await;
        while host.take_packet().is_some() {}
        let report = crate::pmtu_fixture::too_big(&quote, false, 1280).unwrap();
        host.receive_pmtu(&report).unwrap();
        let error = host.poll_pmtu(host.now).unwrap_err();
        assert!(
            matches!(&error, Error::Seed(source) if source.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "synthetic entropy refusal"
        );
        assert_eq!(host.statistics().pmtu_reductions, 0);
    }

    #[tokio::test]
    async fn only_an_ack_accepted_by_the_stack_retires_feedback() {
        for ipv6 in [false, true] {
            let (mut host, _flow, mut peer, quote) = outstanding(ipv6, Box::new(|| Ok(1))).await;
            while host.take_packet().is_some() {}
            peer.sockets
                .get_mut::<tcp::Socket>(peer.tcp)
                .set_ack_delay(None);
            peer.device.inject(quote.clone()).unwrap();
            let now = host.now;
            peer.poll(now.as_millis() as i64 + 20);
            let acknowledgement = peer
                .device
                .outgoing
                .pop_front()
                .expect("controlled peer ACK");
            let header = if ipv6 { 40 } else { 20 };
            let mut invalid = acknowledgement.clone();
            let (source, destination): (smoltcp::wire::IpAddress, smoltcp::wire::IpAddress) =
                if ipv6 {
                    let ip = Ipv6Packet::new_checked(&invalid[..]).unwrap();
                    (ip.src_addr().into(), ip.dst_addr().into())
                } else {
                    let ip = Ipv4Packet::new_checked(&invalid[..]).unwrap();
                    (ip.src_addr().into(), ip.dst_addr().into())
                };
            let mut tcp = TcpPacket::new_unchecked(&mut invalid[header..]);
            tcp.set_ack_number(tcp.ack_number() + 1_000_000);
            tcp.fill_checksum(&source, &destination);
            host.inject(&invalid).unwrap();
            host.poll_io(
                &mut Context::from_waker(Waker::noop()),
                now + Duration::from_millis(1),
            )
            .unwrap();
            let report = crate::pmtu_fixture::too_big(&quote, ipv6, 1280).unwrap();
            assert_eq!(
                host.receive_pmtu(&report),
                Ok(true),
                "an invalid ACK cannot consume a valid sizing reservation"
            );
            host.inject(&acknowledgement).unwrap();
            host.poll_io(
                &mut Context::from_waker(Waker::noop()),
                now + Duration::from_millis(2),
            )
            .unwrap();
            assert!(!host.pmtu_pending());
            assert_eq!(
                host.receive_pmtu(&report),
                Ok(false),
                "an accepted ACK retires the quoted segment"
            );
        }
    }

    #[tokio::test]
    async fn unsupported_mtu_fails_the_selected_stream_instead_of_hanging() {
        for ipv6 in [false, true] {
            let (mut host, mut flow, _peer, quote) = outstanding(ipv6, Box::new(|| Ok(1))).await;
            let mut report = crate::pmtu_fixture::too_big(&quote, ipv6, 1280).unwrap();
            if ipv6 {
                report[44..48].copy_from_slice(&1000u32.to_be_bytes());
            } else {
                report[26..28].copy_from_slice(&1000u16.to_be_bytes());
            }
            refill_report(&mut report, ipv6);
            assert_eq!(host.receive_pmtu(&report), Ok(true));
            let error = flow.stream.read(&mut [0]).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(host.statistics().pmtu_unsupported, 1);
            assert_eq!(host.statistics().pmtu_reductions, 0);
        }
    }
}
