// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Active smoltcp sockets through two BoringTun peers over loopback UDP.

#[path = "../../fragment_fixture.rs"]
mod fragment_fixture;
mod fragment_probe;
#[path = "../../mtu_reduction.rs"]
mod mtu_reduction;
mod outage;
#[path = "../../packet_peer.rs"]
mod packet_peer;
mod path_mtu;
#[path = "../../pmtu_feedback.rs"]
mod pmtu_feedback;
#[path = "../../pmtu_fixture.rs"]
mod pmtu_fixture;
mod pmtu_probe;
#[path = "../../reassembly.rs"]
mod reassembly;
mod udp_feedback;
mod udp_feedback_probe;

#[cfg(target_os = "linux")]
mod idle_watch;
#[cfg(target_os = "linux")]
mod kernel_mtu;
#[cfg(target_os = "linux")]
mod kernel_peer;
#[cfg(target_os = "linux")]
mod link_monitor;
#[cfg(target_os = "linux")]
mod outer_errors;
#[cfg(target_os = "linux")]
mod outer_mtu_probe;
#[cfg(target_os = "linux")]
mod outer_owner;
#[cfg(target_os = "linux")]
mod outer_remote;
#[cfg(target_os = "linux")]
mod outer_tcp_probe;
#[cfg(target_os = "linux")]
mod router_mtu;
#[cfg(target_os = "linux")]
mod router_path;
#[cfg(target_os = "linux")]
mod router_tcp;

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{
        Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};
use packet_peer::{MTU, PACKET_CAPACITY, Peer};
use smoltcp::socket::{tcp, udp};

const REQUEST: &[u8] = b"synthetic-tunnel-request";
const RESPONSE: &[u8] = b"synthetic-tunnel-response-after-fin";
const REKEY_DURATION: Duration = Duration::from_secs(135);
const PMTU_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportFailure {
    StagingLimit,
    StagingAccounting,
    DrainLimit,
    InnerDestination,
    PmtuFeedbackTooLarge,
    SeedSourceMissing,
    PmtuOwnerMismatch,
    PmtuPacketNotOwned,
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WireGuard transport experiment: {self:?}")
    }
}

impl std::error::Error for TransportFailure {}

struct Endpoint {
    peer: Peer,
    transport: Transport,
}

type SeedSource = Box<dyn FnMut() -> io::Result<u64> + Send>;

#[cfg(target_os = "linux")]
fn platform_seed() -> io::Result<u64> {
    mtu_reduction::prepare_seed()
}

#[cfg(not(target_os = "linux"))]
fn platform_seed() -> io::Result<u64> {
    Ok(0x5361)
}

struct PendingPmtuFeedback {
    packet: Vec<u8>,
    retry_at: Duration,
}

struct Transport {
    tunnel: Tunn,
    socket: UdpSocket,
    remote: SocketAddr,
    allowed_source: IpAddr,
    path_budget: path_mtu::PathBudget,
    reassembly: reassembly::Reassembler,
    udp_feedback: Option<udp_feedback::Reservation>,
    pmtu_feedback: Option<pmtu_feedback::Tracker>,
    pmtu_owner: Option<Weak<()>>,
    pending_pmtu_feedback: Option<PendingPmtuFeedback>,
    seed_source: Option<SeedSource>,
    pmtu_fixture: Option<pmtu_probe::PathFixture>,
    pmtu_reductions: usize,
    pmtu_deferrals: usize,
    now: Duration,
    initiations: usize,
    encrypted_packets: usize,
    received_inner: u64,
    drop_first_handshake: bool,
    dropped_handshakes: usize,
    staged_packets: usize,
    blackhole: bool,
    dropped_packets: usize,
    inbound_blackhole: bool,
    dropped_inbound: usize,
    #[cfg(test)]
    received_outer: usize,
}

impl Transport {
    fn send_result(&mut self, result: TunnResult<'_>, peer: &mut Peer) -> Result<bool> {
        match result {
            TunnResult::Done => Ok(false),
            TunnResult::Err(error) => bail!("WireGuard operation failed: {error:?}"),
            TunnResult::WriteToNetwork(packet) => {
                self.path_budget.check_datagram(packet.len())?;
                if packet.first() == Some(&1) {
                    self.initiations += 1;
                    if self.drop_first_handshake {
                        self.drop_first_handshake = false;
                        self.dropped_handshakes += 1;
                        return Ok(true);
                    }
                }
                if self.blackhole {
                    self.dropped_packets = self.dropped_packets.saturating_add(1);
                    return Ok(true);
                }
                ensure!(
                    self.socket.send_to(packet, self.remote)? == packet.len(),
                    "partial outer datagram"
                );
                self.encrypted_packets += 1;
                Ok(true)
            }
            TunnResult::WriteToTunnelV4(packet, source) => {
                ensure!(
                    IpAddr::V4(source) == self.allowed_source,
                    "unapproved inner IPv4 source"
                );
                self.inject_inner(packet, peer)?;
                self.received_inner = self.received_inner.saturating_add(1);
                Ok(true)
            }
            TunnResult::WriteToTunnelV6(packet, source) => {
                ensure!(
                    IpAddr::V6(source) == self.allowed_source,
                    "unapproved inner IPv6 source"
                );
                self.inject_inner(packet, peer)?;
                self.received_inner = self.received_inner.saturating_add(1);
                Ok(true)
            }
        }
    }

    fn pump(&mut self, peer: &mut Peer, now: Duration) -> Result<()> {
        self.ensure_pmtu_owner(peer)?;
        self.reassembly.advance(now)?;
        self.now = now;
        if let Some(tracker) = self.pmtu_feedback.as_mut() {
            tracker.reduction(&[], now)?;
        }
        self.with_seed_source(|owner, seed| owner.retry_pmtu_feedback(peer, seed))?;
        let mut output = [0; MTU + 256];
        while !peer.device.outgoing.is_empty() {
            if self.staged_packets >= PACKET_CAPACITY {
                return Err(TransportFailure::StagingLimit.into());
            }
            let Some(packet) = peer.device.outgoing.pop_front() else {
                break;
            };
            self.staged_packets += 1;
            let result = self.tunnel.encapsulate(&packet, &mut output);
            if is_application_data(&result) {
                self.staged_packets -= 1;
            }
            self.send_result(result, peer)?;
        }
        let result = self.tunnel.update_timers(&mut output);
        self.send_result(result, peer)?;
        let mut incoming = [0; MTU + 256];
        for _ in 0..PACKET_CAPACITY {
            let (length, source) = match self.socket.recv_from(&mut incoming) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };
            #[cfg(test)]
            {
                self.received_outer += 1;
            }
            if source != self.remote {
                continue;
            }
            if self.inbound_blackhole {
                if incoming[..length].starts_with(&[4, 0, 0, 0]) {
                    self.dropped_inbound = self.dropped_inbound.saturating_add(1);
                }
                continue;
            }
            let result =
                self.tunnel
                    .decapsulate(Some(source.ip()), &incoming[..length], &mut output);
            // Discard rejected authentication and replay attempts without
            // ending the transport; the per-pump packet limit bounds work.
            if matches!(
                result,
                TunnResult::Err(
                    WireGuardError::WrongTai64nTimestamp
                        | WireGuardError::InvalidMac
                        | WireGuardError::InvalidAeadTag
                        | WireGuardError::DuplicateCounter
                        | WireGuardError::InvalidCounter
                        | WireGuardError::NoCurrentSession
                )
            ) {
                continue;
            }
            self.receive_result(result, peer)?;
            // BoringTun queues plaintext while handshaking; drain every network result.
            let mut drained = false;
            // Up to 64 staged packets, then one Done result. The sentinel call
            // must fit too; otherwise a full valid queue fails after delivery.
            for _ in 0..=PACKET_CAPACITY {
                let result = self.tunnel.decapsulate(None, &[], &mut output);
                if !self.receive_result(result, peer)? {
                    drained = true;
                    break;
                }
            }
            if !drained {
                return Err(TransportFailure::DrainLimit.into());
            }
        }
        Ok(())
    }

    fn watch_pmtu(
        &mut self,
        peer: &Peer,
        packet: &[u8],
        reporter: std::net::IpAddr,
        now: Duration,
    ) -> Result<()> {
        if now < self.now {
            return Err(pmtu_feedback::Error::InvalidTime.into());
        }
        if self.pending_pmtu_feedback.is_some()
            || self
                .pmtu_feedback
                .as_ref()
                .is_some_and(|tracker| tracker.next_deadline().is_some())
        {
            return Err(pmtu_feedback::Error::Busy.into());
        }
        if !peer
            .device
            .outgoing
            .iter()
            .any(|queued| queued.as_slice() == packet)
        {
            return Err(TransportFailure::PmtuPacketNotOwned.into());
        }
        let mut tracker = pmtu_feedback::Tracker::default();
        tracker.reserve(packet, reporter, now, Duration::from_secs(1))?;
        self.pmtu_feedback = Some(tracker);
        self.pmtu_owner = Some(peer.identity());
        Ok(())
    }

    fn watch_udp(&mut self, packet: &[u8]) -> Result<()> {
        if self.udp_feedback.is_some() {
            return Err(udp_feedback::Error::Busy.into());
        }
        self.udp_feedback = Some(udp_feedback::Reservation::new(packet)?);
        Ok(())
    }

    fn inject_inner(&mut self, packet: &[u8], peer: &mut Peer) -> Result<()> {
        let destination = Tunn::dst_address(packet).ok_or(TransportFailure::InnerDestination)?;
        if !peer
            .interface
            .ip_addrs()
            .iter()
            .any(|address| address.address() == destination.into())
        {
            return Err(TransportFailure::InnerDestination.into());
        }
        let handled =
            self.with_seed_source(|owner, seed| owner.handle_pmtu_feedback(peer, packet, seed))?;
        if handled {
            return Ok(());
        }
        if let Some(fixture) = self.pmtu_fixture.as_mut() {
            match fixture.inspect(packet)? {
                pmtu_probe::Action::Pass => {}
                pmtu_probe::Action::Deliver => {
                    peer.device.inject(packet.to_vec())?;
                    return Ok(());
                }
                pmtu_probe::Action::Drop => {
                    return Ok(());
                }
                pmtu_probe::Action::Feedback(feedback) => {
                    let mut encrypted = [0; MTU + 256];
                    let result = self.tunnel.encapsulate(&feedback, &mut encrypted);
                    ensure!(
                        is_application_data(&result),
                        "controlled feedback could not be encrypted immediately"
                    );
                    self.send_result(result, peer)?;
                    return Ok(());
                }
            }
        }
        if self
            .udp_feedback
            .as_ref()
            .is_some_and(|reservation| reservation.matches(packet))
        {
            self.udp_feedback = None;
            return Err(udp_feedback::Error::PortUnreachable.into());
        }
        match self.reassembly.accept(packet, self.now)? {
            reassembly::Outcome::Pass => peer.device.inject(packet.to_vec())?,
            reassembly::Outcome::Pending => {}
            reassembly::Outcome::Complete(packet) => peer.device.inject(packet)?,
        }
        Ok(())
    }

    fn ensure_pmtu_owner(&self, peer: &Peer) -> Result<()> {
        let active = self.pending_pmtu_feedback.is_some()
            || self
                .pmtu_feedback
                .as_ref()
                .is_some_and(|tracker| tracker.next_deadline().is_some());
        if active
            && self
                .pmtu_owner
                .as_ref()
                .is_none_or(|owner| !owner.ptr_eq(&peer.identity()))
        {
            return Err(TransportFailure::PmtuOwnerMismatch.into());
        }
        Ok(())
    }

    fn with_seed_source<T>(
        &mut self,
        operation: impl FnOnce(&mut Self, &mut dyn FnMut() -> io::Result<u64>) -> Result<T>,
    ) -> Result<T> {
        let mut source = self
            .seed_source
            .take()
            .ok_or(TransportFailure::SeedSourceMissing)?;
        let result = operation(self, source.as_mut());
        self.seed_source = Some(source);
        result
    }

    fn handle_pmtu_feedback(
        &mut self,
        peer: &mut Peer,
        packet: &[u8],
        seed: impl FnOnce() -> io::Result<u64>,
    ) -> Result<bool> {
        self.ensure_pmtu_owner(peer)?;
        let Some(tracker) = self.pmtu_feedback.as_mut() else {
            return Ok(false);
        };
        if self.pending_pmtu_feedback.is_some() {
            return Ok(tracker.reduction(packet, self.now)?.is_some());
        }
        match mtu_reduction::apply_feedback(peer, tracker, packet, self.now, seed) {
            Ok(true) => {
                self.pmtu_reductions += 1;
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) if retryable_pmtu_failure(&error) => {
                if packet.len() > MTU {
                    return Err(TransportFailure::PmtuFeedbackTooLarge.into());
                }
                let retry_at = self
                    .now
                    .checked_add(PMTU_RETRY_INTERVAL)
                    .ok_or(pmtu_feedback::Error::InvalidTime)?;
                self.pending_pmtu_feedback = Some(PendingPmtuFeedback {
                    packet: packet.to_vec(),
                    retry_at,
                });
                self.pmtu_deferrals = self.pmtu_deferrals.saturating_add(1);
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    fn retry_pmtu_feedback(
        &mut self,
        peer: &mut Peer,
        seed: impl FnOnce() -> io::Result<u64>,
    ) -> Result<()> {
        self.ensure_pmtu_owner(peer)?;
        if self
            .pending_pmtu_feedback
            .as_ref()
            .is_none_or(|pending| self.now < pending.retry_at)
        {
            return Ok(());
        }
        let Some(pending) = self.pending_pmtu_feedback.take() else {
            return Ok(());
        };
        self.handle_pmtu_feedback(peer, &pending.packet, seed)?;
        Ok(())
    }

    fn receive_result(&mut self, result: TunnResult<'_>, peer: &mut Peer) -> Result<bool> {
        if is_application_data(&result) {
            self.staged_packets = self
                .staged_packets
                .checked_sub(1)
                .ok_or(TransportFailure::StagingAccounting)?;
        }
        self.send_result(result, peer)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.reassembly.cancel();
        if let Some(tracker) = self.pmtu_feedback.as_mut() {
            tracker.cancel();
        }
    }
}

fn retryable_pmtu_failure(error: &anyhow::Error) -> bool {
    if let Some(seed_error) = error.downcast_ref::<mtu_reduction::SeedError>() {
        return std::error::Error::source(seed_error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .is_some_and(|source| source.kind() == io::ErrorKind::WouldBlock);
    }
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock)
}

fn is_application_data(result: &TunnResult<'_>) -> bool {
    // Type 4 with more than WireGuard's 32-byte overhead contains an IP packet.
    // Empty encrypted keepalives are not staged application packets.
    matches!(result, TunnResult::WriteToNetwork(packet) if packet.first() == Some(&4) && packet.len() > 32)
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        arguments.is_empty()
            || arguments == ["--rekey"]
            || arguments == ["--outer-mtu-check"]
            || arguments == ["--kernel-mtu-check"]
            || arguments == ["--router-mtu-check"]
            || (arguments.len() == 2 && arguments[0] == "--router-mtu-check")
            || (arguments.len() == 2 && arguments[0] == "--router-mtu-peer")
            || ((3..=4).contains(&arguments.len()) && arguments[0] == "--physical-path-client")
            || ((3..=4).contains(&arguments.len()) && arguments[0] == "--physical-path-peer")
            || arguments == ["--kernel-link-check"]
            || arguments == ["--kernel-peer"]
            || arguments == ["--kernel-peer", "--rekey"],
        "usage: wireguard-stack [--kernel-peer [--rekey] | --kernel-link-check | --physical-path-client DIRECTORY INNER [OUTER] | --physical-path-peer DIRECTORY INNER [OUTER] | --outer-mtu-check | --kernel-mtu-check | --router-mtu-check [DIRECTORY] | --router-mtu-peer DIRECTORY | --rekey]"
    );
    if arguments.first().is_some_and(|argument| {
        argument == "--physical-path-client" || argument == "--physical-path-peer"
    }) {
        #[cfg(target_os = "linux")]
        {
            let parse_family = |family: &str| match family {
                "4" => Ok(false),
                "6" => Ok(true),
                _ => bail!("physical path family must be 4 or 6"),
            };
            let inner_ipv6 = parse_family(&arguments[2])?;
            let outer_ipv6 = parse_family(arguments.get(3).unwrap_or(&arguments[2]))?;
            let directory = std::path::Path::new(&arguments[1]);
            return if arguments[0] == "--physical-path-client" {
                router_path::run(directory, inner_ipv6, outer_ipv6)
            } else {
                router_path::serve(directory, inner_ipv6)
            };
        }
        #[cfg(not(target_os = "linux"))]
        bail!("physical path probe requires Linux disposable namespaces");
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--router-mtu-check")
    {
        #[cfg(target_os = "linux")]
        return router_mtu::run(arguments.get(1).map(std::path::Path::new));
        #[cfg(not(target_os = "linux"))]
        bail!("router MTU probe requires Linux disposable namespaces");
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--router-mtu-peer")
    {
        #[cfg(target_os = "linux")]
        return router_mtu::serve(std::path::Path::new(&arguments[1]));
        #[cfg(not(target_os = "linux"))]
        bail!("router MTU peer requires Linux disposable namespaces");
    }
    if arguments == ["--kernel-link-check"] {
        #[cfg(target_os = "linux")]
        return kernel_peer::run_link_check();
        #[cfg(not(target_os = "linux"))]
        bail!("kernel link probe requires Linux disposable namespaces");
    }
    if arguments == ["--kernel-mtu-check"] {
        #[cfg(target_os = "linux")]
        return kernel_mtu::run();
        #[cfg(not(target_os = "linux"))]
        bail!("kernel MTU probe requires Linux disposable namespaces");
    }
    if arguments == ["--outer-mtu-check"] {
        #[cfg(target_os = "linux")]
        return outer_mtu_probe::run();
        #[cfg(not(target_os = "linux"))]
        bail!("outer MTU errors require Linux disposable namespaces");
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--kernel-peer")
    {
        #[cfg(target_os = "linux")]
        return kernel_peer::run(arguments.len() == 2);
        #[cfg(not(target_os = "linux"))]
        bail!("kernel WireGuard peer requires Linux disposable namespaces");
    }
    for ipv6 in [false, true] {
        for outer_ipv6 in [false, true] {
            probe_with_outer(ipv6, outer_ipv6, Duration::ZERO)?;
            println!(
                "PASS active TCP/UDP, empty datagram, FIN, inner_ipv6={ipv6}, outer_ipv6={outer_ipv6}; loopback BoringTun peer"
            );
        }
        outage::run_probe(ipv6)?;
        println!(
            "PASS WireGuard outage: bounded staging, recovery, deadlines and cancellation, IPv6={ipv6}"
        );
        udp_feedback_probe::run_probe(ipv6)?;
        println!("PASS reserved UDP port-unreachable propagation, IPv6={ipv6}");
        pmtu_probe::run_probe(ipv6)?;
        println!("PASS encrypted inner TCP PMTU feedback, IPv6={ipv6}");
        fragment_probe::run_probe(ipv6)?;
        println!(
            "PASS encrypted fragment input: both orders, UDP round trip, expiry and cleanup, IPv6={ipv6}"
        );
    }
    if !arguments.is_empty() {
        probe(false, REKEY_DURATION)?;
        println!("PASS sustained IPv4 UDP across timer-driven rekey");
    }
    Ok(())
}

fn probe(ipv6: bool, minimum_duration: Duration) -> Result<()> {
    probe_with_outer(ipv6, false, minimum_duration)
}

fn probe_with_outer(ipv6: bool, outer_ipv6: bool, minimum_duration: Duration) -> Result<()> {
    let (mut client, mut server) = create_pair_with_outer(ipv6, outer_ipv6)?;
    run_client(
        ipv6,
        minimum_duration,
        &mut client.peer,
        &mut client.transport,
        Some((&mut server.peer, &mut server.transport)),
    )
}

fn create_pair(ipv6: bool) -> Result<(Endpoint, Endpoint)> {
    create_pair_with_outer(ipv6, false)
}

fn create_pair_with_outer(ipv6: bool, outer_ipv6: bool) -> Result<(Endpoint, Endpoint)> {
    let client_address: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let server_address: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    let mut server = Peer::new(server_address, 9000)?;
    server
        .sockets
        .get_mut::<tcp::Socket>(server.tcp)
        .listen((server_address, 9000))?;
    let server_socket = UdpSocket::bind(loopback_address(outer_ipv6))?;
    server_socket.set_nonblocking(true)?;
    let (client, client_transport) = create_client(ipv6, server_socket.local_addr()?)?;
    let client_key = StaticSecret::from([0x11; 32]);
    let server_transport = Transport {
        tunnel: Tunn::new(
            StaticSecret::from([0x22; 32]),
            PublicKey::from(&client_key),
            None,
            Some(1),
            2,
            None,
        ),
        remote: client_transport.socket.local_addr()?,
        socket: server_socket,
        allowed_source: client_address,
        path_budget: path_mtu::PathBudget::new(1500, outer_ipv6)?,
        reassembly: reassembly::Reassembler::new(reassembly::Limits::default())?,
        udp_feedback: None,
        pmtu_feedback: None,
        pmtu_owner: None,
        pending_pmtu_feedback: None,
        seed_source: Some(Box::new(platform_seed)),
        pmtu_fixture: None,
        pmtu_reductions: 0,
        pmtu_deferrals: 0,
        now: Duration::ZERO,
        initiations: 0,
        encrypted_packets: 0,
        received_inner: 0,
        drop_first_handshake: false,
        dropped_handshakes: 0,
        staged_packets: 0,
        blackhole: false,
        dropped_packets: 0,
        inbound_blackhole: false,
        dropped_inbound: 0,
        #[cfg(test)]
        received_outer: 0,
    };
    Ok((
        Endpoint {
            peer: client,
            transport: client_transport,
        },
        Endpoint {
            peer: server,
            transport: server_transport,
        },
    ))
}

fn create_client(ipv6: bool, remote: SocketAddr) -> Result<(Peer, Transport)> {
    let path_budget = path_mtu::PathBudget::new(1500, remote.is_ipv6())?;
    let client_address: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let server_address: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    let client = Peer::new(client_address, 40000)?;
    let socket = UdpSocket::bind(loopback_address(remote.is_ipv6()))?;
    socket.set_nonblocking(true)?;
    // Published synthetic test keys, never credentials for external peers.
    let server_key = StaticSecret::from([0x22; 32]);
    let transport = Transport {
        tunnel: Tunn::new(
            StaticSecret::from([0x11; 32]),
            PublicKey::from(&server_key),
            None,
            Some(1),
            1,
            None,
        ),
        socket,
        remote,
        allowed_source: server_address,
        path_budget,
        reassembly: reassembly::Reassembler::new(reassembly::Limits::default())?,
        udp_feedback: None,
        pmtu_feedback: None,
        pmtu_owner: None,
        pending_pmtu_feedback: None,
        seed_source: Some(Box::new(platform_seed)),
        pmtu_fixture: None,
        pmtu_reductions: 0,
        pmtu_deferrals: 0,
        now: Duration::ZERO,
        initiations: 0,
        encrypted_packets: 0,
        received_inner: 0,
        drop_first_handshake: false,
        dropped_handshakes: 0,
        staged_packets: 0,
        blackhole: false,
        dropped_packets: 0,
        inbound_blackhole: false,
        dropped_inbound: 0,
        #[cfg(test)]
        received_outer: 0,
    };
    Ok((client, transport))
}

fn loopback_address(ipv6: bool) -> SocketAddr {
    if ipv6 {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0))
    } else {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }
}

fn wait_for_outer(socket: &UdpSocket, deadline: Instant) -> Result<()> {
    let mut byte = [0; 1];
    loop {
        ensure!(
            Instant::now() < deadline,
            "outer datagram readiness deadline exceeded"
        );
        match socket.peek_from(&mut byte) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn pace_fixture(step: u64) {
    // Let loopback I/O progress without requiring one OS timer wake per tick.
    if step.is_multiple_of(4) {
        thread::sleep(Duration::from_millis(1));
    } else {
        thread::yield_now();
    }
}

fn run_client(
    ipv6: bool,
    minimum_duration: Duration,
    client: &mut Peer,
    client_transport: &mut Transport,
    server: Option<(&mut Peer, &mut Transport)>,
) -> Result<()> {
    run_client_with_outage(
        ipv6,
        minimum_duration,
        client,
        client_transport,
        server,
        false,
        None,
    )
}

fn run_client_with_outage(
    ipv6: bool,
    minimum_duration: Duration,
    client: &mut Peer,
    client_transport: &mut Transport,
    mut server: Option<(&mut Peer, &mut Transport)>,
    inject_outage: bool,
    response_sent: Option<&AtomicBool>,
) -> Result<()> {
    let client_address: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let server_address: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    client.sockets.get_mut::<tcp::Socket>(client.tcp).connect(
        client.interface.context(),
        (server_address, 9000),
        (client_address, 40001),
    )?;
    let payloads = [
        vec![],
        vec![0x31],
        vec![0x72; 257],
        vec![0x53; if ipv6 { 1232 } else { 1252 }],
    ];
    for payload in &payloads {
        client
            .sockets
            .get_mut::<udp::Socket>(client.udp)
            .send_slice(payload, (server_address, 9000))?;
    }
    let start = Instant::now();
    // A fresh peer may need WireGuard's first handshake retry after kernel
    // initiation limiting. Keep this within the canonical 10-second setup budget.
    let deadline = minimum_duration + Duration::from_secs(if inject_outage { 25 } else { 10 });
    let mut next_heartbeat = Duration::from_secs(1);
    let mut sent = false;
    let mut request = Vec::new();
    let mut replied = false;
    let mut response = Vec::new();
    let mut udp_received = 0;
    let mut heartbeat_pending = false;
    let mut completion_started = None;
    let mut outage_recovered = !inject_outage;
    let mut outage_started = None;
    let mut outage_since = None;
    let mut lost_sequence = None;
    let mut lost_udp_queued = false;
    let mut lost_udp_observed = false;
    let mut retried_during_outage = false;
    let mut inbound_recovered = response_sent.is_none();
    let mut inbound_started = None;
    let mut response_drop_start = None;
    loop {
        ensure!(
            start.elapsed() < deadline,
            "controlled tunnel exchange exceeded deadline"
        );
        let elapsed_ms = i64::try_from(start.elapsed().as_millis())?;
        if client_transport.inbound_blackhole
            && response_drop_start.is_none()
            && response_sent.is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            response_drop_start = Some(client_transport.dropped_inbound);
        }
        client.poll(elapsed_ms);
        if client_transport.blackhole {
            for packet in &client.device.outgoing {
                lost_udp_observed |= is_lost_datagram(packet)?;
                if let Some(frame) = pmtu_probe::plain_tcp(packet)? {
                    let tcp = smoltcp::wire::TcpPacket::new_checked(frame.payload)?;
                    if !tcp.payload().is_empty() {
                        match lost_sequence {
                            None => lost_sequence = Some(tcp.seq_number()),
                            Some(sequence) if sequence == tcp.seq_number() => {
                                retried_during_outage = true
                            }
                            Some(_) => {}
                        }
                    }
                }
            }
        }
        client_transport.pump(client, start.elapsed())?;
        if let Some((server, transport)) = server.as_mut() {
            server.poll(elapsed_ms);
            transport.pump(server, start.elapsed())?;
        }

        let socket = client.sockets.get_mut::<tcp::Socket>(client.tcp);
        if !sent && socket.can_send() && (!inject_outage || udp_received == payloads.len()) {
            if inject_outage {
                client_transport.blackhole = true;
                outage_started = Some(client_transport.dropped_packets);
                outage_since = Some(start.elapsed());
            }
            ensure!(
                socket.send_slice(REQUEST)? == REQUEST.len(),
                "partial request admission"
            );
            socket.close();
            sent = true;
        }
        if socket.can_recv() {
            socket.recv(|bytes| {
                response.extend_from_slice(bytes);
                (bytes.len(), ())
            })?;
            ensure!(response.len() <= RESPONSE.len(), "oversized TCP response");
        }
        let tcp_done = sent && !socket.may_recv();
        if inject_outage && sent && !outage_recovered {
            if client_transport.dropped_packets
                == outage_started.context("missing outage reservation")?
            {
                // Enqueue once alongside the sole application write. The next
                // poll emits both packets into the controlled blackhole.
                if !client_transport.blackhole {
                    anyhow::bail!("outage unexpectedly inactive");
                }
                if !lost_udp_queued
                    && client.sockets.get::<udp::Socket>(client.udp).send_queue() == 0
                {
                    client
                        .sockets
                        .get_mut::<udp::Socket>(client.udp)
                        .send_slice(b"lost-datagram", (server_address, 9000))?;
                    lost_udp_queued = true;
                }
            } else if start
                .elapsed()
                .saturating_sub(outage_since.context("missing outage start")?)
                >= Duration::from_millis(1200)
                && retried_during_outage
                && lost_udp_observed
            {
                ensure!(
                    client_transport.dropped_packets
                        >= outage_started.context("missing outage reservation")? + 3,
                    "outage did not suppress TCP, UDP, and a TCP retry"
                );
                client_transport.blackhole = false;
                client
                    .sockets
                    .get_mut::<udp::Socket>(client.udp)
                    .send_slice(b"heartbeat", (server_address, 9000))?;
                heartbeat_pending = true;
                next_heartbeat = start.elapsed() + Duration::from_secs(1);
                outage_recovered = true;
            }
        }
        if let Some((server, _)) = server.as_mut() {
            let socket = server.sockets.get_mut::<tcp::Socket>(server.tcp);
            if socket.can_recv() {
                socket.recv(|bytes| {
                    request.extend_from_slice(bytes);
                    (bytes.len(), ())
                })?;
                ensure!(request.len() <= REQUEST.len(), "oversized TCP request");
            }
            if !replied && !socket.may_recv() && socket.can_send() {
                ensure!(request == REQUEST, "TCP request/FIN changed");
                ensure!(
                    socket.send_slice(RESPONSE)? == RESPONSE.len(),
                    "partial response admission"
                );
                socket.close();
                replied = true;
            }

            let socket = server.sockets.get_mut::<udp::Socket>(server.udp);
            if socket.can_recv() {
                let (payload, metadata) = socket.recv()?;
                let payload = payload.to_vec();
                ensure!(
                    metadata.endpoint == SocketAddr::new(client_address, 40000).into(),
                    "UDP source changed"
                );
                socket.send_slice(&payload, metadata.endpoint)?;
            }
        }
        let socket = client.sockets.get_mut::<udp::Socket>(client.udp);
        if socket.can_recv() {
            let (actual, metadata) = socket.recv()?;
            ensure!(
                metadata.endpoint == SocketAddr::new(server_address, 9000).into(),
                "UDP reply source changed"
            );
            if udp_received < payloads.len() {
                ensure!(
                    actual == payloads[udp_received],
                    "UDP boundary or empty datagram changed"
                );
                udp_received += 1;
            } else {
                ensure!(
                    heartbeat_pending && actual == b"heartbeat",
                    "unexpected heartbeat response"
                );
                heartbeat_pending = false;
                if let Some(flag) = response_sent
                    && !inbound_recovered
                    && inbound_started.is_none()
                {
                    ensure!(
                        !flag.load(Ordering::Acquire),
                        "response preceded inbound blackout"
                    );
                    client_transport.inbound_blackhole = true;
                    inbound_started = Some(start.elapsed());
                }
            }
        }
        if client_transport.inbound_blackhole {
            ensure!(
                response.is_empty(),
                "response reached application during inbound blackout"
            );
            if let Some(initial) = response_drop_start
                && client_transport.dropped_inbound > initial
                && start
                    .elapsed()
                    .saturating_sub(inbound_started.context("missing inbound blackout start")?)
                    >= Duration::from_millis(1200)
            {
                client_transport.inbound_blackhole = false;
                inbound_recovered = true;
            }
        }
        if !inject_outage
            && udp_received == payloads.len()
            && !heartbeat_pending
            && start.elapsed() >= next_heartbeat
        {
            socket.send_slice(b"heartbeat", (server_address, 9000))?;
            heartbeat_pending = true;
            next_heartbeat = start.elapsed() + Duration::from_secs(1);
        }
        if tcp_done
            && outage_recovered
            && inbound_recovered
            && udp_received == payloads.len()
            && !heartbeat_pending
            && start.elapsed() >= minimum_duration
        {
            // EOF can precede emission of a delayed TCP ACK. Keep driving the
            // controlled loopback stacks before replacing this fixture session.
            let completion = *completion_started.get_or_insert(start.elapsed());
            if start.elapsed() - completion < Duration::from_millis(100) {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            ensure!(response == RESPONSE, "TCP response after FIN changed");
            ensure!(
                client_transport.encrypted_packets > 0
                    && server
                        .as_ref()
                        .is_none_or(|(_, transport)| transport.encrypted_packets > 0),
                "no outer traffic observed"
            );
            if minimum_duration >= REKEY_DURATION {
                ensure!(
                    client_transport.initiations
                        + server
                            .as_ref()
                            .map_or(0, |(_, transport)| transport.initiations)
                        >= 2,
                    "no second handshake initiation observed"
                );
                // A new session must actually complete, not merely attempt a handshake.
                ensure!(
                    client_transport
                        .tunnel
                        .stats()
                        .0
                        .context("missing completed handshake")?
                        < Duration::from_secs(30),
                    "session did not rekey"
                );
            }
            // All stacks, sockets, and tunnel state are owned locally; no background tasks.
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn is_lost_datagram(packet: &[u8]) -> Result<bool> {
    use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
    let (protocol, payload) = match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(packet)?;
            (ip.next_header(), ip.payload())
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(packet)?;
            (ip.next_header(), ip.payload())
        }
        _ => anyhow::bail!("invalid blackout packet IP version"),
    };
    if protocol != IpProtocol::Udp {
        return Ok(false);
    }
    Ok(UdpPacket::new_checked(payload)?.payload() == b"lost-datagram")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive_outer_data(
        socket: &UdpSocket,
        deadline: Instant,
        bytes: &mut [u8],
    ) -> Result<usize> {
        for _ in 0..PACKET_CAPACITY {
            wait_for_outer(socket, deadline)?;
            let (length, _) = socket.recv_from(bytes)?;
            if length > 32 {
                return Ok(length);
            }
            ensure!(
                length == 32 && bytes[0] == 4,
                "unexpected outer datagram before data"
            );
        }
        anyhow::bail!("outer data exceeded the bounded datagram count")
    }

    #[test]
    fn outer_data_waits_past_a_queued_keepalive() {
        for ipv6 in [false, true] {
            let receiver = UdpSocket::bind(loopback_address(ipv6)).unwrap();
            receiver.set_nonblocking(true).unwrap();
            let observer = receiver.try_clone().unwrap();
            let sender = UdpSocket::bind(loopback_address(ipv6)).unwrap();
            let destination = receiver.local_addr().unwrap();
            let mut keepalive = [0; 32];
            keepalive[0] = 4;
            assert_eq!(
                sender.send_to(&keepalive, destination).unwrap(),
                keepalive.len()
            );
            wait_for_outer(&receiver, Instant::now() + Duration::from_secs(2)).unwrap();
            let worker = thread::spawn(move || -> Result<()> {
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    ensure!(Instant::now() < deadline, "keepalive was not consumed");
                    match observer.peek_from(&mut [0; 1]) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Ok(_) => thread::yield_now(),
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut data = [0; 64];
                data[0] = 4;
                ensure!(
                    sender.send_to(&data, destination)? == data.len(),
                    "partial synthetic data"
                );
                Ok(())
            });
            let mut bytes = [0; 128];
            let received = receive_outer_data(
                &receiver,
                Instant::now() + Duration::from_secs(2),
                &mut bytes,
            );
            worker.join().unwrap().unwrap();
            assert_eq!(received.unwrap(), 64);
            assert_eq!(bytes[0], 4);
            let sender = UdpSocket::bind(loopback_address(ipv6)).unwrap();
            assert_eq!(
                sender.send_to(&keepalive, destination).unwrap(),
                keepalive.len()
            );
            assert!(
                receive_outer_data(
                    &receiver,
                    Instant::now() + Duration::from_millis(20),
                    &mut bytes
                )
                .is_err(),
                "a keepalive alone must not satisfy data readiness"
            );
            assert_eq!(sender.send_to(&[0; 16], destination).unwrap(), 16);
            assert!(
                receive_outer_data(
                    &receiver,
                    Instant::now() + Duration::from_secs(2),
                    &mut bytes
                )
                .is_err(),
                "unexpected datagrams must not be treated as data"
            );
            for _ in 0..PACKET_CAPACITY {
                assert_eq!(
                    sender.send_to(&keepalive, destination).unwrap(),
                    keepalive.len()
                );
            }
            assert!(
                receive_outer_data(
                    &receiver,
                    Instant::now() + Duration::from_secs(2),
                    &mut bytes
                )
                .is_err(),
                "keepalives must not cause an unbounded readiness loop"
            );
        }
    }

    #[test]
    fn outer_readiness_waits_for_delayed_datagram_and_times_out() {
        for ipv6 in [false, true] {
            let receiver = UdpSocket::bind(loopback_address(ipv6)).unwrap();
            receiver.set_nonblocking(true).unwrap();
            let sender = UdpSocket::bind(loopback_address(ipv6)).unwrap();
            sender
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let destination = receiver.local_addr().unwrap();
            let worker = thread::spawn(move || {
                thread::sleep(Duration::from_millis(10));
                sender.send_to(b"ready", destination)
            });
            let ready = wait_for_outer(&receiver, Instant::now() + Duration::from_secs(2));
            let sent = worker.join().unwrap().unwrap();
            ready.unwrap();
            let mut bytes = [0; 16];
            let (length, _) = receiver.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..length], b"ready");
            assert_eq!(sent, 5);
            assert!(wait_for_outer(&receiver, Instant::now()).is_err());
        }
    }

    #[test]
    fn blackout_datagram_detection_handles_both_families_and_malformed_packets() {
        assert!(is_lost_datagram(&[]).is_err());
        assert!(is_lost_datagram(&[0x70]).is_err());
        for ipv6 in [false, true] {
            let header = if ipv6 { 40 } else { 20 };
            let payload = b"lost-datagram";
            let mut packet = vec![0; header + 8 + payload.len()];
            if ipv6 {
                packet[0] = 0x60;
                packet[4..6]
                    .copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
                packet[6] = 17;
            } else {
                packet[0] = 0x45;
                let length = u16::try_from(packet.len()).unwrap();
                packet[2..4].copy_from_slice(&length.to_be_bytes());
                packet[9] = 17;
            }
            packet[header + 4..header + 6]
                .copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
            packet[header + 8..].copy_from_slice(payload);
            assert!(is_lost_datagram(&packet).unwrap(), "IPv6 {ipv6}");
            *packet.last_mut().unwrap() ^= 1;
            assert!(!is_lost_datagram(&packet).unwrap(), "IPv6 {ipv6}");
            packet[if ipv6 { 6 } else { 9 }] = 6;
            assert!(!is_lost_datagram(&packet).unwrap(), "IPv6 {ipv6}");
            assert!(
                is_lost_datagram(&packet[..header - 1]).is_err(),
                "IPv6 {ipv6}"
            );
        }
    }

    #[test]
    fn active_sockets_exchange_ipv4_and_ipv6_through_wireguard() {
        for ipv6 in [false, true] {
            for outer_ipv6 in [false, true] {
                probe_with_outer(ipv6, outer_ipv6, Duration::ZERO).unwrap();
            }
        }
    }

    #[test]
    fn fresh_wireguard_session_rejects_old_session_data() {
        fn pair() -> (Tunn, Tunn) {
            let client = StaticSecret::from([0x11; 32]);
            let server = StaticSecret::from([0x22; 32]);
            (
                Tunn::new(
                    client.clone(),
                    PublicKey::from(&server),
                    None,
                    None,
                    1,
                    None,
                ),
                Tunn::new(server, PublicKey::from(&client), None, None, 2, None),
            )
        }

        fn network(result: TunnResult<'_>) -> Vec<u8> {
            match result {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected network packet, got {other:?}"),
            }
        }

        fn handshake(client: &mut Tunn, server: &mut Tunn) {
            let mut output = [0; 2048];
            let initiation = network(client.format_handshake_initiation(&mut output, false));
            let response = network(server.decapsulate(None, &initiation, &mut output));
            let keepalive = network(client.decapsulate(None, &response, &mut output));
            assert!(matches!(
                server.decapsulate(None, &keepalive, &mut output),
                TunnResult::Done
            ));
        }

        let (mut client, mut server) = pair();
        handshake(&mut client, &mut server);
        let mut output = [0; 2048];
        let mut inner = [0; 20];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&20_u16.to_be_bytes());
        inner[12..16].copy_from_slice(&[10, 66, 66, 2]);
        let old = network(client.encapsulate(&inner, &mut output));
        assert!(matches!(
            server.decapsulate(None, &old, &mut output),
            TunnResult::WriteToTunnelV4(_, _)
        ));

        let (mut replacement_client, mut replacement_server) = pair();
        assert!(matches!(
            replacement_server.decapsulate(None, &old, &mut output),
            TunnResult::Err(_)
        ));
        handshake(&mut replacement_client, &mut replacement_server);
        assert!(matches!(
            replacement_server.decapsulate(None, &old, &mut output),
            TunnResult::Err(_)
        ));
        let current = network(replacement_client.encapsulate(&inner, &mut output));
        assert!(matches!(
            replacement_server.decapsulate(None, &current, &mut output),
            TunnResult::WriteToTunnelV4(_, _)
        ));
    }

    #[test]
    fn fresh_wireguard_instance_accepts_previously_seen_handshake_initiation() {
        let client_key = StaticSecret::from([0x11; 32]);
        let server_key = StaticSecret::from([0x22; 32]);
        let mut client = Tunn::new(
            client_key.clone(),
            PublicKey::from(&server_key),
            None,
            None,
            1,
            None,
        );
        let server = || {
            Tunn::new(
                server_key.clone(),
                PublicKey::from(&client_key),
                None,
                None,
                2,
                None,
            )
        };
        let mut output = [0; 2048];
        let initiation = match client.format_handshake_initiation(&mut output, false) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected handshake initiation, got {other:?}"),
        };
        let mut original = server();
        assert!(matches!(
            original.decapsulate(None, &initiation, &mut output),
            TunnResult::WriteToNetwork(_)
        ));
        assert!(matches!(
            original.decapsulate(None, &initiation, &mut output),
            TunnResult::Err(_)
        ));

        let mut replacement = server();
        assert!(matches!(
            replacement.decapsulate(None, &initiation, &mut output),
            TunnResult::WriteToNetwork(_)
        ));
        // A later legitimate initiation must still establish a usable session.
        let mut current_client = Tunn::new(
            client_key,
            PublicKey::from(&server_key),
            None,
            None,
            1,
            None,
        );
        let current_initiation =
            match current_client.format_handshake_initiation(&mut output, false) {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected current initiation, got {other:?}"),
            };
        let response = match replacement.decapsulate(None, &current_initiation, &mut output) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected handshake response, got {other:?}"),
        };
        let keepalive = match current_client.decapsulate(None, &response, &mut output) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected keepalive, got {other:?}"),
        };
        assert!(matches!(
            replacement.decapsulate(None, &keepalive, &mut output),
            TunnResult::Done
        ));
        let mut inner = [0; 20];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&20_u16.to_be_bytes());
        inner[12..16].copy_from_slice(&[10, 66, 66, 2]);
        let data = match current_client.encapsulate(&inner, &mut output) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected encrypted data, got {other:?}"),
        };
        assert!(matches!(
            replacement.decapsulate(None, &data, &mut output),
            TunnResult::WriteToTunnelV4(packet, _) if packet == inner
        ));
        assert!(matches!(
            replacement.decapsulate(None, &initiation, &mut output),
            TunnResult::Err(_)
        ));
        let next = match current_client.encapsulate(&inner, &mut output) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected encrypted data, got {other:?}"),
        };
        assert!(matches!(
            replacement.decapsulate(None, &next, &mut output),
            TunnResult::WriteToTunnelV4(packet, _) if packet == inner
        ));
    }

    #[test]
    fn replayed_handshake_does_not_stop_experimental_udp_transport() {
        for outer_ipv6 in [false, true] {
            let (mut client, mut server) = create_pair_with_outer(false, outer_ipv6).unwrap();
            let mut output = [0; 2048];
            let initiation = match client
                .transport
                .tunnel
                .format_handshake_initiation(&mut output, false)
            {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected handshake initiation, got {other:?}"),
            };
            let server_address = server.transport.socket.local_addr().unwrap();
            assert_eq!(
                client
                    .transport
                    .socket
                    .send_to(&initiation, server_address)
                    .unwrap(),
                initiation.len()
            );
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            wait_for_outer(
                &client.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            let (length, source) = client.transport.socket.recv_from(&mut output).unwrap();
            assert_eq!(source, server_address);
            assert_eq!(output[0], 2, "response must be a handshake response");
            assert!(length > 0);
            let response = output[..length].to_vec();

            for _ in 0..=PACKET_CAPACITY {
                assert_eq!(
                    client
                        .transport
                        .socket
                        .send_to(&initiation, server_address)
                        .unwrap(),
                    initiation.len()
                );
            }
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_outer, 1 + PACKET_CAPACITY);
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_outer, 2 + PACKET_CAPACITY);
            let keepalive = match client
                .transport
                .tunnel
                .decapsulate(None, &response, &mut output)
            {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected keepalive, got {other:?}"),
            };
            client
                .transport
                .socket
                .send_to(&keepalive, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            let mut inner = [0; 20];
            inner[0] = 0x45;
            inner[2..4].copy_from_slice(&20_u16.to_be_bytes());
            inner[12..16].copy_from_slice(&[10, 66, 66, 2]);
            inner[16..20].copy_from_slice(&[10, 66, 66, 10]);
            let data = match client.transport.tunnel.encapsulate(&inner, &mut output) {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected encrypted data, got {other:?}"),
            };
            let mut damaged = data.clone();
            *damaged.last_mut().unwrap() ^= 1;
            client
                .transport
                .socket
                .send_to(&damaged, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_inner, 0);
            client
                .transport
                .socket
                .send_to(&data, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert!(server.peer.device.has_ingress());
            assert_eq!(server.transport.received_inner, 1);
            client
                .transport
                .socket
                .send_to(&data, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(
                server.transport.received_inner, 1,
                "replayed data must not be delivered twice"
            );
            let next = match client.transport.tunnel.encapsulate(&inner, &mut output) {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected fresh encrypted data, got {other:?}"),
            };
            client
                .transport
                .socket
                .send_to(&next, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_inner, 2);
            // Advance beyond BoringTun's 1024-packet replay window without
            // filling the fixture's bounded ingress queue.
            let mut far_ahead = Vec::new();
            for _ in 0..1025 {
                far_ahead = match client.transport.tunnel.encapsulate(&inner, &mut output) {
                    TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                    other => panic!("expected encrypted data, got {other:?}"),
                };
            }
            client
                .transport
                .socket
                .send_to(&far_ahead, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_inner, 3);
            client
                .transport
                .socket
                .send_to(&data, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(
                server.transport.received_inner, 3,
                "out-of-window data must not be delivered"
            );
            let fresh = match client.transport.tunnel.encapsulate(&inner, &mut output) {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected fresh encrypted data, got {other:?}"),
            };
            client
                .transport
                .socket
                .send_to(&fresh, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_inner, 4);
            client
                .transport
                .socket
                .send_to(&[0], server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            assert!(
                server
                    .transport
                    .pump(&mut server.peer, Duration::ZERO)
                    .is_err()
            );
            drop(server);
            UdpSocket::bind(server_address).unwrap();
        }
    }

    #[test]
    fn retired_session_data_does_not_stop_replacement_transport() {
        fn network(result: TunnResult<'_>) -> Vec<u8> {
            match result {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected network packet, got {other:?}"),
            }
        }

        for outer_ipv6 in [false, true] {
            let (mut old_client, mut old_server) =
                create_pair_with_outer(false, outer_ipv6).unwrap();
            let mut output = [0; 2048];
            let initiation = network(
                old_client
                    .transport
                    .tunnel
                    .format_handshake_initiation(&mut output, false),
            );
            let response = network(old_server.transport.tunnel.decapsulate(
                None,
                &initiation,
                &mut output,
            ));
            let keepalive = network(old_client.transport.tunnel.decapsulate(
                None,
                &response,
                &mut output,
            ));
            assert!(matches!(
                old_server
                    .transport
                    .tunnel
                    .decapsulate(None, &keepalive, &mut output),
                TunnResult::Done
            ));
            let mut inner = [0; 20];
            inner[0] = 0x45;
            inner[2..4].copy_from_slice(&20_u16.to_be_bytes());
            inner[12..16].copy_from_slice(&[10, 66, 66, 2]);
            inner[16..20].copy_from_slice(&[10, 66, 66, 10]);
            let retired = network(old_client.transport.tunnel.encapsulate(&inner, &mut output));
            drop((old_client, old_server));

            let (mut client, mut server) = create_pair_with_outer(false, outer_ipv6).unwrap();
            let server_address = server.transport.socket.local_addr().unwrap();
            client
                .transport
                .socket
                .send_to(&retired, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_inner, 0);

            let initiation = network(
                client
                    .transport
                    .tunnel
                    .format_handshake_initiation(&mut output, false),
            );
            client
                .transport
                .socket
                .send_to(&initiation, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            wait_for_outer(
                &client.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            let (length, source) = client.transport.socket.recv_from(&mut output).unwrap();
            assert_eq!(source, server_address);
            let response = output[..length].to_vec();
            let keepalive = network(client.transport.tunnel.decapsulate(
                None,
                &response,
                &mut output,
            ));
            client
                .transport
                .socket
                .send_to(&keepalive, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            client
                .transport
                .socket
                .send_to(&retired, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_inner, 0);
            let fresh = network(client.transport.tunnel.encapsulate(&inner, &mut output));
            client
                .transport
                .socket
                .send_to(&fresh, server_address)
                .unwrap();
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_inner, 1);
            drop(server);
            UdpSocket::bind(server_address).unwrap();
        }
    }

    #[test]
    fn unrecognized_outer_packets_do_not_stop_handshake() {
        for outer_ipv6 in [false, true] {
            let (mut client, mut server) = create_pair_with_outer(false, outer_ipv6).unwrap();
            let mut output = [0; 2048];
            let initiation = match client
                .transport
                .tunnel
                .format_handshake_initiation(&mut output, false)
            {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected handshake initiation, got {other:?}"),
            };
            let server_address = server.transport.socket.local_addr().unwrap();
            let sender = UdpSocket::bind(loopback_address(outer_ipv6)).unwrap();
            sender.set_nonblocking(true).unwrap();
            assert_eq!(
                sender.send_to(&initiation, server_address).unwrap(),
                initiation.len()
            );
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_outer, 1);
            assert_eq!(
                sender.recv_from(&mut output).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(!server.peer.device.has_ingress());

            let mut unrecognized_session_data = [0; 32];
            unrecognized_session_data[0] = 4;
            assert_eq!(
                client
                    .transport
                    .socket
                    .send_to(&unrecognized_session_data, server_address)
                    .unwrap(),
                unrecognized_session_data.len()
            );
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert!(!server.peer.device.has_ingress());

            assert_eq!(
                client
                    .transport
                    .socket
                    .send_to(&initiation, server_address)
                    .unwrap(),
                initiation.len()
            );
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            wait_for_outer(
                &client.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            let (length, source) = client.transport.socket.recv_from(&mut output).unwrap();
            assert_eq!(source, server_address);
            assert!(length > 0);
            assert_eq!(
                output[0], 2,
                "configured peer must receive a handshake response"
            );
            drop(server);
            UdpSocket::bind(server_address).unwrap();
        }
    }

    #[test]
    fn invalid_handshake_mac_does_not_stop_experimental_udp_transport() {
        for outer_ipv6 in [false, true] {
            let (mut client, mut server) = create_pair_with_outer(false, outer_ipv6).unwrap();
            let mut output = [0; 2048];
            let initiation = match client
                .transport
                .tunnel
                .format_handshake_initiation(&mut output, false)
            {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected handshake initiation, got {other:?}"),
            };
            let mut corrupt = initiation.clone();
            let mac_offset = corrupt.len() - 32;
            corrupt[mac_offset] ^= 1;
            let server_address = server.transport.socket.local_addr().unwrap();
            for _ in 0..PACKET_CAPACITY {
                assert_eq!(
                    client
                        .transport
                        .socket
                        .send_to(&corrupt, server_address)
                        .unwrap(),
                    corrupt.len()
                );
            }
            assert_eq!(
                client
                    .transport
                    .socket
                    .send_to(&initiation, server_address)
                    .unwrap(),
                initiation.len()
            );
            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_outer, PACKET_CAPACITY);
            assert_eq!(
                client
                    .transport
                    .socket
                    .recv_from(&mut output)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(!server.peer.device.has_ingress());

            wait_for_outer(
                &server.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            server
                .transport
                .pump(&mut server.peer, Duration::ZERO)
                .unwrap();
            assert_eq!(server.transport.received_outer, PACKET_CAPACITY + 1);
            wait_for_outer(
                &client.transport.socket,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            let (length, source) = client.transport.socket.recv_from(&mut output).unwrap();
            assert_eq!(source, server_address);
            assert!(length > 0);
            assert_eq!(
                output[0], 2,
                "valid initiation must receive a handshake response"
            );
            drop(server);
            UdpSocket::bind(server_address).unwrap();
        }
    }

    #[test]
    fn controlled_outage_retries_tcp_without_replaying_lost_udp() {
        for ipv6 in [false, true] {
            let (mut client, mut server) = create_pair(ipv6).unwrap();
            run_client_with_outage(
                ipv6,
                Duration::ZERO,
                &mut client.peer,
                &mut client.transport,
                Some((&mut server.peer, &mut server.transport)),
                true,
                None,
            )
            .unwrap();
            assert!(client.transport.dropped_packets >= 2);
            assert!(!client.transport.blackhole);
        }
    }

    #[test]
    fn inbound_blackout_discards_data_without_replaying_after_recovery() {
        for ipv6 in [false, true] {
            let sender = UdpSocket::bind(loopback_address(ipv6)).unwrap();
            let (mut peer, mut transport) =
                create_client(ipv6, sender.local_addr().unwrap()).unwrap();
            let local = transport.socket.local_addr().unwrap();
            transport.inbound_blackhole = true;
            let mut data = [0; 32];
            data[0] = 4;
            for _ in 0..2 {
                assert_eq!(sender.send_to(&data, local).unwrap(), data.len());
            }
            data[0] = 2;
            assert_eq!(sender.send_to(&data, local).unwrap(), data.len());
            let deadline = Instant::now() + Duration::from_secs(2);
            while transport.received_outer < 3 {
                wait_for_outer(&transport.socket, deadline).unwrap();
                transport.pump(&mut peer, Duration::ZERO).unwrap();
            }
            assert_eq!(transport.received_outer, 3);
            assert_eq!(transport.dropped_inbound, 2);
            assert!(!peer.device.has_ingress());
            transport.inbound_blackhole = false;
            transport.pump(&mut peer, Duration::from_millis(1)).unwrap();
            assert_eq!(transport.dropped_inbound, 2);
            assert!(!peer.device.has_ingress());
            assert_eq!(
                transport.socket.recv_from(&mut data).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            drop(transport);
            UdpSocket::bind(local).unwrap();
        }
    }

    #[test]
    fn controlled_initial_handshake_loss_is_counted_without_network_send() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let (mut peer, mut transport) =
            create_client(false, receiver.local_addr().unwrap()).unwrap();
        peer.sockets
            .get_mut::<tcp::Socket>(peer.tcp)
            .connect(
                peer.interface.context(),
                ("10.66.66.10".parse::<std::net::Ipv4Addr>().unwrap(), 9000),
                ("10.66.66.2".parse::<std::net::Ipv4Addr>().unwrap(), 40001),
            )
            .unwrap();
        peer.poll(0);
        transport.drop_first_handshake = true;
        transport.pump(&mut peer, Duration::ZERO).unwrap();
        assert_eq!(transport.initiations, 1);
        assert_eq!(transport.dropped_handshakes, 1);
        assert_eq!(transport.encrypted_packets, 0);
        assert_eq!(
            receiver.recv_from(&mut [0; 256]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn outer_budget_accounts_for_real_ipv4_and_ipv6_encrypted_datagrams() {
        for outer_ipv6 in [false, true] {
            for payload_len in [1412, 1472] {
                let (mut client, mut server) = create_pair_with_outer(false, outer_ipv6).unwrap();
                client.peer = Peer::with_mtu("10.66.66.2".parse().unwrap(), 40000, 1500).unwrap();
                client
                    .peer
                    .sockets
                    .get_mut::<udp::Socket>(client.peer.udp)
                    .send_slice(
                        &vec![0x53; payload_len],
                        "10.66.66.10:9000".parse::<SocketAddr>().unwrap(),
                    )
                    .unwrap();
                client.peer.poll(0);
                client
                    .transport
                    .pump(&mut client.peer, Duration::ZERO)
                    .unwrap();
                wait_for_outer(
                    &server.transport.socket,
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
                server
                    .transport
                    .pump(&mut server.peer, Duration::ZERO)
                    .unwrap();
                wait_for_outer(
                    &client.transport.socket,
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
                let result = client.transport.pump(&mut client.peer, Duration::ZERO);
                // 1412 UDP bytes + 28 inner headers + 32 encryption overhead
                // fit exactly in IPv4's 1472-byte outer UDP allowance. IPv6
                // has only 1452 bytes available at the same 1500-byte MTU.
                let expected_delivery = !outer_ipv6 && payload_len == 1412;
                if expected_delivery {
                    result.unwrap();
                } else {
                    assert_eq!(
                        result.unwrap_err().downcast_ref::<path_mtu::Error>(),
                        Some(&path_mtu::Error::PacketTooLarge)
                    );
                }
                let mut bytes = [0; 1600];
                if expected_delivery {
                    let length = receive_outer_data(
                        &server.transport.socket,
                        Instant::now() + Duration::from_secs(2),
                        &mut bytes,
                    )
                    .unwrap();
                    assert_eq!(length, 1472);
                    assert_eq!(bytes[0], 4);
                }
                for _ in 0..PACKET_CAPACITY {
                    match server.transport.socket.recv_from(&mut bytes) {
                        Ok((length, _)) => assert_eq!(
                            length, 32,
                            "only encrypted keepalive may accompany the data"
                        ),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("controlled outer receiver failed: {error}"),
                    }
                }
            }
        }
    }
}
