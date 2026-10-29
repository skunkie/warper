// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled encrypted inner-path too-big feedback, not outer PMTU discovery.

use std::{
    net::{IpAddr, UdpSocket},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use smoltcp::{
    phy::{ChecksumCapabilities, Device},
    socket::tcp,
    wire::{IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket},
};

use crate::{
    Endpoint, create_pair_with_outer,
    packet_peer::{MTU, Peer},
    path_mtu::PathBudget,
};

pub enum Action {
    Pass,
    Deliver,
    Drop,
    Feedback(Vec<u8>),
}

pub struct PathFixture {
    limit: usize,
    pub dropped: usize,
    pub feedback_sent: usize,
}

impl PathFixture {
    pub(super) fn new(limit: usize) -> Result<Self> {
        ensure!(
            (MTU..1500).contains(&limit),
            "invalid controlled path limit"
        );
        Ok(Self {
            limit,
            dropped: 0,
            feedback_sent: 0,
        })
    }

    pub fn inspect(&mut self, packet: &[u8]) -> Result<Action> {
        let Some(frame) = plain_tcp(packet)? else {
            return Ok(Action::Pass);
        };
        let tcp = TcpPacket::new_checked(frame.payload)?;
        ensure!(
            tcp.verify_checksum(&frame.source.into(), &frame.destination.into()),
            "controlled TCP checksum failed"
        );
        if packet.len() <= self.limit {
            return Ok(Action::Deliver);
        }
        ensure!(
            !tcp.payload().is_empty(),
            "oversized controlled TCP has no data"
        );
        if !frame.ipv6 {
            ensure!(
                Ipv4Packet::new_checked(packet)?.dont_frag(),
                "controlled IPv4 too-big feedback requires DF"
            );
        }
        self.dropped += 1;
        if self.feedback_sent != 0 {
            return Ok(Action::Drop);
        }
        let feedback = crate::pmtu_fixture::too_big(packet, frame.ipv6, self.limit)?;
        self.feedback_sent = 1;
        Ok(Action::Feedback(feedback))
    }
}

pub(super) struct TcpFrame<'a> {
    ipv6: bool,
    pub(super) source: IpAddr,
    pub(super) destination: IpAddr,
    pub(super) payload: &'a [u8],
}

pub(super) fn plain_tcp(packet: &[u8]) -> Result<Option<TcpFrame<'_>>> {
    ensure!(
        packet.len() <= 1500,
        "controlled plaintext exceeded fixture budget"
    );
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(packet)?;
            if ip.next_header() != IpProtocol::Tcp {
                return Ok(None);
            }
            ensure!(
                ip.header_len() == 20
                    && !ip.more_frags()
                    && ip.frag_offset() == 0
                    && packet[6] & 0x80 == 0,
                "unsupported controlled TCP header"
            );
            Ipv4Repr::parse(&ip, &ChecksumCapabilities::default())?;
            ensure!(
                usize::from(ip.total_len()) == packet.len(),
                "controlled IP length mismatch"
            );
            Ok(Some(TcpFrame {
                ipv6: false,
                source: ip.src_addr().into(),
                destination: ip.dst_addr().into(),
                payload: &packet[20..],
            }))
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(packet)?;
            if ip.next_header() != IpProtocol::Tcp {
                return Ok(None);
            }
            Ipv6Repr::parse(&ip)?;
            ensure!(
                usize::from(ip.payload_len()) + 40 == packet.len(),
                "controlled IP length mismatch"
            );
            Ok(Some(TcpFrame {
                ipv6: true,
                source: ip.src_addr().into(),
                destination: ip.dst_addr().into(),
                payload: &packet[40..],
            }))
        }
        _ => anyhow::bail!("invalid controlled IP family"),
    }
}

pub fn run_probe(ipv6: bool) -> Result<()> {
    for outer_ipv6 in [false, true] {
        for limit in [MTU, 1400] {
            run_case(ipv6, outer_ipv6, limit)?;
        }
    }
    Ok(())
}

fn run_case(ipv6: bool, outer_ipv6: bool, limit: usize) -> Result<()> {
    let (mut client, mut server) = create_pair_with_outer(ipv6, outer_ipv6)?;
    let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let destination: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    client.peer = Peer::with_mtu(source, 40000, 1500)?;
    server.peer = Peer::with_mtu(destination, 9000, 1500)?;
    for endpoint in [&mut client, &mut server] {
        endpoint.transport.path_budget = PathBudget::new(1600, outer_ipv6)?;
        endpoint
            .peer
            .sockets
            .get_mut::<tcp::Socket>(endpoint.peer.tcp)
            .set_ack_delay(None);
    }
    server.transport.pmtu_fixture = Some(PathFixture::new(limit)?);
    server
        .peer
        .sockets
        .get_mut::<tcp::Socket>(server.peer.tcp)
        .listen((destination, 9000))?;
    client
        .peer
        .sockets
        .get_mut::<tcp::Socket>(client.peer.tcp)
        .connect(
            client.peer.interface.context(),
            (destination, 9000),
            (source, 40001),
        )?;
    let client_address = client.transport.socket.local_addr()?;
    let server_address = server.transport.socket.local_addr()?;
    let result = transfer(&mut client, &mut server, limit);
    drop(client);
    drop(server);
    let cleanup = (|| -> Result<()> {
        drop(UdpSocket::bind(client_address)?);
        drop(UdpSocket::bind(server_address)?);
        Ok(())
    })();
    match (result, cleanup) {
        (Err(primary), cleanup) => Err(primary.context(match cleanup {
            Ok(()) => "encrypted PMTU endpoints released".into(),
            Err(error) => format!("encrypted PMTU cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => cleanup,
    }
}

fn transfer(client: &mut Endpoint, server: &mut Endpoint, limit: usize) -> Result<()> {
    let payload: Vec<_> = (0..8192).map(|index| (index % 251) as u8).collect();
    let reply = b"encrypted-response-after-fin";
    let mut sent = false;
    let mut reserved = false;
    let mut replied = false;
    let mut request = Vec::with_capacity(payload.len());
    let mut response = Vec::with_capacity(reply.len());
    let mut original_endpoints = None;
    let mut retry_sequence = None;
    let mut observed_retry = false;
    let wall = Instant::now();
    for step in 0..1000 {
        let tick = step * 5;
        ensure!(
            wall.elapsed() < Duration::from_secs(12),
            "encrypted PMTU fixture exceeded wall deadline at step {step}"
        );
        let now = Duration::from_millis(tick);
        client.peer.poll(tick as i64);
        if sent && !reserved {
            let packet = client
                .peer
                .device
                .outgoing
                .front()
                .ok_or_else(|| anyhow::anyhow!("missing reserved encrypted TCP data"))?;
            let frame =
                plain_tcp(packet)?.ok_or_else(|| anyhow::anyhow!("reserved output was not TCP"))?;
            let tcp = TcpPacket::new_checked(frame.payload)?;
            ensure!(
                !tcp.payload().is_empty() && packet.len() > limit,
                "reserved data did not exercise the path limit"
            );
            let sequence = tcp.seq_number();
            client
                .transport
                .watch_pmtu(packet, frame.destination, now)?;
            // Established handshake ACK precedes this first application write.
            client
                .transport
                .pmtu_feedback
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("missing PMTU owner"))?
                .acknowledge(
                    std::net::SocketAddr::new(frame.source, tcp.src_port()),
                    std::net::SocketAddr::new(frame.destination, tcp.dst_port()),
                    sequence.0 as u32,
                    now,
                )?;
            retry_sequence = Some(sequence);
            reserved = true;
        }
        if client.transport.pmtu_reductions != 0 {
            for packet in &client.peer.device.outgoing {
                ensure!(
                    packet.len() <= limit,
                    "resized encrypted sender exceeded advertised MTU"
                );
                if let Some(frame) = plain_tcp(packet)? {
                    let tcp = TcpPacket::new_checked(frame.payload)?;
                    if Some(tcp.seq_number()) == retry_sequence && !tcp.payload().is_empty() {
                        observed_retry = true;
                    }
                }
            }
        }
        client.transport.pump(&mut client.peer, now)?;
        server.peer.poll(tick as i64);
        drain(&mut server.peer, &mut request, payload.len())?;
        let socket = server.peer.sockets.get_mut::<tcp::Socket>(server.peer.tcp);
        if sent && !socket.may_recv() && socket.can_send() && !replied {
            ensure!(request == payload, "encrypted PMTU request/FIN changed");
            ensure!(socket.send_slice(reply)? == reply.len());
            socket.close();
            replied = true;
        }
        server.transport.pump(&mut server.peer, now)?;
        let socket = client.peer.sockets.get_mut::<tcp::Socket>(client.peer.tcp);
        if !sent
            && socket.state() == tcp::State::Established
            && server
                .peer
                .sockets
                .get::<tcp::Socket>(server.peer.tcp)
                .state()
                == tcp::State::Established
        {
            original_endpoints = Some((socket.local_endpoint(), socket.remote_endpoint()));
            ensure!(socket.send_slice(&payload)? == payload.len());
            socket.close();
            sent = true;
        }
        drain(&mut client.peer, &mut response, reply.len())?;
        if replied
            && !client
                .peer
                .sockets
                .get::<tcp::Socket>(client.peer.tcp)
                .may_recv()
        {
            // The final ACK can arrive on a later loopback turn. Keep pumping
            // both endpoints until the peer closes, within the existing deadline.
            server.peer.poll(tick as i64);
            if server
                .peer
                .sockets
                .get::<tcp::Socket>(server.peer.tcp)
                .state()
                != tcp::State::Closed
            {
                crate::pace_fixture(step);
                continue;
            }
            ensure!(
                response == reply && observed_retry,
                "encrypted PMTU response or lost-sequence retry missing"
            );
            let socket = client.peer.sockets.get::<tcp::Socket>(client.peer.tcp);
            ensure!(
                Some((socket.local_endpoint(), socket.remote_endpoint())) == original_endpoints,
                "encrypted PMTU changed the connection tuple"
            );
            ensure!(
                client.transport.pmtu_reductions == 1
                    && client.peer.device.capabilities().max_transmission_unit == limit
            );
            let path = server
                .transport
                .pmtu_fixture
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing controlled path"))?;
            ensure!(path.dropped > 0 && path.feedback_sent == 1);
            ensure!(
                client
                    .transport
                    .pmtu_feedback
                    .as_ref()
                    .is_some_and(|tracker| tracker.next_deadline().is_none())
            );
            let inner_address: IpAddr = client.peer.interface.ip_addrs()[0].address().into();
            println!(
                "encrypted inner PMTU: inner_ipv6={}, outer_ipv6={}, limit={limit}, delivered_bytes={}, dropped_packets={}, reductions=1",
                inner_address.is_ipv6(),
                client.transport.remote.is_ipv6(),
                request.len() + response.len(),
                path.dropped
            );
            return Ok(());
        }
        crate::pace_fixture(step);
    }
    anyhow::bail!("encrypted PMTU connection did not complete")
}

pub(super) fn drain(peer: &mut Peer, output: &mut Vec<u8>, limit: usize) -> Result<()> {
    let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
    for _ in 0..2 {
        if !socket.can_recv() {
            break;
        }
        let accepted = socket.recv(|bytes| {
            if bytes.len() > limit.saturating_sub(output.len()) {
                return (0, false);
            }
            output.extend_from_slice(bytes);
            (bytes.len(), true)
        })?;
        ensure!(accepted, "encrypted PMTU receive exceeded byte budget");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feedback_fixture(ipv6: bool) -> (Endpoint, Vec<u8>) {
        let (mut endpoint, _) = create_pair_with_outer(ipv6, false).unwrap();
        let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
            .parse()
            .unwrap();
        let destination: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
            .parse()
            .unwrap();
        let mut client = Peer::with_mtu(source, 40000, 1500).unwrap();
        let mut server = Peer::with_mtu(destination, 9000, 1500).unwrap();
        server
            .sockets
            .get_mut::<tcp::Socket>(server.tcp)
            .listen((destination, 9000))
            .unwrap();
        client
            .sockets
            .get_mut::<tcp::Socket>(client.tcp)
            .connect(
                client.interface.context(),
                (destination, 9000),
                (source, 40001),
            )
            .unwrap();
        for tick in 0..20 {
            client.poll(tick);
            server.poll(tick);
            while let Some(packet) = client.device.outgoing.pop_front() {
                server.device.inject(packet).unwrap();
            }
            while let Some(packet) = server.device.outgoing.pop_front() {
                client.device.inject(packet).unwrap();
            }
            if client.sockets.get::<tcp::Socket>(client.tcp).state() == tcp::State::Established {
                break;
            }
        }
        assert_eq!(
            client.sockets.get::<tcp::Socket>(client.tcp).state(),
            tcp::State::Established
        );
        client.device.outgoing.clear();
        client
            .sockets
            .get_mut::<tcp::Socket>(client.tcp)
            .send_slice(&[0x61; 4096])
            .unwrap();
        client.poll(20);
        let packet = client.device.outgoing.pop_front().unwrap();
        client.device.outgoing.clear();
        endpoint
            .transport
            .watch_pmtu(&packet, destination, Duration::ZERO)
            .unwrap();
        let feedback = crate::pmtu_fixture::too_big(&packet, ipv6, MTU).unwrap();
        endpoint.peer = client;
        (endpoint, feedback)
    }

    #[test]
    fn transient_seed_failure_retains_feedback_until_bounded_retry() {
        use smoltcp::phy::Device;
        for ipv6 in [false, true] {
            let (mut endpoint, feedback) = feedback_fixture(ipv6);
            let retained_bytes = endpoint
                .peer
                .sockets
                .get::<tcp::Socket>(endpoint.peer.tcp)
                .send_queue();
            assert!(retained_bytes > 0);
            assert!(
                endpoint
                    .transport
                    .handle_pmtu_feedback(&mut endpoint.peer, &feedback, || Err(
                        std::io::ErrorKind::WouldBlock.into()
                    ),)
                    .unwrap()
            );
            assert_eq!(
                endpoint
                    .transport
                    .pending_pmtu_feedback
                    .as_ref()
                    .unwrap()
                    .packet,
                feedback
            );
            assert_eq!(
                endpoint
                    .transport
                    .pmtu_feedback
                    .as_ref()
                    .unwrap()
                    .next_deadline(),
                Some(Duration::from_secs(1))
            );
            assert_eq!(
                endpoint.peer.device.capabilities().max_transmission_unit,
                1500
            );
            assert!(
                endpoint
                    .transport
                    .handle_pmtu_feedback(&mut endpoint.peer, &feedback, || Err(
                        std::io::ErrorKind::PermissionDenied.into()
                    ),)
                    .unwrap(),
                "duplicate feedback must retain the first response without requesting a seed"
            );
            endpoint.transport.now = Duration::from_millis(9);
            endpoint
                .transport
                .retry_pmtu_feedback(&mut endpoint.peer, || {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                })
                .unwrap();
            assert!(endpoint.transport.pending_pmtu_feedback.is_some());
            endpoint.transport.now = Duration::from_millis(10);
            endpoint
                .transport
                .retry_pmtu_feedback(&mut endpoint.peer, || Ok(1))
                .unwrap();
            assert!(endpoint.transport.pending_pmtu_feedback.is_none());
            assert_eq!(
                endpoint.peer.device.capabilities().max_transmission_unit,
                MTU
            );
            assert_eq!(endpoint.transport.pmtu_reductions, 1);
            assert_eq!(
                endpoint
                    .peer
                    .sockets
                    .get::<tcp::Socket>(endpoint.peer.tcp)
                    .send_queue(),
                retained_bytes
            );
            assert_eq!(
                endpoint
                    .transport
                    .pmtu_feedback
                    .as_ref()
                    .unwrap()
                    .next_deadline(),
                None
            );
        }
    }

    #[test]
    fn busy_queue_is_retained_until_retry_and_permanent_seed_failure_is_surfaced() {
        use smoltcp::phy::Device;
        for ipv6 in [false, true] {
            let (mut endpoint, feedback) = feedback_fixture(ipv6);
            let error = endpoint
                .transport
                .handle_pmtu_feedback(&mut endpoint.peer, &feedback, || {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                })
                .unwrap_err();
            assert!(
                error
                    .downcast_ref::<crate::mtu_reduction::SeedError>()
                    .is_some()
            );
            assert!(endpoint.transport.pending_pmtu_feedback.is_none());
            endpoint.peer.device.outgoing.push_back(vec![0x53; 100]);
            assert!(
                endpoint
                    .transport
                    .handle_pmtu_feedback(&mut endpoint.peer, &feedback, || Ok(1))
                    .unwrap()
            );
            endpoint.transport.now = Duration::from_millis(10);
            endpoint
                .transport
                .retry_pmtu_feedback(&mut endpoint.peer, || Ok(2))
                .unwrap();
            assert!(endpoint.transport.pending_pmtu_feedback.is_some());
            assert_eq!(
                endpoint.peer.device.outgoing.pop_front().unwrap(),
                vec![0x53; 100]
            );
            endpoint.transport.now = Duration::from_millis(20);
            endpoint
                .transport
                .retry_pmtu_feedback(&mut endpoint.peer, || Ok(3))
                .unwrap();
            assert!(endpoint.transport.pending_pmtu_feedback.is_none());
            assert_eq!(
                endpoint.peer.device.capabilities().max_transmission_unit,
                MTU
            );
        }
    }

    #[test]
    fn pending_feedback_blocks_replacement_after_reservation_retirement() {
        for ipv6 in [false, true] {
            let (mut endpoint, feedback) = feedback_fixture(ipv6);
            assert!(
                endpoint
                    .transport
                    .handle_pmtu_feedback(&mut endpoint.peer, &feedback, || Err(
                        std::io::ErrorKind::WouldBlock.into()
                    ),)
                    .unwrap()
            );
            endpoint.transport.pmtu_feedback.as_mut().unwrap().commit();
            let reporter: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
                .parse()
                .unwrap();
            let error = endpoint
                .transport
                .watch_pmtu(&[], reporter, Duration::ZERO)
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::pmtu_feedback::Error>(),
                Some(&crate::pmtu_feedback::Error::Busy)
            );
            endpoint.transport.now = Duration::from_millis(10);
            endpoint
                .transport
                .retry_pmtu_feedback(&mut endpoint.peer, || Ok(1))
                .unwrap();
            assert!(endpoint.transport.pending_pmtu_feedback.is_none());
        }
    }

    #[test]
    fn oversized_feedback_cannot_allocate_a_pending_response() {
        use smoltcp::wire::{Icmpv4Packet, Icmpv6Packet, Ipv4Packet, Ipv6Packet};
        for ipv6 in [false, true] {
            let (mut endpoint, mut feedback) = feedback_fixture(ipv6);
            feedback.resize(MTU + 1, 0);
            if ipv6 {
                let mut ip = Ipv6Packet::new_checked(feedback.as_mut_slice()).unwrap();
                ip.set_payload_len((MTU + 1 - 40) as u16);
                let (source, destination) = (ip.src_addr(), ip.dst_addr());
                Icmpv6Packet::new_checked(&mut feedback[40..])
                    .unwrap()
                    .fill_checksum(&source, &destination);
            } else {
                let mut ip = Ipv4Packet::new_checked(feedback.as_mut_slice()).unwrap();
                ip.set_total_len((MTU + 1) as u16);
                ip.fill_checksum();
                Icmpv4Packet::new_checked(&mut feedback[20..])
                    .unwrap()
                    .fill_checksum();
            }
            let error = endpoint
                .transport
                .handle_pmtu_feedback(&mut endpoint.peer, &feedback, || {
                    Err(std::io::ErrorKind::WouldBlock.into())
                })
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::TransportFailure>(),
                Some(&crate::TransportFailure::PmtuFeedbackTooLarge)
            );
            assert!(endpoint.transport.pending_pmtu_feedback.is_none());
            assert_eq!(
                endpoint
                    .transport
                    .pmtu_feedback
                    .as_ref()
                    .unwrap()
                    .next_deadline(),
                Some(Duration::from_secs(1))
            );
        }
    }

    #[test]
    fn retained_feedback_expiry_surfaces_without_reconfiguration() {
        use smoltcp::phy::Device;
        for ipv6 in [false, true] {
            let (mut endpoint, feedback) = feedback_fixture(ipv6);
            assert!(
                endpoint
                    .transport
                    .handle_pmtu_feedback(&mut endpoint.peer, &feedback, || Err(
                        std::io::ErrorKind::WouldBlock.into()
                    ),)
                    .unwrap()
            );
            let error = endpoint
                .transport
                .pump(&mut endpoint.peer, Duration::from_secs(1))
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::pmtu_feedback::Error>(),
                Some(&crate::pmtu_feedback::Error::Expired)
            );
            assert_eq!(
                endpoint.peer.device.capabilities().max_transmission_unit,
                1500
            );
            assert_eq!(endpoint.transport.pmtu_reductions, 0);
        }
    }

    #[test]
    fn encrypted_feedback_resizes_the_same_tcp_connection() {
        for ipv6 in [false, true] {
            run_probe(ipv6).unwrap();
        }
    }

    #[test]
    fn controlled_path_checks_tcp_and_preserves_ordinary_udp_size_limits() {
        use smoltcp::socket::udp;
        for limit in [0, MTU - 1, 1500, usize::MAX] {
            assert!(PathFixture::new(limit).is_err());
        }
        for ipv6 in [false, true] {
            let (mut client, mut server) = create_pair_with_outer(ipv6, false).unwrap();
            let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
                .parse()
                .unwrap();
            let destination: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
                .parse()
                .unwrap();
            client.peer = Peer::with_mtu(source, 40000, 1500).unwrap();
            client
                .peer
                .sockets
                .get_mut::<tcp::Socket>(client.peer.tcp)
                .connect(
                    client.peer.interface.context(),
                    (destination, 9000),
                    (source, 40001),
                )
                .unwrap();
            client.peer.poll(0);
            let mut packet = client.peer.device.outgoing.pop_front().unwrap();
            let mut path = PathFixture::new(1400).unwrap();
            assert!(matches!(path.inspect(&packet).unwrap(), Action::Deliver));
            let last = packet.len() - 1;
            packet[last] ^= 1;
            assert!(path.inspect(&packet).is_err());
            assert_eq!(path.dropped, 0);
            assert_eq!(path.feedback_sent, 0);
            client
                .peer
                .sockets
                .get_mut::<udp::Socket>(client.peer.udp)
                .send_slice(
                    &vec![0x53; if ipv6 { 1452 } else { 1472 }],
                    std::net::SocketAddr::new(destination, 9000),
                )
                .unwrap();
            client.peer.poll(1);
            let packet = client.peer.device.outgoing.pop_front().unwrap();
            assert_eq!(packet.len(), 1500);
            assert!(matches!(path.inspect(&packet).unwrap(), Action::Pass));
            server.transport.pmtu_fixture = Some(path);
            let error = server
                .transport
                .inject_inner(&packet, &mut server.peer)
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::reassembly::Error>(),
                Some(&crate::reassembly::Error::PacketTooLarge)
            );
        }
    }
}
