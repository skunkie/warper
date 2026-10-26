// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled fixed-MTU and ICMP capability evidence for pinned smoltcp.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use smoltcp::{
    iface::{Config, Interface, PollIngressSingleResult},
    phy::{ChecksumCapabilities, Device},
    socket::{tcp, udp},
    time::Instant,
    wire::{
        HardwareAddress, Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, Icmpv6DstUnreachable,
        Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6FragmentHeader,
        Ipv6FragmentRepr, Ipv6Packet, Ipv6Repr, TcpPacket,
    },
};

use crate::packet_peer::{MTU, Peer};

#[derive(Debug)]
pub struct UnsupportedPmtu;

impl fmt::Display for UnsupportedPmtu {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("dynamic path MTU discovery is unsupported by the pinned stack candidate")
    }
}

impl std::error::Error for UnsupportedPmtu {}

pub fn run_probe() -> Result<()> {
    for ipv6 in [false, true] {
        port_unreachable(ipv6).context(format!("ICMP port-unreachable IPv6={ipv6}"))?;
        let fixed = tcp_sample(ipv6, MTU)?;
        ensure!(fixed.len() <= MTU, "fixed-MTU TCP exceeded its link budget");
        let before = tcp_sample(ipv6, 1500)?;
        ensure!(
            before.len() > MTU,
            "PMTU fixture did not exercise an oversized TCP segment"
        );
        pmtu_ignored(ipv6).context(format!("PMTU capability IPv6={ipv6}"))?;
        for advertised_mtu in [MTU, 1400] {
            interface_mtu_reduction(ipv6, advertised_mtu)?;
        }
        println!("PASS matched too-big feedback resizes retained TCP sockets, IPv6={ipv6}");
        fragments_not_reassembled(ipv6)?;
        crate::fragment_probe::run_probe(ipv6)?;
        println!("PASS fixed 1280-byte TCP segmentation and ICMP port-unreachable, IPv6={ipv6}");
        println!("PASS bounded pre-admission fragment input, IPv6={ipv6}");
        println!("LIMITATION dynamic PMTU remains unavailable, IPv6={ipv6}");
    }
    Err(UnsupportedPmtu.into())
}

fn addresses(ipv6: bool) -> Result<(IpAddr, IpAddr)> {
    Ok(if ipv6 {
        ("fd66:66::2".parse()?, "fd66:66::10".parse()?)
    } else {
        ("10.66.66.2".parse()?, "10.66.66.10".parse()?)
    })
}

fn peers(ipv6: bool, mtu: usize) -> Result<(Peer, Peer)> {
    let (source, destination) = addresses(ipv6)?;
    let mut client = Peer::with_mtu(source, 40000, mtu)?;
    let mut server = Peer::with_mtu(destination, 9000, mtu)?;
    server
        .sockets
        .get_mut::<tcp::Socket>(server.tcp)
        .listen((destination, 9000))?;
    client.sockets.get_mut::<tcp::Socket>(client.tcp).connect(
        client.interface.context(),
        (destination, 9000),
        (source, 40001),
    )?;
    for step in 0..20 {
        exchange(&mut client, &mut server, step)?;
        if client.sockets.get::<tcp::Socket>(client.tcp).state() == tcp::State::Established {
            return Ok((client, server));
        }
    }
    anyhow::bail!("MTU fixture handshake exceeded controlled budget")
}

fn exchange(client: &mut Peer, server: &mut Peer, now: i64) -> Result<()> {
    client.poll(now);
    server.poll(now);
    while let Some(packet) = client.device.outgoing.pop_front() {
        server.device.inject(packet)?;
    }
    while let Some(packet) = server.device.outgoing.pop_front() {
        client.device.inject(packet)?;
    }
    Ok(())
}

pub(super) fn tcp_sample(ipv6: bool, mtu: usize) -> Result<Vec<u8>> {
    let (mut client, _server) = peers(ipv6, mtu)?;
    client.device.outgoing.clear();
    client
        .sockets
        .get_mut::<tcp::Socket>(client.tcp)
        .send_slice(&[0x61; 4096])?;
    client.poll(20);
    client
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("MTU fixture emitted no data"))
}

fn pmtu_ignored(ipv6: bool) -> Result<()> {
    let (mut client, _server) = peers(ipv6, 1500)?;
    client.device.outgoing.clear();
    client
        .sockets
        .get_mut::<tcp::Socket>(client.tcp)
        .send_slice(&[0x61; 4096])?;
    client.poll(20);
    let first = client
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing quoted TCP packet"))?;
    ensure!(
        first.len() > MTU,
        "PTB quote was not an oversized data packet"
    );
    let header_len = if ipv6 { 40 } else { 20 };
    let original_sequence = TcpPacket::new_checked(&first[header_len..])?.seq_number();
    client.device.outgoing.clear();
    let error = too_big(&first, ipv6)?;
    client.device.inject(error)?;
    client.poll(21);
    client.device.outgoing.clear();
    // Drop data rather than ACK it. Inspect the actual timer-driven retry,
    // not just an application-side capacity value or a parser result.
    for step in 22..3000 {
        client.poll(step);
        while let Some(packet) = client.device.outgoing.pop_front() {
            if packet.len() > MTU
                && TcpPacket::new_checked(&packet[header_len..])?.seq_number() == original_sequence
            {
                return Ok(());
            }
        }
    }
    anyhow::bail!("pinned stack behavior changed: no oversized retry after valid Packet Too Big")
}

fn interface_mtu_reduction(ipv6: bool, advertised_mtu: usize) -> Result<()> {
    let (mut client, mut server) = peers(ipv6, 1500)?;
    for now in 20..30 {
        exchange(&mut client, &mut server, now)?;
    }
    server
        .sockets
        .get_mut::<tcp::Socket>(server.tcp)
        .set_ack_delay(None);
    let endpoints = {
        let socket = client.sockets.get::<tcp::Socket>(client.tcp);
        (socket.local_endpoint(), socket.remote_endpoint())
    };
    let payload: Vec<_> = (0..8192).map(|offset| (offset % 251) as u8).collect();
    let response_payload = b"response-after-resize-fin";
    let socket = client.sockets.get_mut::<tcp::Socket>(client.tcp);
    ensure!(
        socket.send_slice(&payload)? == payload.len(),
        "partial resize workload admission"
    );
    socket.close();
    client.poll(30);
    let first = client
        .device
        .outgoing
        .pop_front()
        .context("no initial TCP data")?;
    ensure!(
        first.len() > MTU,
        "initial path did not emit large TCP data"
    );
    server.device.inject(first)?;
    server.poll(31);
    let mut received = Vec::with_capacity(payload.len());
    drain_tcp(&mut server, &mut received, payload.len())?;
    ensure!(
        !received.is_empty() && received.len() < payload.len(),
        "no partial delivery before path reduction"
    );
    // Deliberate network loss, not adapter eviction. Retained TCP send state
    // owns retries; the application does not repeat send_slice.
    let lost = client
        .device
        .outgoing
        .pop_front()
        .context("no oversized packet to drop")?;
    ensure!(lost.len() > MTU);
    let header_len = if ipv6 { 40 } else { 20 };
    let lost_sequence = TcpPacket::new_checked(&lost[header_len..])?.seq_number();
    let dropped_packets = client.device.outgoing.len() + 1;
    client.device.outgoing.clear();
    let prefix_bytes = received.len();
    let mut accepted_ack = None;
    while let Some(ack) = server.device.outgoing.pop_front() {
        let tcp = TcpPacket::new_checked(&ack[header_len..])?;
        if tcp.ack() {
            accepted_ack = Some(tcp.ack_number().0 as u32);
        }
        client.device.inject(ack)?;
    }
    drain_ingress(&mut client, 32)?;
    let remaining = client.sockets.get::<tcp::Socket>(client.tcp).send_queue();
    ensure!(
        remaining > 0 && remaining < payload.len(),
        "partial ACK did not advance retained send state"
    );
    let feedback = too_big_with_mtu(&lost, ipv6, advertised_mtu)?;
    let mut tracker = crate::pmtu_feedback::Tracker::default();
    tracker.reserve(&lost, Duration::from_millis(32), Duration::from_secs(1))?;
    tracker.acknowledge(
        accepted_ack.context("missing accepted prefix ACK")?,
        Duration::from_millis(33),
    )?;
    ensure!(
        apply_feedback(
            &mut client,
            &mut tracker,
            &feedback,
            Duration::from_millis(34)
        )?,
        "valid too-big feedback did not resize the interface"
    );
    ensure!(
        tracker.next_deadline().is_none(),
        "successful reduction retained its reservation"
    );
    tracker.cancel();
    ensure!(
        client.device.capabilities().max_transmission_unit == advertised_mtu,
        "feedback did not set its advertised MTU"
    );
    ensure!(client.sockets.get::<tcp::Socket>(client.tcp).send_queue() == remaining);
    let mut replied = false;
    let mut response = Vec::with_capacity(response_payload.len());
    let mut emitted_packets = 0;
    let mut emitted_retry = false;
    for now in 35..5000 {
        client.poll(now);
        while let Some(packet) = client.device.outgoing.pop_front() {
            ensure!(
                packet.len() <= advertised_mtu,
                "resized sender emitted oversized TCP packet"
            );
            let header_len = if ipv6 { 40 } else { 20 };
            emitted_packets += 1;
            let tcp = TcpPacket::new_checked(&packet[header_len..])?;
            if !tcp.payload().is_empty() && tcp.seq_number() == lost_sequence {
                emitted_retry = true;
            }
            server.device.inject(packet)?;
        }
        server.poll(now);
        drain_tcp(&mut server, &mut received, payload.len())?;
        ensure!(
            received.len() <= payload.len(),
            "resize duplicated application bytes"
        );
        let socket = server.sockets.get_mut::<tcp::Socket>(server.tcp);
        if !socket.may_recv() && !replied {
            ensure!(received == payload, "resize changed bytes before FIN");
            ensure!(socket.send_slice(response_payload)? == response_payload.len());
            socket.close();
            replied = true;
        }
        while let Some(packet) = server.device.outgoing.pop_front() {
            client.device.inject(packet)?;
        }
        drain_tcp(&mut client, &mut response, response_payload.len())?;
        let socket = client.sockets.get::<tcp::Socket>(client.tcp);
        if replied && !socket.may_recv() {
            ensure!(emitted_retry && response == response_payload);
            ensure!(
                (socket.local_endpoint(), socket.remote_endpoint()) == endpoints,
                "resize changed the connection tuple"
            );
            println!(
                "MTU reduction: IPv6={ipv6}, advertised_mtu={advertised_mtu}, acknowledged_prefix_bytes={prefix_bytes}, delivered_bytes={}, dropped_packets={dropped_packets}, resized_packets={emitted_packets}, controlled_recovery_ms={}",
                received.len() + response.len(),
                now - 34
            );
            return Ok(());
        }
    }
    anyhow::bail!("retained TCP connection failed to complete after interface reduction")
}

fn drain_tcp(peer: &mut Peer, output: &mut Vec<u8>, limit: usize) -> Result<()> {
    let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
    // A receive ring can contain two contiguous slices around its wrap point.
    for _ in 0..2 {
        if !socket.can_recv() {
            break;
        }
        let within_limit = socket.recv(|bytes| {
            if bytes.len() > limit.saturating_sub(output.len()) {
                return (0, false);
            }
            output.extend_from_slice(bytes);
            (bytes.len(), true)
        })?;
        ensure!(
            within_limit,
            "TCP receive exceeded the controlled byte budget"
        );
    }
    Ok(())
}

fn drain_ingress(peer: &mut Peer, now: i64) -> Result<()> {
    for _ in 0..=crate::packet_peer::PACKET_CAPACITY {
        if peer.interface.poll_ingress_single(
            Instant::from_millis(now),
            &mut peer.device,
            &mut peer.sockets,
        ) == PollIngressSingleResult::None
        {
            return Ok(());
        }
    }
    anyhow::bail!("ingress drain exceeded bounded device capacity")
}

fn apply_feedback(
    peer: &mut Peer,
    tracker: &mut crate::pmtu_feedback::Tracker,
    packet: &[u8],
    now: Duration,
) -> Result<bool> {
    let Some(mtu) = tracker.reduction(packet, now)? else {
        return Ok(false);
    };
    if mtu >= peer.device.capabilities().max_transmission_unit {
        return Ok(false);
    }
    rebuild_interface(peer, mtu, i64::try_from(now.as_millis())?)?;
    tracker.commit();
    Ok(true)
}

fn rebuild_interface(peer: &mut Peer, mtu: usize, now: i64) -> Result<()> {
    let addresses = peer.interface.ip_addrs().to_vec();
    let any_ip = peer.interface.any_ip();
    let mut routes = None;
    peer.interface
        .routes_mut()
        .update(|entries| routes = Some(entries.clone()));
    let routes = routes.context("route snapshot not captured")?;
    // Device validation occurs before mutation and refuses both queue kinds.
    peer.device.configure_mtu(mtu)?;
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x5361;
    let mut interface = Interface::new(config, &mut peer.device, Instant::from_millis(now));
    interface.update_ip_addrs(|entries| {
        for address in addresses {
            // The source and destination tables have identical fixed capacity.
            entries
                .push(address)
                .expect("previously admitted interface addresses");
        }
    });
    interface.routes_mut().update(|entries| *entries = routes);
    interface.set_any_ip(any_ip);
    peer.interface = interface;
    Ok(())
}

pub(super) fn too_big(quote: &[u8], ipv6: bool) -> Result<Vec<u8>> {
    too_big_with_mtu(quote, ipv6, MTU)
}

fn too_big_with_mtu(quote: &[u8], ipv6: bool, mtu: usize) -> Result<Vec<u8>> {
    ensure!((MTU..=1500).contains(&mtu), "unsupported fixture MTU");
    ensure!(
        quote.len() > mtu,
        "PTB fixture requires a genuinely oversized quote"
    );
    let checksums = ChecksumCapabilities::default();
    let (source, destination) = addresses(ipv6)?;
    if ipv6 {
        let ip = Ipv6Packet::new_checked(quote)?;
        let header = Ipv6Repr::parse(&ip)?;
        let repr = Icmpv6Repr::PktTooBig {
            mtu: mtu as u32,
            header,
            data: &ip.payload()[..1192],
        };
        let mut bytes = vec![0; 40 + repr.buffer_len()];
        Ipv6Repr {
            src_addr: match destination {
                IpAddr::V6(value) => value,
                _ => unreachable!("fixed family"),
            },
            dst_addr: match source {
                IpAddr::V6(value) => value,
                _ => unreachable!("fixed family"),
            },
            next_header: IpProtocol::Icmpv6,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));
        repr.emit(
            &ip.dst_addr(),
            &ip.src_addr(),
            &mut Icmpv6Packet::new_unchecked(&mut bytes[40..]),
            &checksums,
        );
        bytes[48..].copy_from_slice(&quote[..1232]);
        Icmpv6Packet::new_unchecked(&mut bytes[40..]).fill_checksum(&ip.dst_addr(), &ip.src_addr());
        let ip = Ipv6Packet::new_checked(&bytes[..])?;
        let icmp = Icmpv6Packet::new_checked(ip.payload())?;
        ensure!(
            u8::from(icmp.msg_type()) == 2
                && icmp.msg_code() == 0
                && icmp.pkt_too_big_mtu() == mtu as u32
                && icmp.payload() == &quote[..1232]
                && icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()),
            "PTB fixture checksum, MTU, or exact quote changed"
        );
        Ok(bytes)
    } else {
        let ip = Ipv4Packet::new_checked(quote)?;
        let header = Ipv4Repr::parse(&ip, &checksums)?;
        let repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::FragRequired,
            header,
            data: &ip.payload()[..8],
        };
        let mut bytes = vec![0; 20 + repr.buffer_len()];
        Ipv4Repr {
            src_addr: match destination {
                IpAddr::V4(value) => value,
                _ => unreachable!("fixed family"),
            },
            dst_addr: match source {
                IpAddr::V4(value) => value,
                _ => unreachable!("fixed family"),
            },
            next_header: IpProtocol::Icmp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..]), &checksums);
        repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut bytes[20..]),
            &checksums,
        );
        bytes[28..].copy_from_slice(&quote[..28]);
        // The pinned ICMPv4 representation omits RFC 1191's next-hop MTU.
        // Set that non-cryptographic wire field, then use the library checksum.
        bytes[26..28].copy_from_slice(&(mtu as u16).to_be_bytes());
        Icmpv4Packet::new_unchecked(&mut bytes[20..]).fill_checksum();
        let ip = Ipv4Packet::new_checked(&bytes[..])?;
        let icmp = Icmpv4Packet::new_checked(ip.payload())?;
        ensure!(
            u8::from(icmp.msg_type()) == 3
                && icmp.msg_code() == 4
                && icmp.data() == &quote[..28]
                && icmp.verify_checksum()
                && u16::from_be_bytes([bytes[26], bytes[27]]) == mtu as u16,
            "IPv4 too-big checksum, MTU, or exact quote changed"
        );
        Ok(bytes)
    }
}

fn fragments_not_reassembled(ipv6: bool) -> Result<()> {
    let (source, destination) = addresses(ipv6)?;
    let mut client = Peer::new(source, 40000)?;
    client
        .sockets
        .get_mut::<udp::Socket>(client.udp)
        .send_slice(&[0x53; 200], SocketAddr::new(destination, 9000))?;
    client.poll(0);
    let original = client
        .device
        .outgoing
        .pop_front()
        .context("missing UDP fragmentation sample")?;
    let checksums = ChecksumCapabilities::default();
    let mut fragments = Vec::new();
    for (offset, length, more) in [(0, 128, true), (128, 80, false)] {
        if ipv6 {
            let ip = Ipv6Packet::new_checked(&original[..])?;
            let mut repr = Ipv6Repr::parse(&ip)?;
            repr.next_header = IpProtocol::Ipv6Frag;
            repr.payload_len = 8 + length;
            let mut bytes = vec![0; 48 + length];
            repr.emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));
            bytes[40] = u8::from(IpProtocol::Udp);
            Ipv6FragmentRepr {
                frag_offset: (offset / 8) as u16,
                more_frags: more,
                ident: 42,
            }
            .emit(&mut Ipv6FragmentHeader::new_unchecked(&mut bytes[42..48]));
            bytes[48..].copy_from_slice(&ip.payload()[offset..offset + length]);
            fragments.push(bytes);
        } else {
            let ip = Ipv4Packet::new_checked(&original[..])?;
            let mut repr = Ipv4Repr::parse(&ip, &checksums)?;
            repr.payload_len = length;
            let mut bytes = vec![0; 20 + length];
            let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
            repr.emit(&mut packet, &checksums);
            packet.set_dont_frag(false);
            packet.set_more_frags(more);
            packet.set_frag_offset(offset as u16);
            packet.set_ident(42);
            packet.fill_checksum();
            packet
                .payload_mut()
                .copy_from_slice(&ip.payload()[offset..offset + length]);
            fragments.push(bytes);
        }
    }
    for order in [[0, 1], [1, 0]] {
        let mut server = Peer::new(destination, 9000)?;
        for index in order {
            server.device.inject(fragments[index].clone())?;
        }
        server.poll(1);
        ensure!(
            !server.sockets.get::<udp::Socket>(server.udp).can_recv(),
            "fragment reassembly unexpectedly became available; reassess the capability gate"
        );
    }
    let mut server = Peer::new(destination, 9000)?;
    server.device.inject(original)?;
    server.poll(2);
    let (payload, _) = server.sockets.get_mut::<udp::Socket>(server.udp).recv()?;
    ensure!(
        payload == [0x53; 200],
        "unfragmented control datagram failed"
    );
    Ok(())
}

fn port_unreachable(ipv6: bool) -> Result<()> {
    let (source, destination) = addresses(ipv6)?;
    let mut client = Peer::new(source, 40000)?;
    let mut server = Peer::new(destination, 9000)?;
    client
        .sockets
        .get_mut::<udp::Socket>(client.udp)
        .send_slice(b"sample", SocketAddr::new(destination, 9001))?;
    client.poll(0);
    let original = client
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing UDP request"))?;
    server.device.inject(original)?;
    server.poll(1);
    let response = server
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("stack did not emit port unreachable"))?;
    let checksums = ChecksumCapabilities::default();
    if ipv6 {
        let ip = Ipv6Packet::new_checked(&response[..])?;
        ensure!(
            ip.src_addr() == destination && ip.dst_addr() == source,
            "ICMPv6 endpoints changed"
        );
        ensure!(
            matches!(
                Icmpv6Repr::parse(
                    &ip.src_addr(),
                    &ip.dst_addr(),
                    &Icmpv6Packet::new_checked(ip.payload())?,
                    &checksums
                )?,
                Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    ..
                }
            ),
            "missing valid ICMPv6 port-unreachable"
        );
    } else {
        let ip = Ipv4Packet::new_checked(&response[..])?;
        ensure!(
            IpAddr::V4(ip.src_addr()) == destination && IpAddr::V4(ip.dst_addr()) == source,
            "ICMPv4 endpoints changed"
        );
        ensure!(
            matches!(
                Icmpv4Repr::parse(&Icmpv4Packet::new_checked(ip.payload())?, &checksums)?,
                Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    ..
                }
            ),
            "missing valid ICMPv4 port-unreachable"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_tcp_transfer_completes_after_interface_mtu_reduction() {
        for ipv6 in [false, true] {
            for advertised_mtu in [MTU, 1400] {
                interface_mtu_reduction(ipv6, advertised_mtu).unwrap();
            }
        }
    }

    #[test]
    fn tcp_receive_budget_refuses_excess_without_consuming_bytes() {
        for ipv6 in [false, true] {
            let (mut client, mut server) = peers(ipv6, 1500).unwrap();
            let payload = b"bounded-receive";
            client
                .sockets
                .get_mut::<tcp::Socket>(client.tcp)
                .send_slice(payload)
                .unwrap();
            for now in 20..30 {
                exchange(&mut client, &mut server, now).unwrap();
            }
            let mut received = Vec::new();
            assert!(drain_tcp(&mut server, &mut received, 1).is_err());
            assert!(received.is_empty());
            drain_tcp(&mut server, &mut received, payload.len()).unwrap();
            assert_eq!(received, payload);
        }
    }

    #[test]
    fn interface_replacement_preserves_configuration_and_refuses_queued_input() {
        use smoltcp::{
            iface::Route,
            phy::{Device, RxToken},
            wire::IpCidr,
        };

        for ipv6 in [false, true] {
            let (source, destination) = addresses(ipv6).unwrap();
            let mut peer = Peer::with_mtu(source, 40000, 1500).unwrap();
            peer.interface.set_any_ip(true);
            let route = Route {
                cidr: IpCidr::new(destination.into(), if ipv6 { 128 } else { 32 }),
                via_router: destination.into(),
                preferred_until: Some(Instant::from_millis(500)),
                expires_at: Some(Instant::from_millis(1000)),
            };
            peer.interface
                .routes_mut()
                .update(|entries| entries.push(route).unwrap());
            let addresses = peer.interface.ip_addrs().to_vec();
            peer.device.inject(vec![0x53; 1500]).unwrap();
            let error = rebuild_interface(&mut peer, MTU, 10).unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(peer.device.capabilities().max_transmission_unit, 1500);
            assert_eq!(peer.interface.ip_addrs(), addresses);
            let (packet, _) = peer.device.receive(Instant::from_millis(10)).unwrap();
            packet.consume(|bytes| assert_eq!(bytes, &[0x53; 1500]));
            rebuild_interface(&mut peer, MTU, 11).unwrap();
            assert_eq!(peer.device.capabilities().max_transmission_unit, MTU);
            assert_eq!(peer.interface.ip_addrs(), addresses);
            assert!(peer.interface.any_ip());
            peer.interface.routes_mut().update(|entries| {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].cidr, route.cidr);
                assert_eq!(entries[0].via_router, route.via_router);
                assert_eq!(entries[0].preferred_until, route.preferred_until);
                assert_eq!(entries[0].expires_at, route.expires_at);
            });
        }
    }

    #[test]
    fn matched_feedback_queue_refusal_preserves_reservation_for_retry() {
        use smoltcp::phy::RxToken;
        for ipv6 in [false, true] {
            let packet = tcp_sample(ipv6, 1500).unwrap();
            let feedback = too_big(&packet, ipv6).unwrap();
            let (source, _) = addresses(ipv6).unwrap();
            let mut peer = Peer::with_mtu(source, 40000, 1500).unwrap();
            let mut tracker = crate::pmtu_feedback::Tracker::default();
            tracker
                .reserve(&packet, Duration::ZERO, Duration::from_secs(1))
                .unwrap();
            let mut corrupt = feedback.clone();
            corrupt[if ipv6 { 42 } else { 22 }] ^= 1;
            assert!(
                !apply_feedback(&mut peer, &mut tracker, &corrupt, Duration::from_millis(1))
                    .unwrap()
            );
            assert_eq!(peer.device.capabilities().max_transmission_unit, 1500);
            peer.device.inject(vec![0x53; 1500]).unwrap();
            let error =
                apply_feedback(&mut peer, &mut tracker, &feedback, Duration::from_millis(2))
                    .unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(tracker.next_deadline(), Some(Duration::from_secs(1)));
            assert_eq!(peer.device.capabilities().max_transmission_unit, 1500);
            let (pending, _) = peer.device.receive(Instant::from_millis(2)).unwrap();
            pending.consume(|bytes| assert_eq!(bytes, &[0x53; 1500]));
            assert!(
                apply_feedback(&mut peer, &mut tracker, &feedback, Duration::from_millis(3))
                    .unwrap()
            );
            assert_eq!(peer.device.capabilities().max_transmission_unit, MTU);
            assert!(tracker.next_deadline().is_none());
            assert!(
                !apply_feedback(&mut peer, &mut tracker, &feedback, Duration::from_millis(4))
                    .unwrap()
            );
        }
    }

    #[test]
    fn matched_feedback_never_grows_the_current_interface_and_expires_without_mutation() {
        for ipv6 in [false, true] {
            let packet = tcp_sample(ipv6, 1500).unwrap();
            let feedback = too_big(&packet, ipv6).unwrap();
            let (source, _) = addresses(ipv6).unwrap();
            let mut peer = Peer::new(source, 40000).unwrap();
            let mut tracker = crate::pmtu_feedback::Tracker::default();
            tracker
                .reserve(&packet, Duration::ZERO, Duration::from_secs(1))
                .unwrap();
            assert!(
                !apply_feedback(&mut peer, &mut tracker, &feedback, Duration::from_millis(1))
                    .unwrap()
            );
            assert_eq!(tracker.next_deadline(), Some(Duration::from_secs(1)));
            let error = apply_feedback(&mut peer, &mut tracker, &feedback, Duration::from_secs(1))
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::pmtu_feedback::Error>(),
                Some(&crate::pmtu_feedback::Error::Expired)
            );
            assert_eq!(peer.device.capabilities().max_transmission_unit, MTU);
            assert!(tracker.next_deadline().is_none());
        }
    }

    #[test]
    fn fixed_mtu_and_icmp_work_but_dynamic_pmtu_gate_stays_closed() {
        let error = run_probe().unwrap_err();
        assert!(
            error.downcast_ref::<UnsupportedPmtu>().is_some(),
            "unexpected probe failure: {error:#}"
        );
    }
}
