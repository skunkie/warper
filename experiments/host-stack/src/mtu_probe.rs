// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled fixed-MTU and ICMP capability evidence for pinned smoltcp.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result, ensure};
use smoltcp::{
    phy::ChecksumCapabilities,
    socket::{tcp, udp},
    wire::{
        Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, Icmpv6DstUnreachable, Icmpv6Packet,
        Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6FragmentHeader, Ipv6FragmentRepr,
        Ipv6Packet, Ipv6Repr, TcpPacket,
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
        fragments_not_reassembled(ipv6)?;
        println!("PASS fixed 1280-byte TCP segmentation and ICMP port-unreachable, IPv6={ipv6}");
        println!("LIMITATION dynamic PMTU and fragment reassembly unavailable, IPv6={ipv6}");
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

fn tcp_sample(ipv6: bool, mtu: usize) -> Result<Vec<u8>> {
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

fn too_big(quote: &[u8], ipv6: bool) -> Result<Vec<u8>> {
    ensure!(
        quote.len() > MTU,
        "PTB fixture requires a genuinely oversized quote"
    );
    let checksums = ChecksumCapabilities::default();
    let (source, destination) = addresses(ipv6)?;
    if ipv6 {
        let ip = Ipv6Packet::new_checked(quote)?;
        let header = Ipv6Repr::parse(&ip)?;
        let repr = Icmpv6Repr::PktTooBig {
            mtu: MTU as u32,
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
                && icmp.pkt_too_big_mtu() == 1280
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
        bytes[26..28].copy_from_slice(&(MTU as u16).to_be_bytes());
        Icmpv4Packet::new_unchecked(&mut bytes[20..]).fill_checksum();
        let ip = Ipv4Packet::new_checked(&bytes[..])?;
        let icmp = Icmpv4Packet::new_checked(ip.payload())?;
        ensure!(
            u8::from(icmp.msg_type()) == 3
                && icmp.msg_code() == 4
                && icmp.data() == &quote[..28]
                && icmp.verify_checksum()
                && u16::from_be_bytes([bytes[26], bytes[27]]) == 1280,
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
    fn fixed_mtu_and_icmp_work_but_dynamic_pmtu_gate_stays_closed() {
        let error = run_probe().unwrap_err();
        assert!(
            error.downcast_ref::<UnsupportedPmtu>().is_some(),
            "unexpected probe failure: {error:#}"
        );
    }
}
