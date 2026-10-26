// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Minimum quote validation and reservation isolation.

use super::*;
use crate::packet_peer::Peer;
use smoltcp::{
    phy::ChecksumCapabilities,
    socket::udp,
    wire::{
        Icmpv4DstUnreachable, Icmpv4Repr, Icmpv6DstUnreachable, Icmpv6Repr, Ipv4Repr, Ipv6Repr,
    },
};

fn sample(ipv6: bool) -> (Vec<u8>, Vec<u8>) {
    let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
        .parse()
        .unwrap();
    let destination: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
        .parse()
        .unwrap();
    let mut peer = Peer::new(source, 40000).unwrap();
    peer.sockets
        .get_mut::<udp::Socket>(peer.udp)
        .send_slice(&[0x53; 257], std::net::SocketAddr::new(destination, 9001))
        .unwrap();
    peer.poll(0);
    let packet = peer.device.outgoing.pop_front().unwrap();
    let caps = ChecksumCapabilities::default();
    let error = if ipv6 {
        let ip = Ipv6Packet::new_checked(&packet[..]).unwrap();
        let repr = Icmpv6Repr::DstUnreachable {
            reason: Icmpv6DstUnreachable::PortUnreachable,
            header: Ipv6Repr::parse(&ip).unwrap(),
            data: &ip.payload()[..8],
        };
        let mut bytes = vec![0; 40 + repr.buffer_len()];
        Ipv6Repr {
            src_addr: ip.dst_addr(),
            dst_addr: ip.src_addr(),
            next_header: IpProtocol::Icmpv6,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));
        repr.emit(
            &ip.dst_addr(),
            &ip.src_addr(),
            &mut Icmpv6Packet::new_unchecked(&mut bytes[40..]),
            &caps,
        );
        // Preserve the emitted packet's original length in its truncated quote.
        bytes[48..].copy_from_slice(&packet[..48]);
        refill(&mut bytes, ipv6);
        bytes
    } else {
        let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
        let repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: Ipv4Repr::parse(&ip, &caps).unwrap(),
            data: &ip.payload()[..8],
        };
        let mut bytes = vec![0; 20 + repr.buffer_len()];
        Ipv4Repr {
            src_addr: ip.dst_addr(),
            dst_addr: ip.src_addr(),
            next_header: IpProtocol::Icmp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..]), &caps);
        repr.emit(&mut Icmpv4Packet::new_unchecked(&mut bytes[20..]), &caps);
        bytes[28..].copy_from_slice(&packet[..28]);
        refill(&mut bytes, ipv6);
        bytes
    };
    (packet, error)
}

fn refill(bytes: &mut [u8], ipv6: bool) {
    if ipv6 {
        let ip = Ipv6Packet::new_unchecked(&bytes[..]);
        let (source, destination) = (ip.src_addr(), ip.dst_addr());
        Icmpv6Packet::new_unchecked(&mut bytes[40..]).fill_checksum(&source, &destination);
    } else {
        Ipv4Packet::new_unchecked(&mut bytes[..]).fill_checksum();
        Icmpv4Packet::new_unchecked(&mut bytes[20..]).fill_checksum();
    }
}

#[test]
fn minimum_quotes_match_without_rewriting_original_lengths() {
    for ipv6 in [false, true] {
        let (packet, error) = sample(ipv6);
        let reservation = Reservation::new(&packet).unwrap();
        assert!(reservation.matches(&error));
        for length in 0..error.len() {
            assert!(
                !reservation.matches(&error[..length]),
                "truncated at {length}"
            );
        }
    }
}

#[test]
fn unrelated_quotes_and_corrupt_feedback_cannot_match() {
    for ipv6 in [false, true] {
        let (packet, error) = sample(ipv6);
        let reservation = Reservation::new(&packet).unwrap();
        let ip_len = if ipv6 { 40 } else { 20 };
        let quote_offset = ip_len + 8;
        let udp_offset = quote_offset + ip_len;
        // Exercise independent fields with otherwise valid outer checksums.
        for offset in [
            ip_len,
            ip_len + 1,
            quote_offset,
            quote_offset + if ipv6 { 6 } else { 9 },
            udp_offset,
            udp_offset + 2,
            udp_offset + 4,
            udp_offset + 6,
        ] {
            let mut changed = error.clone();
            changed[offset] ^= 0x10;
            refill(&mut changed, ipv6);
            assert!(!reservation.matches(&changed), "mutated offset {offset}");
        }
        let mut checksum = error.clone();
        checksum[ip_len + 2] ^= 1;
        assert!(!reservation.matches(&checksum));
        let mut source = error.clone();
        source[if ipv6 { 23 } else { 15 }] ^= 1;
        refill(&mut source, ipv6);
        assert!(!reservation.matches(&source));
        assert!(!reservation.matches(&packet));
        assert!(
            reservation.matches(&error),
            "bad feedback must leave the reservation intact"
        );
    }
}

#[test]
fn invalid_datagrams_and_unsupported_quotes_are_rejected() {
    for ipv6 in [false, true] {
        let (packet, _) = sample(ipv6);
        for length in 0..packet.len() {
            assert_eq!(
                Reservation::new(&packet[..length]),
                Err(Error::InvalidPacket)
            );
        }
        let mut checksum = packet.clone();
        let ip_len = if ipv6 { 40 } else { 20 };
        checksum[ip_len + 6] ^= 1;
        assert_eq!(Reservation::new(&checksum), Err(Error::InvalidPacket));
        assert_eq!(
            Reservation::new(&vec![0; MTU + 1]),
            Err(Error::InvalidPacket)
        );
    }
}

#[test]
fn quoted_addresses_identity_fragments_and_lengths_are_validated() {
    for ipv6 in [false, true] {
        let (packet, error) = sample(ipv6);
        let reservation = Reservation::new(&packet).unwrap();
        let offset = if ipv6 { 48 } else { 28 };
        let fields: &[usize] = if ipv6 {
            &[4, 6, 23, 39]
        } else {
            &[2, 4, 6, 9, 15, 19]
        };
        for field in fields {
            let mut changed = error.clone();
            changed[offset + field] ^= 0x10;
            if !ipv6 {
                Ipv4Packet::new_unchecked(&mut changed[offset..]).fill_checksum();
            }
            refill(&mut changed, ipv6);
            assert!(!reservation.matches(&changed), "quoted field {field}");
        }
        for protocol in [IpProtocol::Tcp, IpProtocol::Ipv6Frag] {
            let mut changed = packet.clone();
            if ipv6 {
                Ipv6Packet::new_unchecked(&mut changed[..]).set_next_header(protocol);
            } else {
                Ipv4Packet::new_unchecked(&mut changed[..]).set_next_header(protocol);
                Ipv4Packet::new_unchecked(&mut changed[..]).fill_checksum();
            }
            assert_eq!(Reservation::new(&changed), Err(Error::InvalidPacket));
        }
    }
}

#[test]
fn reservation_is_single_use_and_busy_or_invalid_admission_preserves_it() {
    for ipv6 in [false, true] {
        let (packet, error) = sample(ipv6);
        let (mut client, _server) = crate::create_pair(ipv6).unwrap();
        assert_eq!(
            client
                .transport
                .watch_udp(&[])
                .unwrap_err()
                .downcast_ref::<Error>(),
            Some(&Error::InvalidPacket)
        );
        assert!(client.transport.udp_feedback.is_none());
        client.transport.watch_udp(&packet).unwrap();
        assert_eq!(
            client
                .transport
                .watch_udp(&[])
                .unwrap_err()
                .downcast_ref::<Error>(),
            Some(&Error::Busy)
        );
        let mut unrelated = error.clone();
        unrelated[if ipv6 { 41 } else { 21 }] = 0;
        refill(&mut unrelated, ipv6);
        client
            .transport
            .inject_inner(&unrelated, &mut client.peer)
            .unwrap();
        assert!(client.transport.udp_feedback.is_some());
        assert_eq!(
            client
                .transport
                .inject_inner(&error, &mut client.peer)
                .unwrap_err()
                .downcast_ref::<Error>(),
            Some(&Error::PortUnreachable)
        );
        assert!(client.transport.udp_feedback.is_none());
        client
            .transport
            .inject_inner(&error, &mut client.peer)
            .unwrap();
    }
}
