// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fragment ownership, boundaries, and runtime admission regressions.

use super::*;
use crate::{
    fragment_probe::split,
    packet_peer::Peer,
    udp_adapter::{self, UdpAdapter},
};
use smoltcp::socket::udp;

fn sample(ipv6: bool) -> Vec<u8> {
    let source = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
        .parse()
        .unwrap();
    let destination = if ipv6 {
        "[fd66:66::10]:9000"
    } else {
        "10.66.66.10:9000"
    }
    .parse::<std::net::SocketAddr>()
    .unwrap();
    let mut peer = Peer::new(source, 40000).unwrap();
    peer.sockets
        .get_mut::<udp::Socket>(peer.udp)
        .send_slice(&[0x53; 200], destination)
        .unwrap();
    peer.poll(0);
    peer.device.outgoing.pop_front().unwrap()
}

fn pending(input: &mut Reassembler, packet: &[u8], now: Duration) {
    assert!(matches!(input.accept(packet, now), Ok(Outcome::Pending)));
}

fn offset(packet: &mut [u8], offset: usize, more: bool) {
    if packet[0] >> 4 == 4 {
        let mut ip = Ipv4Packet::new_unchecked(packet);
        ip.set_frag_offset(offset as u16);
        ip.set_more_frags(more);
        ip.fill_checksum();
    } else {
        let mut header = Ipv6FragmentHeader::new_unchecked(&mut packet[42..48]);
        header.set_frag_offset((offset / 8) as u16);
        header.set_more_frags(more);
    }
}

#[test]
fn invalid_limits_and_nonfragment_input_preserve_state() {
    for limits in [
        Limits {
            slots: 0,
            ..Limits::default()
        },
        Limits {
            slots: 5,
            ..Limits::default()
        },
        Limits {
            timeout: Duration::ZERO,
            ..Limits::default()
        },
        Limits {
            timeout: Duration::from_secs(61),
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            Reassembler::new(limits),
            Err(Error::InvalidLimits)
        ));
    }
    let mut input = Reassembler::new(Limits::default()).unwrap();
    assert!(matches!(
        input.accept(&[], Duration::ZERO),
        Ok(Outcome::Pass)
    ));
    assert_eq!(input.next_deadline(), None);
}

#[test]
fn accepted_fragment_progress_does_not_renew_the_original_deadline() {
    for ipv6 in [false, true] {
        let original = sample(ipv6);
        let first = split(&original, 42, 64).unwrap()[0].clone();
        let mut middle = first.clone();
        let header = if ipv6 { 48 } else { 20 };
        let original_header = if ipv6 { 40 } else { 20 };
        middle[header..].copy_from_slice(&original[original_header + 64..original_header + 128]);
        offset(&mut middle, 64, true);
        let mut input = Reassembler::new(Limits::default()).unwrap();
        pending(&mut input, &first, Duration::ZERO);
        pending(&mut input, &middle, Duration::from_millis(500));
        assert_eq!(input.next_deadline(), Some(Duration::from_secs(1)));
        input.advance(Duration::from_millis(999)).unwrap();
        assert!(input.next_deadline().is_some());
        input.advance(Duration::from_secs(1)).unwrap();
        assert_eq!(input.next_deadline(), None);
        assert_eq!(input.statistics().timed_out, 1);
        let last = split(&original, 42, 128).unwrap()[1].clone();
        pending(&mut input, &last, Duration::from_secs(1));
        assert_eq!(input.next_deadline(), Some(Duration::from_secs(2)));
    }
}

#[test]
fn unsupported_headers_and_bad_alignment_do_not_allocate_assembly_state() {
    for ipv6 in [false, true] {
        let first = split(&sample(ipv6), 42, 128).unwrap()[0].clone();
        let mut unsupported = first.clone();
        if ipv6 {
            unsupported[40] = 58;
        } else {
            unsupported.splice(20..20, [0; 4]);
            unsupported[0] = 0x46;
            let length = unsupported.len() as u16;
            let mut ip = Ipv4Packet::new_unchecked(&mut unsupported[..]);
            ip.set_total_len(length);
            ip.fill_checksum();
        }
        let mut input = Reassembler::new(Limits::default()).unwrap();
        assert!(matches!(
            input.accept(&unsupported, Duration::ZERO),
            Err(Error::UnsupportedHeaders)
        ));
        let mut misaligned = first;
        misaligned.pop();
        let length = misaligned.len();
        if ipv6 {
            Ipv6Packet::new_unchecked(&mut misaligned[..]).set_payload_len((length - 40) as u16);
        } else {
            let mut ip = Ipv4Packet::new_unchecked(&mut misaligned[..]);
            ip.set_total_len(length as u16);
            ip.fill_checksum();
        }
        assert!(matches!(
            input.accept(&misaligned, Duration::ZERO),
            Err(Error::MalformedPacket)
        ));
        assert_eq!(input.next_deadline(), None);
    }
}

#[test]
fn overlap_discards_entire_datagram_and_retains_nonrenewing_tombstone() {
    for ipv6 in [false, true] {
        let [first, last] = split(&sample(ipv6), 42, 128).unwrap();
        let mut partial = last.clone();
        offset(&mut partial, 64, false);
        for overlapping in [&first, &partial] {
            let mut input = Reassembler::new(Limits {
                slots: 1,
                ..Limits::default()
            })
            .unwrap();
            pending(&mut input, &first, Duration::ZERO);
            assert!(matches!(
                input.accept(overlapping, Duration::from_millis(500)),
                Err(Error::Overlap)
            ));
            assert!(matches!(
                input.accept(&last, Duration::from_millis(900)),
                Err(Error::Discarded)
            ));
            assert_eq!(input.next_deadline(), Some(Duration::from_secs(1)));
            let other = split(&sample(ipv6), 43, 128).unwrap();
            assert!(matches!(
                input.accept(&other[0], Duration::from_millis(999)),
                Err(Error::ResourceLimit)
            ));
            input.advance(Duration::from_secs(1)).unwrap();
            assert_eq!(input.next_deadline(), None);
            pending(&mut input, &other[0], Duration::from_secs(1));
            assert_eq!(input.statistics().discarded, 1);
        }
    }
}

#[test]
fn full_slots_preserve_other_assemblies_and_completion_releases_capacity() {
    for ipv6 in [false, true] {
        let first = split(&sample(ipv6), 1, 128).unwrap();
        let second = split(&sample(ipv6), 2, 128).unwrap();
        let third = split(&sample(ipv6), 3, 128).unwrap();
        let mut input = Reassembler::new(Limits::default()).unwrap();
        pending(&mut input, &first[0], Duration::ZERO);
        pending(&mut input, &second[1], Duration::ZERO);
        assert!(matches!(
            input.accept(&third[0], Duration::ZERO),
            Err(Error::ResourceLimit)
        ));
        assert!(matches!(
            input.accept(&first[1], Duration::ZERO),
            Ok(Outcome::Complete(_))
        ));
        pending(&mut input, &third[0], Duration::ZERO);
        assert!(matches!(
            input.accept(&second[0], Duration::ZERO),
            Ok(Outcome::Complete(_))
        ));
        assert!(matches!(
            input.accept(&third[1], Duration::ZERO),
            Ok(Outcome::Complete(_))
        ));
        assert_eq!(input.statistics().completed, 3);
        assert_eq!(input.next_deadline(), None);
    }
}

#[test]
fn inconsistent_final_lengths_poison_without_publishing_bytes() {
    for ipv6 in [false, true] {
        let [_first, last] = split(&sample(ipv6), 42, 128).unwrap();
        let mut conflicting = last.clone();
        offset(&mut conflicting, 256, false);
        let mut input = Reassembler::new(Limits::default()).unwrap();
        pending(&mut input, &last, Duration::ZERO);
        assert!(matches!(
            input.accept(&conflicting, Duration::ZERO),
            Err(Error::ConflictingEnd)
        ));
        assert!(matches!(
            input.accept(&last, Duration::ZERO),
            Err(Error::Discarded)
        ));
    }
}

#[test]
fn excessive_disjoint_ranges_are_discarded_with_fixed_metadata() {
    for ipv6 in [false, true] {
        let first = split(&sample(ipv6), 42, 8).unwrap()[0].clone();
        let mut input = Reassembler::new(Limits::default()).unwrap();
        for index in 0..5 {
            let mut fragment = first.clone();
            offset(&mut fragment, 8 + index * 16, true);
            let result = input.accept(&fragment, Duration::ZERO);
            if index < 4 {
                assert!(matches!(result, Ok(Outcome::Pending)));
            } else {
                assert!(matches!(result, Err(Error::TooManyRanges)));
            }
        }
        assert_eq!(input.statistics().discarded, 1);
    }
}

#[test]
fn invalid_time_and_cancellation_do_not_release_partial_output() {
    let fragments = split(&sample(false), 42, 128).unwrap();
    let mut input = Reassembler::new(Limits::default()).unwrap();
    pending(&mut input, &fragments[0], Duration::from_millis(100));
    for now in [Duration::ZERO, Duration::MAX] {
        assert!(matches!(
            input.accept(&fragments[1], now),
            Err(Error::InvalidTime)
        ));
        assert_eq!(input.next_deadline(), Some(Duration::from_millis(1100)));
    }
    input.cancel();
    input.cancel();
    assert_eq!(input.next_deadline(), None);
    assert!(matches!(
        input.accept(&fragments[1], Duration::from_millis(200)),
        Err(Error::Cancelled)
    ));
}

#[test]
fn checksum_validation_occurs_before_fragmented_udp_publication() {
    for ipv6 in [false, true] {
        let [first, mut last] = split(&sample(ipv6), 42, 128).unwrap();
        *last.last_mut().unwrap() ^= 1;
        let mut input = Reassembler::new(Limits::default()).unwrap();
        pending(&mut input, &first, Duration::ZERO);
        let Outcome::Complete(packet) = input.accept(&last, Duration::ZERO).unwrap() else {
            panic!("complete set must normalize before transport validation")
        };
        let (mut host, mut accepted) = UdpAdapter::new(
            udp_adapter::Limits::default(),
            crate::udp_probe::select_backend,
        )
        .unwrap();
        assert_eq!(
            host.inject(&packet),
            Err(udp_adapter::Error::MalformedPacket)
        );
        assert!(accepted.try_recv().is_err());
        assert_eq!(host.active_associations(), 0);
    }
}

#[test]
fn ipv6_atomic_fragments_are_independent_of_existing_identification() {
    let original = sample(true);
    let [first, last] = split(&original, 42, 128).unwrap();
    let mut atomic = first[..48].to_vec();
    atomic.extend_from_slice(&original[40..]);
    let length = (atomic.len() - 40) as u16;
    Ipv6Packet::new_unchecked(&mut atomic[..]).set_payload_len(length);
    offset(&mut atomic, 0, false);
    let mut input = Reassembler::new(Limits {
        slots: 1,
        ..Limits::default()
    })
    .unwrap();
    pending(&mut input, &first, Duration::ZERO);
    let Outcome::Complete(packet) = input.accept(&atomic, Duration::from_millis(500)).unwrap()
    else {
        panic!("atomic fragment must bypass queued assembly")
    };
    assert_eq!(packet, original);
    assert_eq!(input.next_deadline(), Some(Duration::from_secs(1)));
    assert!(matches!(
        input.accept(&last, Duration::from_millis(999)),
        Ok(Outcome::Complete(_))
    ));
    assert_eq!(input.statistics().completed, 2);
}

#[test]
fn ipv6_protocol_mismatch_discards_a_shared_identification() {
    let [first, mut last] = split(&sample(true), 42, 128).unwrap();
    last[40] = 6;
    let mut input = Reassembler::new(Limits::default()).unwrap();
    pending(&mut input, &first, Duration::ZERO);
    assert!(matches!(
        input.accept(&last, Duration::ZERO),
        Err(Error::ProtocolMismatch)
    ));
}

#[test]
fn malformed_and_oversized_fragments_do_not_reserve_slots() {
    for ipv6 in [false, true] {
        let [first, last] = split(&sample(ipv6), 42, 128).unwrap();
        let mut oversized = last.clone();
        offset(&mut oversized, 2000, false);
        let mut input = Reassembler::new(Limits::default()).unwrap();
        assert!(matches!(
            input.accept(&oversized, Duration::ZERO),
            Err(Error::PacketTooLarge)
        ));
        let mut malformed = first.clone();
        if ipv6 {
            malformed[41] = 1;
        } else {
            malformed[8] ^= 1;
        }
        assert!(matches!(
            input.accept(&malformed, Duration::ZERO),
            Err(Error::MalformedPacket)
        ));
        assert_eq!(input.next_deadline(), None);
        pending(&mut input, &first, Duration::ZERO);
        assert!(matches!(
            input.accept(&last, Duration::ZERO),
            Ok(Outcome::Complete(_))
        ));
    }
}

#[test]
fn incomplete_tcp_headers_and_short_ipv6_fragment_headers_are_rejected() {
    for ipv6 in [false, true] {
        for at in [8, 32] {
            let mut first = split(&sample(ipv6), 42, at).unwrap()[0].clone();
            let header = if ipv6 { 48 } else { 20 };
            if ipv6 {
                first[40] = 6;
            } else {
                let mut ip = Ipv4Packet::new_unchecked(&mut first[..]);
                ip.set_next_header(IpProtocol::Tcp);
                ip.fill_checksum();
            }
            if at == 32 {
                first[header + 12] = 0xf0;
            }
            let mut input = Reassembler::new(Limits::default()).unwrap();
            assert!(matches!(
                input.accept(&first, Duration::ZERO),
                Err(Error::MalformedPacket)
            ));
            assert_eq!(input.next_deadline(), None);
        }
    }
    let mut short = split(&sample(true), 42, 128).unwrap()[0][..40].to_vec();
    Ipv6Packet::new_unchecked(&mut short[..]).set_payload_len(0);
    let mut input = Reassembler::new(Limits::default()).unwrap();
    assert!(matches!(
        input.accept(&short, Duration::ZERO),
        Err(Error::MalformedPacket)
    ));
    assert!(matches!(
        input.accept(&vec![0; MTU + 1], Duration::ZERO),
        Err(Error::PacketTooLarge)
    ));
}

#[test]
fn completed_fragments_cannot_bypass_backend_selection() {
    for ipv6 in [false, true] {
        let mut original = sample(ipv6);
        let header = if ipv6 { 40 } else { 20 };
        let source = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
            .parse::<IpAddr>()
            .unwrap();
        let destination = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
            .parse::<IpAddr>()
            .unwrap();
        let mut udp = smoltcp::wire::UdpPacket::new_unchecked(&mut original[header..]);
        udp.set_dst_port(9999);
        udp.fill_checksum(&source.into(), &destination.into());
        let fragments = split(&original, 42, 128).unwrap();
        let mut input = Reassembler::new(Limits::default()).unwrap();
        pending(&mut input, &fragments[0], Duration::ZERO);
        let Outcome::Complete(packet) = input.accept(&fragments[1], Duration::ZERO).unwrap() else {
            panic!("complete fragments must normalize")
        };
        let (mut host, mut accepted) = UdpAdapter::new(
            udp_adapter::Limits::default(),
            crate::udp_probe::select_backend,
        )
        .unwrap();
        assert_eq!(
            host.inject(&packet),
            Err(udp_adapter::Error::UnselectedDestination)
        );
        assert!(accepted.try_recv().is_err());
        assert_eq!(host.active_associations(), 0);
    }
}
