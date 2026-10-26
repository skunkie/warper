// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Too-big quote, lifetime and admission boundaries.

use super::*;

pub(super) fn sample(ipv6: bool) -> (Vec<u8>, Vec<u8>) {
    let packet = crate::mtu_probe::tcp_sample(ipv6, 1500).unwrap();
    let mut feedback = crate::mtu_probe::too_big(&packet, ipv6).unwrap();
    // Exercise the minimum header/sequence quote, not incidental extra data.
    feedback.truncate(if ipv6 { 96 } else { 56 });
    refill(&mut feedback, ipv6);
    (packet, feedback)
}

fn reserved(packet: &[u8]) -> Tracker {
    let mut tracker = Tracker::default();
    tracker
        .reserve(packet, Duration::ZERO, Duration::from_secs(1))
        .unwrap();
    tracker
}

fn refill(bytes: &mut [u8], ipv6: bool) {
    if ipv6 {
        let length = bytes.len() - 40;
        let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
        ip.set_payload_len(length as u16);
        let (source, destination) = (ip.src_addr(), ip.dst_addr());
        Icmpv6Packet::new_unchecked(&mut bytes[40..]).fill_checksum(&source, &destination);
    } else {
        let length = bytes.len();
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ip.set_total_len(length as u16);
        ip.fill_checksum();
        Icmpv4Packet::new_unchecked(&mut bytes[20..]).fill_checksum();
    }
}

fn advertise(bytes: &mut [u8], mtu: u32, ipv6: bool) {
    if ipv6 {
        bytes[44..48].copy_from_slice(&mtu.to_be_bytes());
    } else {
        bytes[26..28].copy_from_slice(&(mtu as u16).to_be_bytes());
    }
    refill(bytes, ipv6);
}

#[test]
fn minimum_quotes_derive_the_advertised_reduction_and_commit_once() {
    for ipv6 in [false, true] {
        let (packet, feedback) = sample(ipv6);
        for mtu in [1280, 1400] {
            let mut tracker = reserved(&packet);
            let mut feedback = feedback.clone();
            advertise(&mut feedback, mtu, ipv6);
            assert_eq!(
                tracker.reduction(&feedback, Duration::from_millis(1)),
                Ok(Some(mtu as usize))
            );
            assert_eq!(tracker.next_deadline(), Some(Duration::from_secs(1)));
            tracker.commit();
            assert_eq!(tracker.next_deadline(), None);
            assert_eq!(
                tracker.reduction(&feedback, Duration::from_millis(2)),
                Ok(None)
            );
        }
    }
}

#[test]
fn corrupt_or_unrelated_feedback_cannot_consume_or_renew_the_reservation() {
    for ipv6 in [false, true] {
        let (packet, feedback) = sample(ipv6);
        let mut tracker = reserved(&packet);
        let ip_len = if ipv6 { 40 } else { 20 };
        let quote = ip_len + 8;
        let tcp = quote + ip_len;
        for offset in [
            ip_len,
            ip_len + 1,
            if ipv6 { 39 } else { 19 },
            quote,
            quote + if ipv6 { 6 } else { 9 },
            tcp,
            tcp + 2,
            tcp + 4,
        ] {
            let mut changed = feedback.clone();
            changed[offset] ^= 0x10;
            if !ipv6 {
                Ipv4Packet::new_unchecked(&mut changed[quote..]).fill_checksum();
            }
            refill(&mut changed, ipv6);
            assert_eq!(
                tracker.reduction(&changed, Duration::from_millis(1)),
                Ok(None),
                "mutated offset {offset}"
            );
            assert_eq!(tracker.next_deadline(), Some(Duration::from_secs(1)));
        }
        let mut non_icmp = feedback.clone();
        if ipv6 {
            Ipv6Packet::new_unchecked(&mut non_icmp[..]).set_next_header(IpProtocol::Udp);
        } else {
            Ipv4Packet::new_unchecked(&mut non_icmp[..]).set_next_header(IpProtocol::Udp);
        }
        refill(&mut non_icmp, ipv6);
        assert_eq!(
            tracker.reduction(&non_icmp, Duration::from_millis(1)),
            Ok(None)
        );
        let mut checksum = feedback.clone();
        checksum[ip_len + 2] ^= 1;
        assert_eq!(
            tracker.reduction(&checksum, Duration::from_millis(1)),
            Ok(None)
        );
        if !ipv6 {
            let mut quote_checksum = feedback.clone();
            quote_checksum[quote + 10] ^= 1;
            refill(&mut quote_checksum, ipv6);
            assert_eq!(
                tracker.reduction(&quote_checksum, Duration::from_millis(1)),
                Ok(None)
            );
        }
        for length in 0..feedback.len() {
            assert_eq!(
                tracker.reduction(&feedback[..length], Duration::from_millis(1)),
                Ok(None)
            );
            // Keep the enclosing IP length valid too, so quote/body truncation
            // is checked independently of the outer frame-length check.
            if length >= ip_len + 4 {
                let mut short = feedback[..length].to_vec();
                refill(&mut short, ipv6);
                assert_eq!(
                    tracker.reduction(&short, Duration::from_millis(1)),
                    Ok(None),
                    "short body {length}"
                );
            }
        }
        assert_eq!(
            tracker.reduction(&vec![0; 1501], Duration::from_millis(1)),
            Ok(None)
        );
        assert_eq!(
            tracker.reduction(&feedback, Duration::from_millis(2)),
            Ok(Some(1280))
        );
    }
}

#[test]
fn quoted_addresses_identity_and_original_lengths_must_match() {
    for ipv6 in [false, true] {
        let (packet, feedback) = sample(ipv6);
        let mut tracker = reserved(&packet);
        let quote = if ipv6 { 48 } else { 28 };
        let offsets: &[usize] = if ipv6 { &[4, 23, 39] } else { &[2, 4, 15, 19] };
        for offset in offsets {
            let mut changed = feedback.clone();
            changed[quote + offset] ^= 1;
            if !ipv6 {
                Ipv4Packet::new_unchecked(&mut changed[quote..]).fill_checksum();
            }
            refill(&mut changed, ipv6);
            assert_eq!(
                tracker.reduction(&changed, Duration::ZERO),
                Ok(None),
                "quoted field {offset}"
            );
        }
    }
}

#[test]
fn router_sources_are_allowed_but_nonunicast_sources_are_rejected() {
    for ipv6 in [false, true] {
        let (packet, feedback) = sample(ipv6);
        let mut tracker = reserved(&packet);
        let mut router = feedback.clone();
        if ipv6 {
            Ipv6Packet::new_unchecked(&mut router[..]).set_src_addr("fd66:66::1".parse().unwrap());
        } else {
            Ipv4Packet::new_unchecked(&mut router[..]).set_src_addr("10.66.66.1".parse().unwrap());
        }
        refill(&mut router, ipv6);
        assert_eq!(tracker.reduction(&router, Duration::ZERO), Ok(Some(1280)));
        for source in if ipv6 {
            vec!["::", "ff02::1"]
        } else {
            vec!["0.0.0.0", "224.0.0.1", "255.255.255.255"]
        } {
            let mut changed = feedback.clone();
            if ipv6 {
                Ipv6Packet::new_unchecked(&mut changed[..]).set_src_addr(source.parse().unwrap());
            } else {
                Ipv4Packet::new_unchecked(&mut changed[..]).set_src_addr(source.parse().unwrap());
            }
            refill(&mut changed, ipv6);
            assert_eq!(
                tracker.reduction(&changed, Duration::ZERO),
                Ok(None),
                "source {source}"
            );
        }
    }
}

#[test]
fn unsupported_mtu_and_nonreductions_do_not_consume_the_reservation() {
    for ipv6 in [false, true] {
        let (packet, feedback) = sample(ipv6);
        let mut tracker = reserved(&packet);
        for mtu in [0, 1, 1279] {
            let mut changed = feedback.clone();
            advertise(&mut changed, mtu, ipv6);
            assert_eq!(
                tracker.reduction(&changed, Duration::ZERO),
                Err(Error::UnsupportedMtu)
            );
            // An unrelated quote cannot trigger a typed path error.
            let quote = if ipv6 { 48 } else { 28 };
            changed[quote + if ipv6 { 40 } else { 20 } + 4] ^= 1;
            refill(&mut changed, ipv6);
            assert_eq!(tracker.reduction(&changed, Duration::ZERO), Ok(None));
        }
        for mtu in [1500, 65535] {
            let mut changed = feedback.clone();
            advertise(&mut changed, mtu, ipv6);
            assert_eq!(tracker.reduction(&changed, Duration::ZERO), Ok(None));
        }
        assert_eq!(tracker.next_deadline(), Some(Duration::from_secs(1)));
    }
}

#[test]
fn lifetime_is_nonrenewing_and_expiry_cancellation_and_clock_errors_are_explicit() {
    for ipv6 in [false, true] {
        let (packet, feedback) = sample(ipv6);
        let mut tracker = reserved(&packet);
        assert_eq!(
            tracker.reserve(&packet, Duration::from_millis(1), Duration::from_secs(10)),
            Err(Error::Busy)
        );
        assert_eq!(tracker.next_deadline(), Some(Duration::from_secs(1)));
        assert_eq!(tracker.reduction(&[], Duration::from_millis(999)), Ok(None));
        assert_eq!(
            tracker.reduction(&feedback, Duration::ZERO),
            Err(Error::InvalidTime)
        );
        assert_eq!(
            tracker.reduction(&feedback, Duration::from_secs(1)),
            Err(Error::Expired)
        );
        assert_eq!(tracker.next_deadline(), None);
        tracker
            .reserve(&packet, Duration::from_secs(1), Duration::from_secs(1))
            .unwrap();
        tracker.cancel();
        tracker.cancel();
        assert_eq!(tracker.next_deadline(), None);
        assert_eq!(
            tracker.reduction(&feedback, Duration::from_secs(1)),
            Err(Error::Cancelled)
        );
        assert_eq!(
            tracker.reserve(&packet, Duration::from_secs(1), Duration::from_secs(1)),
            Err(Error::Cancelled)
        );
    }
}

#[test]
fn invalid_packets_lifetimes_and_deadline_overflow_do_not_reserve_capacity() {
    for ipv6 in [false, true] {
        let (packet, _) = sample(ipv6);
        let mut tracker = Tracker::default();
        for lifetime in [Duration::ZERO, Duration::from_secs(11)] {
            assert_eq!(
                tracker.reserve(&packet, Duration::ZERO, lifetime),
                Err(Error::InvalidLifetime)
            );
        }
        for length in 0..packet.len() {
            assert_eq!(
                tracker.reserve(&packet[..length], Duration::ZERO, Duration::from_secs(1)),
                Err(Error::InvalidPacket)
            );
        }
        for source_port in [false, true] {
            let mut zero_port = packet.clone();
            let ip = parse_ip(&zero_port, false).unwrap();
            let (source, destination) = (ip.source, ip.destination);
            let mut tcp = TcpPacket::new_unchecked(&mut zero_port[if ipv6 { 40 } else { 20 }..]);
            if source_port {
                tcp.set_src_port(0);
            } else {
                tcp.set_dst_port(0);
            }
            tcp.fill_checksum(&source.into(), &destination.into());
            assert_eq!(
                tracker.reserve(&zero_port, Duration::ZERO, Duration::from_secs(1)),
                Err(Error::InvalidPacket)
            );
        }
        let mut checksum = packet.clone();
        checksum[if ipv6 { 56 } else { 36 }] ^= 1;
        assert_eq!(
            tracker.reserve(&checksum, Duration::ZERO, Duration::from_secs(1)),
            Err(Error::InvalidPacket)
        );
        assert_eq!(tracker.next_deadline(), None);
        assert_eq!(
            tracker.reserve(&packet, Duration::MAX, Duration::from_secs(1)),
            Err(Error::InvalidTime)
        );
        assert_eq!(
            tracker.reserve(
                &packet,
                Duration::from_millis(i64::MAX as u64),
                Duration::from_secs(1)
            ),
            Err(Error::InvalidTime)
        );
        assert_eq!(tracker.next_deadline(), None);
    }
}

#[test]
fn accepted_ack_retires_only_the_complete_segment_across_sequence_wrap() {
    for ipv6 in [false, true] {
        let (packet, _) = sample(ipv6);
        for (sequence, fin) in [
            (100_u32, false),
            (u32::MAX - 10, false),
            (u32::MAX - 10, true),
        ] {
            let mut packet = packet.clone();
            let ip_len = if ipv6 { 40 } else { 20 };
            let ip = parse_ip(&packet, false).unwrap();
            let (source, destination) = (ip.source, ip.destination);
            let mut tcp = TcpPacket::new_unchecked(&mut packet[ip_len..]);
            tcp.set_seq_number(TcpSeqNumber(sequence as i32));
            tcp.set_fin(fin);
            tcp.fill_checksum(&source.into(), &destination.into());
            let payload_len = TcpPacket::new_checked(&packet[ip_len..])
                .unwrap()
                .payload()
                .len();
            let end = sequence
                .wrapping_add(payload_len as u32)
                .wrapping_add(u32::from(fin));
            let mut tracker = reserved(&packet);
            tracker
                .acknowledge(end.wrapping_sub(1), Duration::from_millis(1))
                .unwrap();
            assert!(tracker.next_deadline().is_some());
            tracker.acknowledge(end, Duration::from_millis(2)).unwrap();
            assert!(tracker.next_deadline().is_none());
            let feedback = crate::mtu_probe::too_big(&packet, ipv6).unwrap();
            assert_eq!(
                tracker.reduction(&feedback, Duration::from_millis(3)),
                Ok(None)
            );
        }
    }
}
