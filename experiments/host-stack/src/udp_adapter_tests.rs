// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Admission rollback, retained ownership, expiry, and cancellation checks.

use super::*;
use crate::udp_probe::select_backend;

fn sample(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
    encode(
        SocketAddr::from(([10, 66, 66, 2], source)),
        SocketAddr::from(([10, 66, 66, 91], destination)),
        payload,
    )
    .unwrap()
}

#[test]
fn public_udp_boundary_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<UdpAdapter>();
    assert_send::<Association>();
    assert_send::<Datagram>();
}

#[test]
fn unrepresentable_new_association_deadline_preserves_existing_association() {
    let invalid_limits = Limits {
        max_age: Duration::from_millis(crate::MAX_CLOCK_MILLIS as u64 + 1),
        ..Limits::default()
    };
    assert!(matches!(
        UdpAdapter::new(invalid_limits, select_backend),
        Err(Error::InvalidLimits)
    ));
    for ipv6 in [false, true] {
        let limits = Limits {
            idle_timeout: Duration::from_secs(1),
            max_age: Duration::from_secs(1),
            ..Limits::default()
        };
        let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
        let maximum = Duration::from_millis(crate::MAX_CLOCK_MILLIS as u64);
        let start = maximum - Duration::from_secs(1);
        let address = |port| {
            if ipv6 {
                format!("[fd66:66::2]:{port}")
            } else {
                format!("10.66.66.2:{port}")
            }
            .parse::<SocketAddr>()
            .unwrap()
        };
        let destination = if ipv6 {
            "[fd66:66::91]:9000"
        } else {
            "10.66.66.91:9000"
        }
        .parse()
        .unwrap();
        let first = encode(address(40000), destination, b"first").unwrap();
        let second = encode(address(40001), destination, b"second").unwrap();
        assert_eq!(
            host.poll(Duration::from_millis(i64::MAX as u64)),
            Err(Error::InvalidTime)
        );
        host.poll(start).unwrap();
        let id = host.inject(&first).unwrap();
        let association = accepted.try_recv().unwrap();
        host.poll(start + Duration::from_millis(1)).unwrap();
        assert_eq!(host.inject(&second), Err(Error::InvalidTime));
        assert_eq!(host.inject(&first), Ok(id));
        assert_eq!(host.active_associations(), 1);
        assert!(accepted.try_recv().is_err());
        host.poll(maximum).unwrap();
        assert_eq!(host.active_associations(), 0);
        assert_eq!(
            host.poll(maximum + Duration::from_millis(1)),
            Err(Error::InvalidTime)
        );
        assert_eq!(
            host.poll(Duration::from_millis(i64::MAX as u64)),
            Err(Error::InvalidTime)
        );
        drop(association);
        host.cancel();
    }
}

#[tokio::test]
async fn repeated_tuple_keeps_identity_and_backend_without_duplicate_publication() {
    let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
    let packet = sample(40000, 9000, b"first");
    let id = host.inject(&packet).unwrap();
    let mut association = accepted.try_recv().unwrap();
    host.select_backend = |_| None;
    assert_eq!(host.inject(&sample(40000, 9000, b"second")), Ok(id));
    assert!(accepted.try_recv().is_err());
    assert_eq!(association.metadata().backend, BackendId(1));
    assert_eq!(association.recv().await.unwrap().payload(), b"first");
    assert_eq!(association.recv().await.unwrap().payload(), b"second");
    assert_eq!(host.statistics().admitted, 1);
    assert_eq!(host.statistics().received, 2);
}

#[test]
fn accepted_queue_failure_releases_reservations_without_consuming_id() {
    let limits = Limits {
        accepted: 1,
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    assert_eq!(host.inject(&sample(40000, 9000, b"first")), Ok(FlowId(1)));
    assert_eq!(
        host.inject(&sample(40001, 9000, b"second")),
        Err(Error::QueueFull)
    );
    assert_eq!(host.active_associations(), 1);
    let _first = accepted.try_recv().unwrap();
    assert_eq!(host.inject(&sample(40001, 9000, b"second")), Ok(FlowId(2)));
    assert_eq!(host.statistics().rejected, 1);
}

#[tokio::test]
async fn global_datagram_failure_rolls_back_association_and_accept_capacity() {
    let limits = Limits {
        datagrams: 1,
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    host.inject(&sample(40000, 9000, b"first")).unwrap();
    let mut first = accepted.try_recv().unwrap();
    let retained = first.recv().await.unwrap();
    assert_eq!(
        host.inject(&sample(40001, 9000, b"second")),
        Err(Error::ResourceLimit)
    );
    assert!(accepted.try_recv().is_err());
    assert_eq!(host.active_associations(), 1);
    drop(retained);
    assert_eq!(host.inject(&sample(40001, 9000, b"second")), Ok(FlowId(2)));
}

#[tokio::test]
async fn held_datagram_remains_charged_after_expiry_and_association_drop() {
    let limits = Limits {
        associations: 1,
        accepted: 1,
        datagrams: 1,
        idle_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    let packet = sample(40000, 9000, b"retained");
    host.inject(&packet).unwrap();
    let mut association = accepted.try_recv().unwrap();
    let retained = association.recv().await.unwrap();
    host.poll(Duration::from_secs(1)).unwrap();
    drop(association);
    assert_eq!(host.active_associations(), 0);
    assert_eq!(host.inject(&packet), Err(Error::ResourceLimit));
    assert_eq!(retained.payload(), b"retained");
    drop(retained);
    assert_eq!(host.inject(&packet), Ok(FlowId(2)));
}

#[tokio::test]
async fn expired_application_handle_retains_lifetime_charge_and_cannot_reply() {
    let limits = Limits {
        associations: 1,
        accepted: 1,
        idle_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    let packet = sample(40000, 9000, b"sample");
    host.inject(&packet).unwrap();
    let mut association = accepted.try_recv().unwrap();
    drop(association.recv().await.unwrap());
    association.try_reply(b"pending").unwrap();
    host.poll(Duration::ZERO).unwrap();
    association.try_reply(b"queued").unwrap();
    host.poll(Duration::from_secs(1)).unwrap();
    assert!(
        host.take_packet().is_none(),
        "expired output must be withdrawn"
    );
    assert_eq!(host.inject(&packet), Err(Error::ResourceLimit));
    assert_eq!(association.try_reply(b"stale"), Err(Error::TimedOut));
    assert!(matches!(association.recv().await, Err(Error::TimedOut)));
    drop(association);
    assert_eq!(host.inject(&packet), Ok(FlowId(2)));
    host.poll(Duration::from_secs(1)).unwrap();
    assert!(
        host.take_packet().is_none(),
        "old replies must not reach a replacement owner"
    );
}

#[tokio::test]
async fn saturated_input_does_not_refresh_idle_deadline_or_displace_owner() {
    let limits = Limits {
        queue: 1,
        idle_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    let packet = sample(40000, 9000, b"original");
    host.inject(&packet).unwrap();
    let mut association = accepted.try_recv().unwrap();
    host.poll(Duration::from_millis(500)).unwrap();
    assert_eq!(
        host.inject(&sample(40000, 9000, b"overflow")),
        Err(Error::QueueFull)
    );
    assert_eq!(association.recv().await.unwrap().payload(), b"original");
    host.poll(Duration::from_secs(1)).unwrap();
    assert!(matches!(association.recv().await, Err(Error::TimedOut)));
    assert_eq!(host.statistics().timed_out, 1);
}

#[tokio::test]
async fn successful_traffic_refreshes_idle_but_not_absolute_age() {
    let limits = Limits {
        idle_timeout: Duration::from_secs(2),
        max_age: Duration::from_secs(3),
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    let packet = sample(40000, 9000, b"sample");
    host.inject(&packet).unwrap();
    let mut association = accepted.try_recv().unwrap();
    drop(association.recv().await.unwrap());
    host.poll(Duration::from_secs(1)).unwrap();
    host.inject(&packet).unwrap();
    drop(association.recv().await.unwrap());
    host.poll(Duration::from_secs(2)).unwrap();
    association.try_reply(b"reply").unwrap();
    host.poll(Duration::from_secs(2)).unwrap();
    assert!(host.take_packet().is_some());
    host.poll(Duration::from_secs(3)).unwrap();
    assert!(matches!(association.recv().await, Err(Error::TimedOut)));
}

#[tokio::test]
async fn reply_queue_and_global_quota_preserve_already_admitted_messages() {
    let limits = Limits {
        datagrams: 2,
        queue: 1,
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    host.inject(&sample(40000, 9000, b"held")).unwrap();
    let mut association = accepted.try_recv().unwrap();
    let retained = association.recv().await.unwrap();
    association.try_reply(b"first").unwrap();
    assert_eq!(association.try_reply(b"second"), Err(Error::QueueFull));
    host.poll(Duration::ZERO).unwrap();
    assert_eq!(association.try_reply(b"second"), Err(Error::ResourceLimit));
    let packet = host.take_packet().unwrap();
    assert_eq!(decode(&packet).unwrap().2, b"first");
    association.try_reply(b"second").unwrap();
    host.poll(Duration::ZERO).unwrap();
    let packet = host.take_packet().unwrap();
    assert_eq!(decode(&packet).unwrap().2, b"second");
    drop(retained);
}

#[tokio::test]
async fn full_packet_output_backpressures_replies_without_consuming_them() {
    let limits = Limits {
        datagrams: MAX_DATAGRAMS,
        queue: 1,
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    host.inject(&sample(40000, 9000, b"sample")).unwrap();
    let mut association = accepted.try_recv().unwrap();
    drop(association.recv().await.unwrap());
    for _ in 0..PACKET_CAPACITY {
        association.try_reply(b"first").unwrap();
        host.poll(Duration::ZERO).unwrap();
    }
    association.try_reply(b"last").unwrap();
    host.poll(Duration::ZERO).unwrap();
    assert_eq!(association.try_reply(b"overflow"), Err(Error::QueueFull));
    for _ in 0..PACKET_CAPACITY {
        assert_eq!(decode(&host.take_packet().unwrap()).unwrap().2, b"first");
    }
    host.poll(Duration::ZERO).unwrap();
    assert_eq!(decode(&host.take_packet().unwrap()).unwrap().2, b"last");
    assert!(host.take_packet().is_none());
}

#[tokio::test]
async fn near_full_output_rotates_association_priority_without_starving_a_sender() {
    let limits = Limits {
        datagrams: MAX_DATAGRAMS,
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    host.inject(&sample(40000, 9000, b"first")).unwrap();
    let mut first = accepted.try_recv().unwrap();
    drop(first.recv().await.unwrap());
    host.inject(&sample(40001, 9000, b"second")).unwrap();
    let mut second = accepted.try_recv().unwrap();
    drop(second.recv().await.unwrap());
    for _ in 0..PACKET_CAPACITY {
        first.try_reply(b"filler").unwrap();
        host.poll(Duration::ZERO).unwrap();
    }
    first.try_reply(b"first").unwrap();
    second.try_reply(b"second").unwrap();
    host.poll(Duration::ZERO).unwrap();
    for _ in 0..2 {
        host.take_packet().unwrap();
        host.poll(Duration::ZERO).unwrap();
    }
    let mut final_payloads = Vec::new();
    while let Some(packet) = host.take_packet() {
        let payload = decode(&packet).unwrap().2;
        if payload != b"filler" {
            final_payloads.push(payload.to_vec());
        }
    }
    assert_eq!(final_payloads, [b"second".to_vec(), b"first".to_vec()]);
}

#[test]
fn dropping_application_retires_queued_replies_and_allows_new_identity() {
    let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
    let packet = sample(40000, 9000, b"sample");
    host.inject(&packet).unwrap();
    let association = accepted.try_recv().unwrap();
    association.try_reply(b"sample").unwrap();
    host.poll(Duration::ZERO).unwrap();
    drop(association);
    host.poll(Duration::ZERO).unwrap();
    assert!(host.take_packet().is_none());
    assert_eq!(host.statistics().application_closed, 1);
    assert_eq!(host.inject(&packet), Ok(FlowId(2)));
}

#[tokio::test]
async fn cancellation_and_driver_drop_wake_pending_receivers_with_terminal_error() {
    use std::{
        future::Future,
        pin::pin,
        sync::atomic::AtomicUsize,
        task::{Context, Poll, Wake, Waker},
    };
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    for drop_driver in [false, true] {
        let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
        let packet = sample(40000, 9000, b"sample");
        host.inject(&packet).unwrap();
        let mut association = accepted.try_recv().unwrap();
        drop(association.recv().await.unwrap());
        association.try_reply(b"pending").unwrap();
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut receive = pin!(association.recv());
        assert!(matches!(
            receive.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Pending
        ));
        if drop_driver {
            drop(host);
        } else {
            host.cancel();
            host.cancel();
            assert_eq!(host.inject(&packet), Err(Error::Cancelled));
            assert_eq!(host.poll(Duration::ZERO), Err(Error::Cancelled));
            assert!(host.take_packet().is_none());
        }
        assert!(count.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(receive.await, Err(Error::Cancelled)));
        assert!(accepted.recv().await.is_none());
    }
}

#[test]
fn association_limit_and_closed_consumer_do_not_displace_admitted_tuple() {
    let limits = Limits {
        associations: 1,
        accepted: 1,
        ..Limits::default()
    };
    let (mut host, accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    let packet = sample(40000, 9000, b"sample");
    assert_eq!(host.inject(&packet), Ok(FlowId(1)));
    assert_eq!(
        host.inject(&sample(40001, 9000, b"other")),
        Err(Error::ResourceLimit)
    );
    assert_eq!(host.inject(&packet), Ok(FlowId(1)));
    drop(accepted);
    host.poll(Duration::ZERO).unwrap();
    assert_eq!(
        host.inject(&sample(40001, 9000, b"other")),
        Err(Error::ConsumerClosed)
    );
    assert_eq!(host.active_associations(), 0);
}

#[test]
fn invalid_limits_clocks_and_identifier_exhaustion_fail_without_mutation() {
    for limits in [
        Limits {
            associations: 0,
            ..Limits::default()
        },
        Limits {
            associations: MAX_ASSOCIATIONS + 1,
            ..Limits::default()
        },
        Limits {
            accepted: 0,
            ..Limits::default()
        },
        Limits {
            accepted: 3,
            ..Limits::default()
        },
        Limits {
            queue: 0,
            ..Limits::default()
        },
        Limits {
            queue: MAX_QUEUE + 1,
            ..Limits::default()
        },
        Limits {
            datagrams: 0,
            ..Limits::default()
        },
        Limits {
            datagrams: MAX_DATAGRAMS + 1,
            ..Limits::default()
        },
        Limits {
            idle_timeout: Duration::ZERO,
            ..Limits::default()
        },
        Limits {
            max_age: Duration::MAX,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            UdpAdapter::new(limits, select_backend),
            Err(Error::InvalidLimits)
        ));
    }
    let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
    assert_eq!(host.poll(Duration::MAX), Err(Error::InvalidTime));
    host.poll(Duration::from_secs(1)).unwrap();
    assert_eq!(host.poll(Duration::ZERO), Err(Error::InvalidTime));
    host.next_id = u64::MAX;
    assert_eq!(
        host.inject(&sample(40000, 9000, b"sample")),
        Err(Error::ResourceLimit)
    );
    assert_eq!(host.active_associations(), 0);
    assert!(accepted.try_recv().is_err());
    host.next_id = 1;
    assert_eq!(host.inject(&sample(40000, 9000, b"sample")), Ok(FlowId(1)));
}

#[tokio::test]
async fn malformed_unsupported_and_unselected_packets_do_not_publish_ownership() {
    let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
    for sample in [vec![], vec![0x70], vec![0x40; 12], vec![0x60; 12]] {
        assert_eq!(host.inject(&sample), Err(Error::MalformedPacket));
    }
    assert_eq!(host.inject(&vec![0; MTU + 1]), Err(Error::DatagramTooLarge));
    let mut corrupt = sample(40000, 9000, b"sample");
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(host.inject(&corrupt), Err(Error::MalformedPacket));
    let mut unsupported = sample(40000, 9000, b"sample");
    let mut packet = Ipv4Packet::new_unchecked(&mut unsupported[..]);
    packet.set_next_header(IpProtocol::Tcp);
    packet.fill_checksum();
    assert_eq!(host.inject(&unsupported), Err(Error::UnsupportedProtocol));
    assert_eq!(
        host.inject(&sample(40000, 9999, b"sample")),
        Err(Error::UnselectedDestination)
    );
    assert_eq!(
        host.inject(&sample(0, 9000, b"sample")),
        Err(Error::MalformedPacket)
    );
    assert_eq!(
        host.inject(&sample(40000, 0, b"sample")),
        Err(Error::MalformedPacket)
    );
    assert_eq!(host.active_associations(), 0);
    assert!(accepted.try_recv().is_err());
    assert!(host.take_packet().is_none());
    assert_eq!(host.inject(&sample(40000, 9000, b"valid")), Ok(FlowId(1)));
    let mut association = accepted.try_recv().unwrap();
    assert_eq!(association.recv().await.unwrap().payload(), b"valid");
}

#[test]
fn replies_enforce_each_family_mtu_before_queue_admission() {
    for ipv6 in [false, true] {
        let source: SocketAddr = if ipv6 {
            "[fd66:66::2]:40000"
        } else {
            "10.66.66.2:40000"
        }
        .parse()
        .unwrap();
        let destination: SocketAddr = if ipv6 {
            "[fd66:66::91]:9000"
        } else {
            "10.66.66.91:9000"
        }
        .parse()
        .unwrap();
        let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
        host.inject(&encode(source, destination, b"").unwrap())
            .unwrap();
        let association = accepted.try_recv().unwrap();
        let maximum = max_payload(destination);
        assert_eq!(
            association.try_reply(&vec![0; maximum + 1]),
            Err(Error::DatagramTooLarge)
        );
        association.try_reply(&vec![0x31; maximum]).unwrap();
        host.poll(Duration::ZERO).unwrap();
        assert_eq!(host.take_packet().unwrap().len(), MTU);
        assert_eq!(host.statistics().replied, 1);
    }
}

#[test]
fn ip_and_udp_validation_rejects_ambiguous_or_unsupported_input_before_admission() {
    struct Case {
        id: &'static str,
        packet: Vec<u8>,
        expected: Error,
    }
    let original = sample(40000, 9000, b"sample");
    let mut bad_ip_checksum = original.clone();
    bad_ip_checksum[8] ^= 1;
    let mut fragment = original.clone();
    let mut packet = Ipv4Packet::new_unchecked(&mut fragment[..]);
    packet.set_more_frags(true);
    packet.fill_checksum();
    let mut short_udp_length = original.clone();
    let mut packet = UdpPacket::new_unchecked(&mut short_udp_length[20..]);
    packet.set_len(8);
    packet.fill_checksum(
        &"10.66.66.2".parse::<std::net::Ipv4Addr>().unwrap().into(),
        &"10.66.66.91".parse::<std::net::Ipv4Addr>().unwrap().into(),
    );
    let mut invalid_udp_length = original.clone();
    UdpPacket::new_unchecked(&mut invalid_udp_length[20..]).set_len(65535);
    let v6 = encode(
        "[fd66:66::2]:40000".parse().unwrap(),
        "[fd66:66::91]:9000".parse().unwrap(),
        b"sample",
    )
    .unwrap();
    let mut extension_header = v6.clone();
    Ipv6Packet::new_unchecked(&mut extension_header[..]).set_next_header(IpProtocol::Ipv6Frag);
    let mut omitted_v6_checksum = v6;
    UdpPacket::new_unchecked(&mut omitted_v6_checksum[40..]).set_checksum(0);
    for case in [
        Case {
            id: "ipv4 checksum",
            packet: bad_ip_checksum,
            expected: Error::MalformedPacket,
        },
        Case {
            id: "ipv4 fragment",
            packet: fragment,
            expected: Error::UnsupportedProtocol,
        },
        Case {
            id: "trailing UDP bytes",
            packet: short_udp_length,
            expected: Error::MalformedPacket,
        },
        Case {
            id: "UDP length beyond IP",
            packet: invalid_udp_length,
            expected: Error::MalformedPacket,
        },
        Case {
            id: "IPv6 fragment header",
            packet: extension_header,
            expected: Error::UnsupportedProtocol,
        },
        Case {
            id: "missing IPv6 checksum",
            packet: omitted_v6_checksum,
            expected: Error::MalformedPacket,
        },
        Case {
            id: "unspecified source",
            packet: encode(
                "0.0.0.0:40000".parse().unwrap(),
                "10.66.66.91:9000".parse().unwrap(),
                b"",
            )
            .unwrap(),
            expected: Error::MalformedPacket,
        },
        Case {
            id: "multicast destination",
            packet: encode(
                "10.66.66.2:40000".parse().unwrap(),
                "224.0.0.1:9000".parse().unwrap(),
                b"",
            )
            .unwrap(),
            expected: Error::MalformedPacket,
        },
    ] {
        let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
        assert_eq!(host.inject(&case.packet), Err(case.expected), "{}", case.id);
        assert_eq!(host.active_associations(), 0, "{}", case.id);
        assert!(accepted.try_recv().is_err(), "{}", case.id);
        assert!(host.take_packet().is_none(), "{}", case.id);
    }
    // An omitted checksum is legal only for IPv4 UDP.
    let mut no_checksum = original;
    UdpPacket::new_unchecked(&mut no_checksum[20..]).set_checksum(0);
    let (mut host, _accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
    assert_eq!(host.inject(&no_checksum), Ok(FlowId(1)));
}

#[tokio::test]
async fn expiry_wakes_pending_receive_and_cancelled_reply_preserves_terminal_reason() {
    let limits = Limits {
        idle_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let (mut host, mut accepted) = UdpAdapter::new(limits, select_backend).unwrap();
    host.inject(&sample(40000, 9000, b"")).unwrap();
    let mut association = accepted.try_recv().unwrap();
    drop(association.recv().await.unwrap());
    let mut handle = tokio::spawn(async move {
        let result = association.recv().await;
        (association, result)
    });
    tokio::task::yield_now().await;
    host.poll(Duration::from_secs(1)).unwrap();
    let completed = tokio::time::timeout(Duration::from_secs(1), &mut handle).await;
    if completed.is_err() {
        handle.abort();
        assert!(
            handle.await.is_err(),
            "timed-out receive task must be joined"
        );
    }
    let (association, result) = completed.unwrap().unwrap();
    assert!(matches!(result, Err(Error::TimedOut)));
    host.cancel();
    assert_eq!(
        association.try_reply(b"stale"),
        Err(Error::TimedOut),
        "later cancellation must not overwrite the retired owner's reason"
    );

    let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend).unwrap();
    host.inject(&sample(40000, 9000, b"")).unwrap();
    let association = accepted.try_recv().unwrap();
    host.cancel();
    assert_eq!(association.try_reply(b"stale"), Err(Error::Cancelled));
}
