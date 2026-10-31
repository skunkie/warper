// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled packet peers verify the public stream and lifetime behavior.

use super::*;
use std::task::Waker;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warper_core::{BackendId, routing::Entry};

use crate::fixture::Peer;

fn policy(destination: SocketAddr) -> Arc<Policy> {
    Arc::new(
        Policy::new(
            &[Entry {
                network: destination.ip(),
                prefix_len: if destination.is_ipv4() { 32 } else { 128 },
                backend: BackendId(70000),
            }],
            1,
        )
        .unwrap(),
    )
}
fn poll(host: &mut HostAdapter, now: Duration) {
    host.poll_io(&mut Context::from_waker(Waker::noop()), now)
        .unwrap();
}
fn pump(host: &mut HostAdapter, peer: &mut Peer, now: Duration) {
    peer.poll(now);
    while let Some(packet) = peer.device.outgoing.pop_front() {
        host.inject(&packet).unwrap();
    }
    poll(host, now);
    while let Some(packet) = host.take_packet() {
        assert!(packet.len() <= MTU);
        peer.device.inject(packet).unwrap();
    }
    peer.poll(now);
}
fn connected(
    ipv6: bool,
    limits: Limits,
) -> (HostAdapter, Receiver<AcceptedFlow>, AcceptedFlow, Peer) {
    let mut peer = Peer::new(ipv6, 50000);
    let (mut host, mut accepted) =
        HostAdapter::new(limits, policy(peer.destination), Seed::fixture()).unwrap();
    for turn in 0..100 {
        pump(&mut host, &mut peer, Duration::from_millis(turn));
        if let Ok(flow) = accepted.try_recv() {
            return (host, accepted, flow, peer);
        }
    }
    panic!("controlled TCP handshake did not complete");
}

#[tokio::test]
async fn packet_flows_preserve_original_metadata_bytes_and_response_after_fin() {
    for ipv6 in [false, true] {
        let (mut host, _accepted, flow, mut peer) = connected(ipv6, Limits::default());
        let mut flow = flow.into_core();
        assert_eq!(flow.metadata.source, peer.source);
        assert_eq!(flow.metadata.destination, peer.destination);
        assert_eq!(flow.metadata.backend, BackendId(70000));
        let request: Vec<_> = (0..65536).map(|n| (n % 251) as u8).collect();
        let response: Vec<_> = (0..65536).map(|n| (n % 239) as u8).collect();
        let mut actual = Vec::new();
        let mut sent = 0;
        let mut closed = false;
        let ((), ()) = tokio::join!(
            async {
                let mut received = Vec::new();
                flow.stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, request);
                flow.stream.write_all(&response).await.unwrap();
                flow.stream.flush().await.unwrap();
                flow.stream.shutdown().await.unwrap();
            },
            async {
                for turn in 100..10100 {
                    let socket = peer.tcp();
                    if socket.can_send() && sent < request.len() {
                        sent += socket.send_slice(&request[sent..]).unwrap();
                    }
                    if sent == request.len() && !closed {
                        socket.close();
                        closed = true;
                    }
                    if socket.can_recv() {
                        socket
                            .recv(|bytes| {
                                assert!(actual.len() + bytes.len() <= response.len());
                                actual.extend_from_slice(bytes);
                                (bytes.len(), ())
                            })
                            .unwrap();
                    }
                    let finished = actual.len() == response.len() && !socket.may_recv();
                    pump(&mut host, &mut peer, Duration::from_millis(turn));
                    if finished {
                        for offset in 1..8 {
                            pump(&mut host, &mut peer, Duration::from_millis(turn + offset));
                        }
                        assert_eq!(actual, response);
                        return;
                    }
                    tokio::task::yield_now().await;
                }
                panic!("bounded packet exchange did not complete");
            }
        );
        assert_eq!(host.active_flows(), 0);
        assert_eq!(host.statistics().finished, 1);
        assert_eq!(host.retained_flows(), 1);
        drop(flow);
        assert_eq!(host.retained_flows(), 0);
        host.cancel();
        assert!(!host.has_packet());
    }
}

#[tokio::test]
async fn cancellation_and_owner_drop_surface_errors_and_retain_the_buffer_charge() {
    let (mut host, _accepted, mut flow, _peer) = connected(false, Limits::default());
    host.cancel();
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 1);
    assert_eq!(host.inject(&[]), Err(AdmissionError::Cancelled));
    assert_eq!(host.next_deadline(true), None);
    let mut bytes = [0; 1];
    assert_eq!(
        flow.stream.read(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        flow.stream
            .write(b"not delivered")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        flow.stream.flush().await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        flow.stream.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    drop(flow);
    assert_eq!(host.retained_flows(), 0);
    let (host, _accepted, mut flow, _peer) = connected(true, Limits::default());
    drop(host);
    assert_eq!(
        flow.stream.read(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn idle_expiry_prevents_reusing_retired_stream_capacity_until_drop() {
    let limits = Limits {
        flows: 1,
        accepted: 1,
        idle_timeout: Duration::from_millis(25),
        ..Limits::default()
    };
    let (mut host, _accepted, mut flow, _peer) = connected(false, limits);
    poll(&mut host, Duration::from_millis(100));
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.statistics().timed_out, 1);
    let mut peer = Peer::new(false, 50001);
    let syn = peer.syn();
    assert_eq!(host.inject(&syn), Err(AdmissionError::ResourceLimit));
    let mut bytes = [0; 1];
    assert_eq!(
        flow.stream.read(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    drop(flow);
    assert_eq!(host.retained_flows(), 0);
    assert_eq!(host.inject(&syn), Ok(2));
    host.cancel();
}

#[test]
fn application_loss_reset_and_absolute_expiry_retire_flow_ownership() {
    let (mut host, _accepted, flow, _peer) = connected(false, Limits::default());
    drop(flow);
    poll(&mut host, Duration::from_millis(100));
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 0);
    assert_eq!(host.statistics().application_closed, 1);

    let (mut host, _accepted, mut flow, mut peer) = connected(false, Limits::default());
    peer.tcp().abort();
    pump(&mut host, &mut peer, Duration::from_millis(100));
    assert_eq!(host.statistics().reset, 1);
    let mut byte = [0];
    let mut read = ReadBuf::new(&mut byte);
    assert!(matches!(
        Pin::new(&mut flow.stream).poll_read(&mut Context::from_waker(Waker::noop()), &mut read),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset
    ));

    let limits = Limits {
        max_age: Duration::from_millis(50),
        ..Limits::default()
    };
    let (mut host, _accepted, flow, _peer) = connected(false, limits);
    poll(&mut host, Duration::from_millis(50));
    assert_eq!(host.statistics().timed_out, 1);
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 1);
    drop(flow);
    assert_eq!(host.retained_flows(), 0);
}

#[test]
fn expired_flow_discards_delayed_ingress_before_reusing_its_listener_slot() {
    let limits = Limits {
        flows: 1,
        accepted: 1,
        idle_timeout: Duration::from_millis(25),
        ..Limits::default()
    };
    let (mut host, mut accepted, flow, _peer) = connected(false, limits);
    let mut old_peer = Peer::new(false, 50000);
    host.inject(&old_peer.syn()).unwrap();
    // Inject transport backpressure without delivering any synthetic output.
    while host.device.outgoing.len() < crate::device::PACKET_CAPACITY {
        host.device.outgoing.push_back(vec![0; MTU]);
    }
    poll(&mut host, Duration::from_millis(100));
    assert_eq!(host.active_flows(), 0);
    drop(flow);
    host.device.outgoing.clear();
    let mut new_peer = Peer::new(false, 50001);
    for turn in 200..300 {
        pump(&mut host, &mut new_peer, Duration::from_millis(turn));
        if let Ok(flow) = accepted.try_recv() {
            assert_eq!(flow.metadata.source, new_peer.source);
            assert_eq!(flow.metadata.destination, new_peer.destination);
            return;
        }
    }
    panic!("retired ingress prevented the new peer from completing its handshake");
}

#[test]
fn pending_handshake_expiry_and_accept_queue_failures_release_only_owned_capacity() {
    let mut a = Peer::new(false, 50000);
    let mut b = Peer::new(false, 50001);
    let limits = Limits {
        flows: 2,
        accepted: 1,
        setup_timeout: Duration::from_millis(10),
        ..Limits::default()
    };
    let (mut host, accepted) =
        HostAdapter::new(limits, policy(a.destination), Seed::fixture()).unwrap();
    assert_eq!(host.inject(&a.syn()), Ok(1));
    assert_eq!(host.inject(&b.syn()), Err(AdmissionError::AcceptQueueFull));
    assert_eq!(host.retained_flows(), 1);
    poll(&mut host, Duration::ZERO);
    assert_eq!(host.next_deadline(false), Some(Duration::from_millis(10)));
    poll(&mut host, Duration::from_millis(10));
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 0);
    drop(accepted);
    let mut b = Peer::new(false, 50001);
    assert_eq!(host.inject(&b.syn()), Err(AdmissionError::ConsumerClosed));
    assert_eq!(host.retained_flows(), 0);
    host.cancel();
}

#[test]
fn unsupported_or_invalid_packets_never_publish_a_flow() {
    let mut peer = Peer::new(false, 50000);
    let syn = peer.syn();
    let (mut host, _accepted) =
        HostAdapter::new(Limits::default(), policy(peer.destination), Seed::fixture()).unwrap();
    assert_eq!(
        host.inject(&vec![0; MTU + 1]),
        Err(AdmissionError::PacketTooLarge)
    );
    assert_eq!(host.inject(&[]), Err(AdmissionError::MalformedPacket));
    let mut fragment = syn.clone();
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut fragment);
        ip.set_more_frags(true);
        ip.fill_checksum();
    }
    assert_eq!(
        host.inject(&fragment),
        Err(AdmissionError::UnsupportedProtocol)
    );
    let mut extra = syn.clone();
    extra.push(0);
    assert_eq!(host.inject(&extra), Err(AdmissionError::MalformedPacket));
    let mut udp = syn.clone();
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut udp);
        ip.set_next_header(IpProtocol::Udp);
        ip.fill_checksum();
    }
    assert_eq!(host.inject(&udp), Err(AdmissionError::UnsupportedProtocol));
    let mut non_syn = syn.clone();
    {
        let mut tcp = TcpPacket::new_unchecked(&mut non_syn[20..]);
        tcp.set_syn(false);
        tcp.fill_checksum(&peer.source.ip().into(), &peer.destination.ip().into());
    }
    assert_eq!(host.inject(&non_syn), Err(AdmissionError::UnknownFlow));
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 0);
    let empty = Arc::new(Policy::new(&[], 1).unwrap());
    let (mut unselected, _accepted) =
        HostAdapter::new(Limits::default(), empty, Seed::fixture()).unwrap();
    assert_eq!(
        unselected.inject(&syn),
        Err(AdmissionError::UnselectedDestination)
    );
}

#[test]
fn invalid_limits_clocks_and_full_ingress_do_not_expand_resource_ownership() {
    let peer = Peer::new(false, 50000);
    for limits in [
        Limits {
            flows: 0,
            ..Limits::default()
        },
        Limits {
            flows: 17,
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
            setup_timeout: Duration::ZERO,
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
            HostAdapter::new(limits, policy(peer.destination), Seed::fixture()),
            Err(AdmissionError::InvalidLimits)
        ));
    }
    let mut peer = peer;
    let syn = peer.syn();
    let (mut host, _accepted) =
        HostAdapter::new(Limits::default(), policy(peer.destination), Seed::fixture()).unwrap();
    for _ in 0..crate::device::PACKET_CAPACITY {
        assert_eq!(host.inject(&syn), Ok(1));
    }
    assert_eq!(host.inject(&syn), Err(AdmissionError::ResourceLimit));
    assert_eq!(host.active_flows(), 1);
    assert_eq!(host.retained_flows(), 1);
    poll(&mut host, Duration::from_millis(1));
    assert_eq!(
        host.poll_io(&mut Context::from_waker(Waker::noop()), Duration::ZERO),
        Err(AdmissionError::InvalidTime)
    );
    assert!(host.buffer_capacity() < 1024 * 1024);
    host.cancel();
    assert_eq!(host.retained_flows(), 0);
}
