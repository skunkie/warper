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
async fn dns_output_receipt_waits_for_peer_ack_and_survives_observation_loss() {
    use std::future::Future;
    use tokio::sync::watch;
    let endpoint = "192.0.2.9:53".parse().unwrap();
    let (mut host, _backend, mut dns) = HostAdapter::with_dns(
        Limits::default(),
        policy(endpoint),
        Seed::fixture(),
        endpoint,
    )
    .unwrap();
    let mut peer = Peer::with_destination(false, 50000, endpoint);
    let mut accepted = None;
    for turn in 0..100 {
        pump(&mut host, &mut peer, Duration::from_millis(turn));
        if let Ok(flow) = dns.try_recv() {
            accepted = Some(flow);
            break;
        }
    }
    let mut flow = accepted.unwrap();
    let control = flow.stream.dns_output().unwrap();
    let (owner, _) = watch::channel(false);
    let request = || warper_core::transport::Request {
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
        cancellation: owner.subscribe(),
    };
    control.begin(request()).unwrap();
    flow.stream.write_all(b"reply").await.unwrap();
    let mut receipt = control.receipt().unwrap();
    assert_eq!(control.begin(request()), Err(DnsOutputError::Busy));
    {
        // Bytes in the duplex buffer are not TCP transmission or acknowledgment.
        let mut waiting = Box::pin(receipt.wait(request()));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    poll(&mut host, Duration::from_millis(100));
    {
        // Nor are packets waiting in the adapter's outgoing queue.
        let mut waiting = Box::pin(receipt.wait(request()));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    let (cancelled, _) = watch::channel(true);
    assert_eq!(
        receipt
            .wait(warper_core::transport::Request {
                deadline: request().deadline,
                cancellation: cancelled.subscribe()
            })
            .await,
        Err(DnsOutputError::WaitCancelled)
    );
    for turn in 101..1000 {
        pump(&mut host, &mut peer, Duration::from_millis(turn));
    }
    receipt.wait(request()).await.unwrap();
    assert_eq!(
        receipt.wait(request()).await,
        Err(DnsOutputError::AlreadyJoined)
    );
    let mut bytes = [0; 5];
    assert_eq!(peer.tcp().recv_slice(&mut bytes).unwrap(), 5);
    assert_eq!(&bytes, b"reply");
    control.begin(request()).unwrap();
    flow.stream.write_all(b"pending reset").await.unwrap();
    let mut reset = control.receipt().unwrap();
    poll(&mut host, Duration::from_secs(1));
    // A reset clears smoltcp's send queue. It must never look like an ACK.
    peer.tcp().abort();
    pump(&mut host, &mut peer, Duration::from_millis(1001));
    assert_eq!(reset.wait(request()).await, Err(DnsOutputError::Reset));
    host.cancel();
    drop(flow);
    assert_eq!(host.retained_flows(), 0);
}

#[tokio::test(start_paused = true)]
async fn dns_output_original_expiry_is_terminal_even_with_unenqueued_bytes() {
    use tokio::sync::watch;
    let endpoint = "192.0.2.9:53".parse().unwrap();
    let (mut host, _backend, mut dns) = HostAdapter::with_dns(
        Limits::default(),
        policy(endpoint),
        Seed::fixture(),
        endpoint,
    )
    .unwrap();
    let mut peer = Peer::with_destination(false, 50000, endpoint);
    let mut accepted = None;
    for turn in 0..100 {
        pump(&mut host, &mut peer, Duration::from_millis(turn));
        if let Ok(flow) = dns.try_recv() {
            accepted = Some(flow);
            break;
        }
    }
    let mut flow = accepted.unwrap();
    let control = flow.stream.dns_output().unwrap();
    let (owner, _) = watch::channel(false);
    control
        .begin(warper_core::transport::Request {
            deadline: tokio::time::Instant::now() + Duration::from_millis(1),
            cancellation: owner.subscribe(),
        })
        .unwrap();
    flow.stream.write_all(b"pending").await.unwrap();
    let mut receipt = control.receipt().unwrap();
    let observer = || warper_core::transport::Request {
        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        cancellation: owner.subscribe(),
    };
    assert_eq!(
        receipt.wait(observer()).await,
        Err(DnsOutputError::Deadline)
    );
    assert_eq!(control.begin(observer()), Err(DnsOutputError::Deadline));
    host.cancel();
    drop(flow);
    assert_eq!(host.retained_flows(), 0);
}

#[tokio::test(start_paused = true)]
async fn queued_dns_tcp_packets_retain_original_deadlines_and_connection_cancellation() {
    use tokio::sync::watch;
    use warper_core::transport::Request;

    for ipv6 in [false, true] {
        for cause in ["drop", "shutdown", "cancel", "expiry"] {
            let endpoint = if ipv6 {
                "[2001:db8::9]:53"
            } else {
                "192.0.2.9:53"
            }
            .parse()
            .unwrap();
            let (mut host, _backend, mut dns) = HostAdapter::with_dns(
                Limits::default(),
                policy(endpoint),
                Seed::fixture(),
                endpoint,
            )
            .unwrap();
            let mut peer = Peer::with_destination(ipv6, 50000, endpoint);
            let mut accepted = None;
            for turn in 0..100 {
                pump(&mut host, &mut peer, Duration::from_millis(turn));
                if let Ok(flow) = dns.try_recv() {
                    accepted = Some(flow);
                    break;
                }
            }
            let mut flow = accepted.unwrap();
            let (owner, _) = watch::channel(false);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(1);
            let control = flow.stream.dns_output().unwrap();
            control
                .begin(Request {
                    deadline,
                    cancellation: owner.subscribe(),
                })
                .unwrap();
            flow.stream.write_all(b"queued response").await.unwrap();
            let mut receipt = control.receipt().unwrap();
            poll(&mut host, Duration::from_millis(100));
            let mut packets = Vec::new();
            while let Some(packet) = host.take_output() {
                if packet.request().is_some() {
                    packets.push(packet);
                }
            }
            assert!(
                !packets.is_empty(),
                "{cause}: response must enter the native output queue"
            );
            for packet in &packets {
                assert_eq!(packet.request().unwrap().deadline, deadline, "{cause}");
                assert!(!*packet.cancellation().unwrap().borrow(), "{cause}");
            }
            let mut flow = Some(flow);
            let expected = match cause {
                "drop" => {
                    drop(flow.take());
                    DnsOutputError::Closed
                }
                "shutdown" => {
                    host.cancel_flows().unwrap();
                    drop(flow.take());
                    DnsOutputError::Cancelled
                }
                "cancel" => {
                    owner.send_replace(true);
                    DnsOutputError::Cancelled
                }
                "expiry" => {
                    tokio::time::advance(Duration::from_millis(1)).await;
                    DnsOutputError::Deadline
                }
                _ => unreachable!(),
            };
            let (observer, _) = watch::channel(false);
            assert_eq!(
                receipt
                    .wait(Request {
                        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
                        cancellation: observer.subscribe(),
                    })
                    .await,
                Err(expected),
                "{cause}"
            );
            for packet in packets {
                assert!(
                    *packet.cancellation().unwrap().borrow(),
                    "{cause}: a retained segment must observe connection termination"
                );
                if cause == "cancel" {
                    assert!(*packet.request().unwrap().cancellation.borrow());
                }
                if cause == "expiry" {
                    assert!(tokio::time::Instant::now() >= packet.request().unwrap().deadline);
                }
                packet
                    .complete(Err(crate::runtime::delivery::Failure::Cancelled))
                    .unwrap();
            }
            host.cancel();
            drop(flow);
            assert_eq!(host.retained_flows(), 0, "{cause}");
        }
    }
}

#[tokio::test]
async fn local_dns_tcp_preserves_tuple_and_response_after_fin_without_backend_acceptance() {
    for ipv6 in [false, true] {
        let endpoint = if ipv6 {
            "[2001:db8::9]:53"
        } else {
            "192.0.2.9:53"
        }
        .parse()
        .unwrap();
        let mut peer = Peer::with_destination(ipv6, 50000, endpoint);
        // A matching backend route must not override the explicit local role.
        let (mut host, mut backend, mut dns) = HostAdapter::with_dns(
            Limits::default(),
            policy(endpoint),
            Seed::fixture(),
            endpoint,
        )
        .unwrap();
        let mut accepted = None;
        for turn in 0..100 {
            pump(&mut host, &mut peer, Duration::from_millis(turn));
            if let Ok(flow) = dns.try_recv() {
                accepted = Some(flow);
                break;
            }
        }
        let mut flow = accepted.unwrap();
        assert_eq!(flow.metadata.source, peer.source);
        assert_eq!(flow.metadata.destination, endpoint);
        assert!(backend.try_recv().is_err());
        let request = b"\x00\x04one!\x00\x04two!";
        let response = b"\x00\x04yes!\x00\x04done";
        let mut sent = 0;
        let mut actual = Vec::new();
        let mut closed = false;
        let server = async {
            let mut input = Vec::new();
            flow.stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, request);
            flow.stream.write_all(response).await.unwrap();
            flow.stream.shutdown().await.unwrap();
        };
        let client = async {
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
                            actual.extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .unwrap();
                }
                let finished = actual.len() == response.len() && !socket.may_recv();
                pump(&mut host, &mut peer, Duration::from_millis(turn));
                if finished {
                    assert_eq!(actual, response);
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("bounded local DNS TCP exchange did not complete");
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
        host.cancel();
        drop(flow);
        assert_eq!(host.retained_flows(), 0);
        assert!(backend.try_recv().is_err());
    }
}

#[test]
fn local_dns_rejects_other_ports_and_closed_consumers_before_backend_selection() {
    let endpoint = "192.0.2.9:53".parse().unwrap();
    let (mut host, mut backend, dns) = HostAdapter::with_dns(
        Limits::default(),
        policy(endpoint),
        Seed::fixture(),
        endpoint,
    )
    .unwrap();
    let mut wrong_port = Peer::new(false, 50000);
    assert_eq!(
        host.inject(&wrong_port.syn()),
        Err(AdmissionError::UnsupportedProtocol)
    );
    drop(dns);
    let mut peer = Peer::with_destination(false, 50001, endpoint);
    assert_eq!(
        host.inject(&peer.syn()),
        Err(AdmissionError::ConsumerClosed)
    );
    assert_eq!(host.retained_flows(), 0);
    assert_eq!(host.active_flows(), 0);
    assert!(backend.try_recv().is_err());
    host.cancel();
}

#[tokio::test]
async fn local_dns_and_backend_tcp_share_lifetime_admission() {
    let endpoint = "192.0.2.9:53".parse().unwrap();
    let destination = "192.0.2.10:443".parse().unwrap();
    let limits = Limits {
        flows: 1,
        accepted: 1,
        ..Limits::default()
    };
    let (mut host, mut backend, mut dns) =
        HostAdapter::with_dns(limits, policy(destination), Seed::fixture(), endpoint).unwrap();
    let mut peer = Peer::with_destination(false, 50000, endpoint);
    let mut accepted = None;
    for turn in 0..100 {
        pump(&mut host, &mut peer, Duration::from_millis(turn));
        if let Ok(flow) = dns.try_recv() {
            accepted = Some(flow);
            break;
        }
    }
    let mut flow = accepted.unwrap();
    let mut application = Peer::with_destination(false, 50001, destination);
    assert_eq!(
        host.inject(&application.syn()),
        Err(AdmissionError::ResourceLimit)
    );
    host.cancel_flows().unwrap();
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 1);
    assert_eq!(
        flow.stream.read(&mut [0]).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    drop(flow);
    assert_eq!(host.retained_flows(), 0);
    assert!(backend.try_recv().is_err());
    host.cancel();
}

#[test]
fn local_dns_quiescence_aborts_pending_handshakes_and_rejects_new_ones() {
    let endpoint = "192.0.2.9:53".parse().unwrap();
    let (mut host, _backend, mut dns) = HostAdapter::with_dns(
        Limits::default(),
        Arc::new(Policy::new(&[], 1).unwrap()),
        Seed::fixture(),
        endpoint,
    )
    .unwrap();
    let mut peer = Peer::with_destination(false, 50000, endpoint);
    host.inject(&peer.syn()).unwrap();
    host.quiesce().unwrap();
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 0);
    let mut next = Peer::with_destination(false, 50001, endpoint);
    assert_eq!(host.inject(&next.syn()), Err(AdmissionError::Quiescing));
    poll(&mut host, Duration::ZERO);
    assert!(dns.try_recv().is_err());
    host.cancel();
}

#[test]
fn local_dns_full_accept_queue_retains_only_the_existing_lifetime() {
    let endpoint = "192.0.2.9:53".parse().unwrap();
    let limits = Limits {
        flows: 2,
        accepted: 1,
        ..Limits::default()
    };
    let (mut host, _backend, mut dns) = HostAdapter::with_dns(
        limits,
        Arc::new(Policy::new(&[], 1).unwrap()),
        Seed::fixture(),
        endpoint,
    )
    .unwrap();
    let mut peer = Peer::with_destination(false, 50000, endpoint);
    for turn in 0..8 {
        pump(&mut host, &mut peer, Duration::from_millis(turn));
    }
    assert_eq!(dns.len(), 1);
    let mut next = Peer::with_destination(false, 50001, endpoint);
    assert_eq!(
        host.inject(&next.syn()),
        Err(AdmissionError::AcceptQueueFull)
    );
    assert_eq!(host.active_flows(), 1);
    assert_eq!(host.retained_flows(), 1);
    host.cancel();
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 1);
    drop(dns.try_recv().unwrap());
    assert_eq!(host.retained_flows(), 0);
}

#[test]
fn local_dns_validates_endpoint_before_allocating_host_buffers() {
    for endpoint in [
        "192.0.2.9:0",
        "192.0.2.9:54",
        "127.0.0.1:53",
        "0.0.0.0:53",
        "[::]:53",
        "[::1]:53",
    ] {
        assert!(
            matches!(
                HostAdapter::with_dns(
                    Limits::default(),
                    Arc::new(Policy::new(&[], 1).unwrap()),
                    Seed::fixture(),
                    endpoint.parse().unwrap()
                ),
                Err(AdmissionError::InvalidLimits)
            ),
            "{endpoint}"
        );
    }
}

#[tokio::test]
async fn packet_flows_preserve_original_metadata_bytes_and_response_after_fin() {
    for quiescing in [false, true] {
        for ipv6 in [false, true] {
            let (mut host, _accepted, flow, mut peer) = connected(ipv6, Limits::default());
            if quiescing {
                host.quiesce().unwrap();
            }
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
        host.device
            .outgoing
            .push_back(crate::runtime::delivery::Packet::untracked(vec![0; MTU]));
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

#[tokio::test]
async fn quiescence_keeps_accepted_lifetimes_and_resets_new_tuples() {
    for ipv6 in [false, true] {
        let (mut host, mut accepted, flow, _old) = connected(ipv6, Limits::default());
        host.quiesce().unwrap();
        host.quiesce().unwrap();
        let mut peer = Peer::new(ipv6, 50001);
        assert_eq!(host.inject(&peer.syn()), Err(AdmissionError::Quiescing));
        poll(&mut host, Duration::from_secs(1));
        while let Some(packet) = host.take_packet() {
            let (_, destination, _) = tcp_metadata(&packet).unwrap();
            if destination == peer.source {
                peer.device.inject(packet).unwrap();
            }
        }
        peer.poll(Duration::from_secs(1));
        assert_eq!(peer.tcp().state(), tcp::State::Closed);
        assert_eq!(host.active_flows(), 1);
        assert_eq!(host.retained_flows(), 1);
        assert!(matches!(
            accepted.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(flow);
        host.cancel();
        assert_eq!(host.retained_flows(), 0);
        assert_eq!(host.quiesce(), Err(AdmissionError::Cancelled));
    }
}

#[tokio::test]
async fn quiescence_aborts_unpublished_handshakes_without_accepting_a_stream() {
    for ipv6 in [false, true] {
        let mut peer = Peer::new(ipv6, 50000);
        let (mut host, mut accepted) =
            HostAdapter::new(Limits::default(), policy(peer.destination), Seed::fixture()).unwrap();
        host.inject(&peer.syn()).unwrap();
        poll(&mut host, Duration::ZERO);
        host.quiesce().unwrap();
        assert_eq!(host.active_flows(), 0);
        assert_eq!(host.retained_flows(), 0);
        poll(&mut host, Duration::from_millis(1));
        while let Some(packet) = host.take_packet() {
            peer.device.inject(packet).unwrap();
        }
        peer.poll(Duration::from_millis(1));
        assert_eq!(peer.tcp().state(), tcp::State::Closed);
        assert!(matches!(
            accepted.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        host.cancel();
    }
}

#[test]
fn quiescent_reset_ingress_remains_bounded_without_flow_allocation() {
    let mut peer = Peer::new(false, 50000);
    let (mut host, _accepted) =
        HostAdapter::new(Limits::default(), policy(peer.destination), Seed::fixture()).unwrap();
    host.quiesce().unwrap();
    let syn = peer.syn();
    for _ in 0..crate::device::PACKET_CAPACITY {
        assert_eq!(host.inject(&syn), Err(AdmissionError::Quiescing));
    }
    assert_eq!(host.inject(&syn), Err(AdmissionError::ResourceLimit));
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.retained_flows(), 0);
    host.cancel();
}

#[tokio::test]
async fn dynamic_flow_selection_is_pinned_before_syn_admission_through_last_stream_drop() {
    let _elapsed = selected_flow_exchange().await;
}

async fn selected_flow_exchange() -> Duration {
    // The manual packet driver uses a no-op poll waker. Start each exchange
    // with a fresh cooperative budget before its bounded synchronous pumps.
    tokio::task::yield_now().await;
    use crate::routing_fixture::LeaseRoutes;
    use std::sync::atomic::Ordering;
    use warper_core::dns::lease::Error as LeaseError;

    let mut peer = Peer::new(false, 50000);
    let routes = LeaseRoutes::new(peer.destination.ip());
    let (mut host, mut accepted) =
        HostAdapter::with_selector(Limits::default(), routes.clone(), Seed::fixture()).unwrap();
    let started = std::time::Instant::now();
    let syn = peer.syn();
    let id = host.inject(&syn).unwrap();
    assert_eq!(
        routes.ledger.lock().unwrap().stats().flows,
        1,
        "the initial SYN already owns its routing reference"
    );
    assert_eq!(
        host.inject(&syn).unwrap(),
        id,
        "a retransmitted SYN reuses the existing selection"
    );
    assert_eq!(routes.ledger.lock().unwrap().stats().flows, 1);
    for turn in 0..100 {
        pump(&mut host, &mut peer, Duration::from_millis(turn));
        if !accepted.is_empty() {
            break;
        }
    }
    let mut flow = accepted.try_recv().unwrap();
    routes.advance(2);
    assert_eq!(routes.ledger.lock().unwrap().stats().leases, 0);
    assert_eq!(
        routes
            .ledger
            .lock()
            .unwrap()
            .begin_retirement(Duration::from_secs(2), routes.route),
        Err(LeaseError::Referenced)
    );
    routes.behavior.store(3, Ordering::Release);
    peer.tcp().send_slice(b"stable selected flow").unwrap();
    for _ in 0..20 {
        pump(&mut host, &mut peer, Duration::from_secs(2));
    }
    let mut bytes = [0; 20];
    flow.stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"stable selected flow");
    assert_eq!(flow.metadata.backend, BackendId(70000));
    let elapsed = started.elapsed();
    host.cancel();
    assert_eq!(
        routes.ledger.lock().unwrap().stats().flows,
        1,
        "retained application streams still pin the route after driver cancellation"
    );
    drop(flow);
    routes.advance(2);
    let mut ledger = routes.ledger.lock().unwrap();
    assert_eq!(ledger.stats().flows, 0);
    ledger
        .begin_retirement(Duration::from_secs(2), routes.route)
        .unwrap();
    ledger.finish_retirement(routes.route).unwrap();
    elapsed
}

#[test]
fn failed_syn_admission_releases_only_its_new_selection_without_fallback() {
    use crate::routing_fixture::LeaseRoutes;
    use std::sync::atomic::Ordering;

    let mut peer = Peer::new(false, 50000);
    let routes = LeaseRoutes::new(peer.destination.ip());
    let (mut host, _accepted) = HostAdapter::with_selector(
        Limits {
            flows: 1,
            accepted: 1,
            ..Limits::default()
        },
        routes.clone(),
        Seed::fixture(),
    )
    .unwrap();
    let syn = peer.syn();
    for (behavior, expected) in [
        (1, AdmissionError::SelectionBusy),
        (2, AdmissionError::SelectionUnready),
        (3, AdmissionError::SelectionUnavailable),
    ] {
        routes.behavior.store(behavior, Ordering::Release);
        assert_eq!(host.inject(&syn), Err(expected));
        assert_eq!(host.active_flows(), 0);
    }
    routes.behavior.store(0, Ordering::Release);
    host.inject(&syn).unwrap();
    let mut other = Peer::new(false, 50001);
    assert_eq!(
        host.inject(&other.syn()),
        Err(AdmissionError::ResourceLimit)
    );
    routes.advance(0);
    assert_eq!(routes.ledger.lock().unwrap().stats().flows, 1);
    host.cancel();
    routes.advance(0);
    assert_eq!(routes.ledger.lock().unwrap().stats().flows, 0);
}

#[tokio::test]
#[ignore = "controlled stack flow ownership workload; run explicitly in release mode"]
async fn selected_flow_ownership_workload() {
    let started = std::time::Instant::now();
    let mut latencies = Vec::new();
    for index in 0..100 {
        let elapsed = tokio::time::timeout(Duration::from_secs(2), selected_flow_exchange()).await;
        assert!(elapsed.is_ok(), "controlled flow {index} stalled");
        latencies.push(elapsed.unwrap().as_nanos());
    }
    latencies.sort_unstable();
    println!(
        "selected flow workload flows=100 payload_bytes=2000 elapsed_ns={} p50_ns={} p95_ns={} p99_ns={}; controlled in-memory TCP peers, synthetic expiry clock, no induced loss, fixture setup excluded from flow latency",
        started.elapsed().as_nanos(),
        latencies[49],
        latencies[94],
        latencies[98]
    );
}
