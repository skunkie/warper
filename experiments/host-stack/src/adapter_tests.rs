// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Behavioral admission, error, deadline, and stream-lifecycle checks.

use super::*;
use crate::{
    accepted_probe::{exchange, peer, select_backend, source},
    packet_peer::Peer,
};
use std::{
    sync::atomic::AtomicUsize,
    task::{Wake, Waker},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn syn(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut peer = Peer::new(source.ip(), source.port()).unwrap();
    peer.sockets
        .get_mut::<tcp::Socket>(peer.tcp)
        .connect(peer.interface.context(), destination, source)
        .unwrap();
    peer.poll(0);
    peer.device.outgoing.pop_front().unwrap()
}

fn selected_syn(suffix: u8) -> Vec<u8> {
    syn(
        source(false, suffix).unwrap(),
        "10.66.66.91:9100".parse().unwrap(),
    )
}

fn poll(host: &mut HostAdapter, now: Duration) {
    host.poll_io(&mut Context::from_waker(Waker::noop()), now)
        .unwrap();
}

async fn connected(
    ipv6: bool,
    limits: Limits,
) -> (HostAdapter, Receiver<AcceptedFlow>, AcceptedFlow, [Peer; 2]) {
    let (mut host, mut accepted) = HostAdapter::new(limits, select_backend).unwrap();
    let mut peers = [peer(ipv6, 2).unwrap(), peer(ipv6, 3).unwrap()];
    let destination = SocketAddr::new(source(ipv6, 91).unwrap().ip(), 9100);
    peers[0]
        .sockets
        .get_mut::<tcp::Socket>(peers[0].tcp)
        .connect(
            peers[0].interface.context(),
            destination,
            source(ipv6, 2).unwrap(),
        )
        .unwrap();
    for step in 0..20 {
        exchange(&mut host, &mut peers, Duration::from_millis(step))
            .await
            .unwrap();
        if let Ok(flow) = accepted.try_recv() {
            return (host, accepted, flow, peers);
        }
    }
    panic!("controlled handshake did not complete");
}

#[test]
fn duplicate_syn_coalesces_and_accept_queue_reservation_precedes_mutation() {
    let limits = Limits {
        accepted: 1,
        ..Limits::default()
    };
    let (mut host, receiver) = HostAdapter::new(limits, select_backend).unwrap();
    let first = selected_syn(2);
    let id = host.inject(&first).unwrap();
    assert_eq!(host.inject(&first).unwrap(), id);
    assert_eq!(
        host.inject(&selected_syn(3)),
        Err(AdmissionError::AcceptQueueFull)
    );
    assert_eq!(host.active_flows(), 1);
    assert_eq!(host.statistics().admitted, 1);
    drop(receiver);
    assert_eq!(
        host.inject(&selected_syn(3)),
        Err(AdmissionError::ConsumerClosed)
    );
    assert_eq!(host.active_flows(), 1);
}

#[test]
fn flow_capacity_rejects_new_source_without_displacing_existing_tuple() {
    let (mut host, _receiver) = HostAdapter::new(Limits::default(), select_backend).unwrap();
    let first = selected_syn(2);
    let id = host.inject(&first).unwrap();
    assert_ne!(host.inject(&selected_syn(3)).unwrap(), id);
    assert_eq!(
        host.inject(&selected_syn(4)),
        Err(AdmissionError::ResourceLimit)
    );
    assert_eq!(host.inject(&first).unwrap(), id);
    assert_eq!(host.active_flows(), 2);
}

#[test]
fn unrepresentable_new_flow_deadline_preserves_existing_flow() {
    let invalid_limits = Limits {
        max_age: Duration::from_millis(crate::MAX_CLOCK_MILLIS as u64 + 1),
        ..Limits::default()
    };
    assert!(matches!(
        HostAdapter::new(invalid_limits, select_backend),
        Err(AdmissionError::InvalidLimits)
    ));
    for ipv6 in [false, true] {
        let limits = Limits {
            setup_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            max_age: Duration::from_secs(1),
            ..Limits::default()
        };
        let (mut host, _receiver) = HostAdapter::new(limits, select_backend).unwrap();
        let maximum = Duration::from_millis(crate::MAX_CLOCK_MILLIS as u64);
        let start = maximum - Duration::from_secs(1);
        let destination = SocketAddr::new(source(ipv6, 91).unwrap().ip(), 9100);
        let first = syn(source(ipv6, 2).unwrap(), destination);
        let second = syn(source(ipv6, 3).unwrap(), destination);
        assert_eq!(
            host.poll_io(
                &mut Context::from_waker(Waker::noop()),
                Duration::from_millis(i64::MAX as u64)
            ),
            Err(AdmissionError::InvalidTime)
        );
        poll(&mut host, start);
        let id = host.inject(&first).unwrap();
        poll(&mut host, start + Duration::from_millis(1));
        assert_eq!(host.inject(&second), Err(AdmissionError::InvalidTime));
        assert_eq!(host.inject(&first), Ok(id));
        assert_eq!(host.active_flows(), 1);
        poll(&mut host, maximum);
        assert_eq!(host.active_flows(), 0);
        assert_eq!(
            host.poll_io(
                &mut Context::from_waker(Waker::noop()),
                maximum + Duration::from_millis(1)
            ),
            Err(AdmissionError::InvalidTime)
        );
        assert_eq!(
            host.poll_io(
                &mut Context::from_waker(Waker::noop()),
                Duration::from_millis(i64::MAX as u64)
            ),
            Err(AdmissionError::InvalidTime)
        );
        host.cancel();
    }
}

#[test]
fn unrepresentable_stack_clock_returns_error_without_panicking() {
    let (mut host, _receiver) = HostAdapter::new(Limits::default(), select_backend).unwrap();
    assert_eq!(
        host.poll_io(
            &mut Context::from_waker(Waker::noop()),
            Duration::from_millis(i64::MAX as u64)
        ),
        Err(AdmissionError::InvalidTime)
    );
    poll(&mut host, Duration::ZERO);
    host.cancel();
}

#[test]
fn packet_queue_exhaustion_rolls_back_slot_and_accept_reservation() {
    let (mut host, _receiver) = HostAdapter::new(Limits::default(), select_backend).unwrap();
    let first = selected_syn(2);
    for _ in 0..crate::packet_peer::PACKET_CAPACITY {
        host.inject(&first).unwrap();
    }
    assert_eq!(
        host.inject(&selected_syn(3)),
        Err(AdmissionError::ResourceLimit)
    );
    assert_eq!(host.active_flows(), 1);
    poll(&mut host, Duration::ZERO);
    host.inject(&selected_syn(3)).unwrap();
    assert_eq!(host.active_flows(), 2);
}

#[test]
fn invalid_and_unselected_packets_do_not_reserve_flows() {
    let (mut host, _receiver) = HostAdapter::new(Limits::default(), select_backend).unwrap();
    assert_eq!(host.inject(&[0]), Err(AdmissionError::MalformedPacket));
    let mut corrupt = selected_syn(2);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert_eq!(host.inject(&corrupt), Err(AdmissionError::MalformedPacket));
    assert_eq!(
        host.inject(&vec![0; MTU + 1]),
        Err(AdmissionError::PacketTooLarge { mtu: MTU })
    );
    let unselected = syn(
        "192.0.2.2:40000".parse().unwrap(),
        "192.0.2.91:9100".parse().unwrap(),
    );
    assert_eq!(
        host.inject(&unselected),
        Err(AdmissionError::UnselectedDestination)
    );
    let mut peer = peer(false, 2).unwrap();
    peer.sockets
        .get_mut::<smoltcp::socket::udp::Socket>(peer.udp)
        .send_slice(b"sample", "10.66.66.91:9100".parse::<SocketAddr>().unwrap())
        .unwrap();
    peer.poll(0);
    assert_eq!(
        host.inject(&peer.device.outgoing.pop_front().unwrap()),
        Err(AdmissionError::UnsupportedProtocol)
    );
    assert_eq!(host.active_flows(), 0);
}

#[test]
fn setup_deadline_releases_unaccepted_flow_and_reserved_queue_capacity() {
    let limits = Limits {
        flows: 1,
        accepted: 1,
        setup_timeout: Duration::from_millis(10),
        ..Limits::default()
    };
    let (mut host, mut receiver) = HostAdapter::new(limits, select_backend).unwrap();
    let id = host.inject(&selected_syn(2)).unwrap();
    poll(&mut host, Duration::from_millis(9));
    assert_eq!(host.active_flows(), 1);
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    poll(&mut host, Duration::from_millis(10));
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.statistics().accepted, 0);
    assert_eq!(host.statistics().timed_out, 1);
    assert_ne!(host.inject(&selected_syn(3)).unwrap(), id);
    assert_eq!(host.active_flows(), 1);
}

#[test]
fn invalid_clock_and_limits_fail_explicitly() {
    for limits in [
        Limits {
            flows: 0,
            ..Limits::default()
        },
        Limits {
            flows: MAX_FLOW_SLOTS + 1,
            ..Limits::default()
        },
        Limits {
            accepted: 0,
            ..Limits::default()
        },
        Limits {
            setup_timeout: Duration::ZERO,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            HostAdapter::new(limits, select_backend),
            Err(AdmissionError::InvalidLimits)
        ));
    }
    let (mut host, _receiver) = HostAdapter::new(Limits::default(), select_backend).unwrap();
    poll(&mut host, Duration::from_millis(10));
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        host.poll_io(&mut cx, Duration::ZERO),
        Err(AdmissionError::InvalidTime)
    );
    assert_eq!(
        host.poll_io(&mut cx, Duration::MAX),
        Err(AdmissionError::InvalidTime)
    );
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn cancellation_wakes_blocked_stream_and_reports_interrupted() {
    for ipv6 in [false, true] {
        let (mut host, mut receiver, mut flow, _peers) = connected(ipv6, Limits::default()).await;
        let wake_count = Arc::new(WakeCount::default());
        let waker = Waker::from(wake_count.clone());
        let mut bytes = [0; 1];
        let mut read = Box::pin(flow.stream.read(&mut bytes));
        assert!(
            std::future::Future::poll(read.as_mut(), &mut Context::from_waker(&waker)).is_pending()
        );
        host.cancel();
        assert!(
            wake_count.0.load(Ordering::Relaxed) > 0,
            "cancellation must wake the registered reader"
        );
        assert_eq!(read.await.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(
            flow.stream.write(b"sample").await.unwrap_err().kind(),
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
        assert_eq!(host.active_flows(), 0);
        assert_eq!(
            host.inject(&selected_syn(4)),
            Err(AdmissionError::Cancelled)
        );
        assert!(receiver.recv().await.is_none());
        host.cancel();
    }
}

#[tokio::test]
async fn dropping_driver_reports_cancellation_to_accepted_stream() {
    let (host, _receiver, mut flow, _peers) = connected(false, Limits::default()).await;
    drop(host);
    assert_eq!(
        flow.stream.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn dropping_application_releases_slot_and_allows_new_flow_identifier() {
    let (mut host, _receiver, flow, _peers) = connected(false, Limits::default()).await;
    let id = flow.metadata.id;
    drop(flow);
    let now = host.now + Duration::from_millis(1);
    poll(&mut host, now);
    assert_eq!(host.active_flows(), 0);
    assert_eq!(host.statistics().application_closed, 1);
    assert_ne!(host.inject(&selected_syn(3)).unwrap(), id);
}

#[tokio::test]
async fn idle_deadline_and_absolute_age_report_timeout_instead_of_eof() {
    for ipv6 in [false, true] {
        let limits = Limits {
            idle_timeout: Duration::from_millis(10),
            ..Limits::default()
        };
        let (mut host, _receiver, mut flow, _peers) = connected(ipv6, limits).await;
        let base = host.now;
        poll(&mut host, base + Duration::from_millis(9));
        assert_eq!(host.active_flows(), 1);
        poll(&mut host, base + Duration::from_millis(10));
        assert_eq!(host.active_flows(), 0);
        assert_eq!(
            flow.stream.read(&mut [0; 1]).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );

        let limits = Limits {
            max_age: Duration::from_millis(20),
            ..Limits::default()
        };
        let (mut host, _receiver, mut flow, _peers) = connected(ipv6, limits).await;
        poll(&mut host, Duration::from_millis(20));
        assert_eq!(
            flow.stream.read(&mut [0; 1]).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}

#[tokio::test]
async fn peer_reset_reports_connection_reset_instead_of_clean_eof() {
    for ipv6 in [false, true] {
        let (mut host, _receiver, mut flow, mut peers) = connected(ipv6, Limits::default()).await;
        peers[0]
            .sockets
            .get_mut::<tcp::Socket>(peers[0].tcp)
            .abort();
        let now = host.now + Duration::from_millis(1);
        exchange(&mut host, &mut peers, now).await.unwrap();
        assert_eq!(
            flow.stream.read(&mut [0; 1]).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(host.active_flows(), 0);
        assert_eq!(host.statistics().reset, 1);
    }
}

#[test]
fn public_stream_and_driver_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<HostAdapter>();
    assert_send::<AcceptedFlow>();
}

#[tokio::test]
async fn retired_stream_holds_buffer_budget_until_application_drops_it() {
    let limits = Limits {
        flows: 1,
        accepted: 1,
        idle_timeout: Duration::from_millis(10),
        ..Limits::default()
    };
    let (mut host, _receiver, mut flow, _peers) = connected(false, limits).await;
    let id = flow.metadata.id;
    let now = host.now + Duration::from_millis(10);
    poll(&mut host, now);
    assert_eq!(host.active_flows(), 0);
    assert_eq!(
        flow.stream.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        host.inject(&selected_syn(3)),
        Err(AdmissionError::ResourceLimit),
        "a retained closed stream still owns its duplex buffers"
    );
    drop(flow);
    assert_ne!(host.inject(&selected_syn(3)).unwrap(), id);
}

#[tokio::test]
async fn application_write_half_close_preserves_later_request_bytes() {
    use futures::FutureExt;
    for ipv6 in [false, true] {
        let (mut host, _receiver, mut flow, mut peers) = connected(ipv6, Limits::default()).await;
        flow.stream.shutdown().await.unwrap();
        let base = host.now;
        let expected = b"request-after-response-fin";
        let mut sent = false;
        let mut received = Vec::new();
        let mut eof = false;
        for step in 1..100 {
            exchange(&mut host, &mut peers, base + Duration::from_millis(step))
                .await
                .unwrap();
            let socket = peers[0].sockets.get_mut::<tcp::Socket>(peers[0].tcp);
            if !socket.may_recv() && socket.can_send() && !sent {
                assert_eq!(socket.send_slice(expected).unwrap(), expected.len());
                socket.close();
                sent = true;
            }
            let mut bytes = [0; 64];
            if let Some(result) = flow.stream.read(&mut bytes).now_or_never() {
                let count = result.unwrap();
                if count == 0 {
                    eof = true;
                    break;
                }
                received.extend_from_slice(&bytes[..count]);
                assert!(received.len() <= expected.len());
            }
        }
        assert!(
            sent && eof,
            "both half-closes must finish without canceling the read direction"
        );
        assert_eq!(received, expected);
        host.cancel();
    }
}

#[tokio::test]
async fn unread_application_stream_backpressures_peer_and_resumes_after_read() {
    for ipv6 in [false, true] {
        let (mut host, _receiver, mut flow, mut peers) = connected(ipv6, Limits::default()).await;
        let base = host.now;
        let mut sent = 0;
        for step in 1..5000 {
            exchange(&mut host, &mut peers, base + Duration::from_millis(step))
                .await
                .unwrap();
            let socket = peers[0].sockets.get_mut::<tcp::Socket>(peers[0].tcp);
            if socket.can_send() {
                sent += socket.send_slice(&[0x55; 1024]).unwrap();
            }
        }
        assert!(
            sent > BYTE_CAPACITY && sent <= BYTE_CAPACITY * 3,
            "duplex, receive window, and sender buffers bound retained bytes"
        );
        let before = sent;
        let mut bytes = [0; 1024];
        assert_eq!(flow.stream.read(&mut bytes).await.unwrap(), bytes.len());
        assert_eq!(bytes, [0x55; 1024]);
        for step in 5000..5200 {
            exchange(&mut host, &mut peers, base + Duration::from_millis(step))
                .await
                .unwrap();
            let socket = peers[0].sockets.get_mut::<tcp::Socket>(peers[0].tcp);
            if socket.can_send() {
                sent += socket.send_slice(&[0x55; 1024]).unwrap();
            }
        }
        assert!(sent > before, "reading must reopen the receive window");
        host.cancel();
    }
}

#[tokio::test]
async fn interface_rebuild_preserves_active_backend_streams_and_pending_bytes() {
    for ipv6 in [false, true] {
        let (mut host, mut accepted) =
            HostAdapter::with_mtu(Limits::default(), select_backend, 1500).unwrap();
        assert_eq!(
            smoltcp::phy::Device::capabilities(&host.device).max_transmission_unit,
            1500
        );
        let mut peers = [peer(ipv6, 2).unwrap(), peer(ipv6, 3).unwrap()];
        let destinations = [
            SocketAddr::new(source(ipv6, 91).unwrap().ip(), 9100),
            SocketAddr::new(source(ipv6, 92).unwrap().ip(), 9101),
        ];
        for index in 0..2 {
            let peer = &mut peers[index];
            peer.sockets
                .get_mut::<tcp::Socket>(peer.tcp)
                .connect(
                    peer.interface.context(),
                    destinations[index],
                    source(ipv6, 2 + index as u8).unwrap(),
                )
                .unwrap();
        }
        let mut flows = Vec::new();
        for step in 0..50 {
            exchange(&mut host, &mut peers, Duration::from_millis(step))
                .await
                .unwrap();
            while let Ok(flow) = accepted.try_recv() {
                flows.push(flow);
            }
        }
        assert_eq!(flows.len(), 2);
        flows.sort_by_key(|flow| flow.metadata.source.ip());
        let metadata = [flows[0].metadata, flows[1].metadata];
        assert_ne!(metadata[0].id, metadata[1].id);
        assert_ne!(metadata[0].backend, metadata[1].backend);
        for index in 0..2 {
            assert_eq!(metadata[index].destination, destinations[index]);
            assert_eq!(
                Some(metadata[index].backend),
                select_backend(destinations[index])
            );
            flows[index]
                .stream
                .write_all(&[0x31 + index as u8; 512])
                .await
                .unwrap();
        }
        let mut received = [Vec::new(), Vec::new()];
        for step in 50..100 {
            exchange(&mut host, &mut peers, Duration::from_millis(step))
                .await
                .unwrap();
            for index in 0..2 {
                let peer = &mut peers[index];
                let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
                while socket.can_recv() {
                    socket
                        .recv(|bytes| {
                            received[index].extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .unwrap();
                }
            }
        }
        for index in 0..2 {
            assert_eq!(received[index], vec![0x31 + index as u8; 512]);
            flows[index]
                .stream
                .write_all(&[0x51 + index as u8; 256])
                .await
                .unwrap();
        }
        poll(&mut host, Duration::from_millis(100));
        assert!(!host.device.has_ingress());
        let queued = host.device.outgoing.clone();
        let mut queued_destinations = [false; 2];
        for packet in &queued {
            let destination: std::net::IpAddr = if ipv6 {
                Ipv6Packet::new_checked(packet.as_slice())
                    .unwrap()
                    .dst_addr()
                    .into()
            } else {
                Ipv4Packet::new_checked(packet.as_slice())
                    .unwrap()
                    .dst_addr()
                    .into()
            };
            for index in 0..2 {
                queued_destinations[index] |= destination == metadata[index].source.ip();
            }
        }
        assert_eq!(queued_destinations, [true, true]);
        let send_queues: Vec<_> = host
            .slots
            .iter()
            .map(|slot| host.sockets.get::<tcp::Socket>(slot.socket).send_queue())
            .collect();
        let error = crate::mtu_reduction::rebuild_components(
            &mut host.interface,
            &mut host.device,
            1280,
            100,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(host.device.outgoing, queued);
        assert_eq!(
            smoltcp::phy::Device::capabilities(&host.device).max_transmission_unit,
            1500
        );
        assert_eq!(
            host.slots
                .iter()
                .map(|slot| host.sockets.get::<tcp::Socket>(slot.socket).send_queue())
                .collect::<Vec<_>>(),
            send_queues
        );
        assert_eq!(host.active_flows(), 2);
        for step in 101..150 {
            exchange(&mut host, &mut peers, Duration::from_millis(step))
                .await
                .unwrap();
            for index in 0..2 {
                let peer = &mut peers[index];
                let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
                while socket.can_recv() {
                    socket
                        .recv(|bytes| {
                            received[index].extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .unwrap();
                }
            }
        }
        for index in 0..2 {
            let mut expected = vec![0x31 + index as u8; 512];
            expected.extend([0x51 + index as u8; 256]);
            assert_eq!(received[index], expected);
            flows[index]
                .stream
                .write_all(&[0x61 + index as u8; 256])
                .await
                .unwrap();
            flows[index].stream.shutdown().await.unwrap();
        }
        assert!(!host.device.has_ingress());
        assert!(host.device.outgoing.is_empty());
        crate::mtu_reduction::rebuild_components(&mut host.interface, &mut host.device, 1280, 150)
            .unwrap();
        assert_eq!(host.active_flows(), 2);
        assert_eq!(
            smoltcp::phy::Device::capabilities(&host.device).max_transmission_unit,
            1280
        );
        for expected in metadata {
            assert!(
                host.slots
                    .iter()
                    .filter_map(|slot| slot.flow.as_ref())
                    .any(|flow| flow.metadata == expected)
            );
        }
        assert!(host.interface.any_ip());
        assert_eq!([flows[0].metadata, flows[1].metadata], metadata);
        let mut finished = [false; 2];
        // The pinned TCP stack retains TIME-WAIT for ten controlled seconds.
        for step in 150..30000 {
            exchange(&mut host, &mut peers, Duration::from_millis(step))
                .await
                .unwrap();
            for index in 0..2 {
                let peer = &mut peers[index];
                let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
                while socket.can_recv() {
                    socket
                        .recv(|bytes| {
                            received[index].extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .unwrap();
                    assert!(received[index].len() <= 1024);
                }
                if !socket.may_recv() && !finished[index] {
                    socket.close();
                    finished[index] = true;
                }
            }
            if finished == [true, true] && host.active_flows() == 0 {
                break;
            }
        }
        assert_eq!(finished, [true, true]);
        assert_eq!(host.active_flows(), 0);
        for (index, actual) in received.iter().enumerate() {
            let mut expected = vec![0x31 + index as u8; 512];
            expected.extend([0x51 + index as u8; 256]);
            expected.extend([0x61 + index as u8; 256]);
            assert_eq!(actual, &expected);
        }
        assert_eq!(host.statistics().finished, 2);
        host.cancel();
        drop(flows);
        assert_eq!(host.lifetimes.available_permits(), 2);
    }
}

#[tokio::test]
async fn ingress_respects_current_experimental_mtu_in_both_families() {
    use futures::FutureExt;

    for invalid in [1279, 1501] {
        assert!(matches!(
            HostAdapter::with_mtu(Limits::default(), select_backend, invalid),
            Err(AdmissionError::InvalidMtu)
        ));
    }
    for ipv6 in [false, true] {
        let (mut host, mut accepted) =
            HostAdapter::with_mtu(Limits::default(), select_backend, 1500).unwrap();
        assert_eq!(
            host.inject(&[0; 1501]),
            Err(AdmissionError::PacketTooLarge { mtu: 1500 })
        );
        assert_eq!(host.active_flows(), 0);
        let address = source(ipv6, 2).unwrap();
        let destination = SocketAddr::new(source(ipv6, 91).unwrap().ip(), 9100);
        let mut peers = [
            Peer::with_mtu(address.ip(), address.port(), 1500).unwrap(),
            peer(ipv6, 3).unwrap(),
        ];
        let first = &mut peers[0];
        first
            .sockets
            .get_mut::<tcp::Socket>(first.tcp)
            .connect(first.interface.context(), destination, address)
            .unwrap();
        let mut flow = None;
        for step in 0..50 {
            exchange(&mut host, &mut peers, Duration::from_millis(step))
                .await
                .unwrap();
            if let Ok(accepted_flow) = accepted.try_recv() {
                flow = Some(accepted_flow);
            }
        }
        let mut flow = flow.unwrap();
        assert_eq!(flow.metadata.source, address);
        assert_eq!(flow.metadata.destination, destination);
        let first = &mut peers[0];
        first.poll(50);
        first.device.outgoing.clear();
        let sample = vec![0x6a; if ipv6 { 1440 } else { 1460 }];
        assert_eq!(
            first
                .sockets
                .get_mut::<tcp::Socket>(first.tcp)
                .send_slice(&sample)
                .unwrap(),
            sample.len()
        );
        first.poll(51);
        let packet = first.device.outgoing.pop_front().unwrap();
        assert_eq!(packet.len(), 1500);
        let (mut default_host, _default_accepted) =
            HostAdapter::new(Limits::default(), select_backend).unwrap();
        assert_eq!(
            default_host.inject(&packet),
            Err(AdmissionError::PacketTooLarge { mtu: MTU })
        );
        default_host.cancel();
        assert_eq!(host.inject(&packet), Ok(flow.metadata.id));
        let mut actual = Vec::new();
        for step in 52..100 {
            exchange(&mut host, &mut peers, Duration::from_millis(step))
                .await
                .unwrap();
            let mut buffer = [0; 2048];
            if let Some(result) = flow.stream.read(&mut buffer).now_or_never() {
                let count = result.unwrap();
                actual.extend_from_slice(&buffer[..count]);
            }
        }
        assert_eq!(actual, sample);
        assert!(!host.device.has_ingress());
        assert!(host.device.outgoing.is_empty());
        crate::mtu_reduction::rebuild_components(&mut host.interface, &mut host.device, MTU, 100)
            .unwrap();
        assert_eq!(
            host.inject(&packet),
            Err(AdmissionError::PacketTooLarge { mtu: MTU })
        );
        assert_eq!(host.active_flows(), 1);
        assert!(flow.stream.read(&mut [0; 16]).now_or_never().is_none());
        host.cancel();
        drop(flow);
        assert_eq!(host.lifetimes.available_permits(), 2);
    }
}
