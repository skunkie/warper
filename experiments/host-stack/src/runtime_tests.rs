// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled-clock scheduling and shutdown checks.

use super::*;
use std::time::Duration;

fn runtime(capacity: usize) -> (Runtime, Channels) {
    Runtime::new(
        adapter::Limits::default(),
        udp_adapter::Limits::default(),
        crate::udp_probe::select_backend,
        capacity,
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn idle_runner_waits_without_periodic_polling_and_shutdown_is_joined() {
    let (runtime, channels) = runtime(2);
    let task = tokio::spawn(runtime.run());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(100)).await;
    tokio::task::yield_now().await;
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.turns, 1);
    assert_eq!(report.timer_wakes, 0);
}

#[tokio::test(start_paused = true)]
async fn first_packet_after_long_idle_uses_current_admission_time() {
    let (runtime, mut channels) = runtime(2);
    let runner = tokio::spawn(runtime.run());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(100)).await;
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let mut association = channels.udp.recv().await.unwrap();
    assert_eq!(association.recv().await.unwrap().payload(), b"sample");
    association.try_reply(b"reply").unwrap();
    assert!(channels.packets.recv().await.is_some());
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.udp_timed_out, 0);
}

#[tokio::test(start_paused = true)]
async fn incomplete_fragments_publish_no_handler_and_expire_without_further_input() {
    let (runtime, mut channels) = runtime(2);
    let runner = tokio::spawn(runtime.run());
    let fragments = crate::fragment_probe::split(&udp_packet(40000), 42, 8).unwrap();
    channels.ingress.try_inject(&fragments[0]).unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(channels.udp.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.fragment_timeouts, 1);
    assert_eq!(report.reassembled, 0);
    assert_eq!(report.admitted, 0);
    assert!(channels.udp.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn discarded_fragment_slots_expire_before_distinct_datagram_is_admitted() {
    for ipv6 in [false, true] {
        let (runtime, mut channels) = runtime(8);
        let runner = tokio::spawn(runtime.run());
        let first = crate::fragment_probe::split(&udp_packet_for(ipv6, 40000), 1, 8).unwrap();
        let second = crate::fragment_probe::split(&udp_packet_for(ipv6, 40001), 2, 8).unwrap();
        let blocked = crate::fragment_probe::split(&udp_packet_for(ipv6, 40002), 3, 8).unwrap();
        for fragment in [
            &first[0],
            &first[0],
            &second[0],
            &second[0],
            &blocked[0],
            &blocked[1],
        ] {
            channels.ingress.try_inject(fragment).unwrap();
        }
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            channels.udp.try_recv().is_err(),
            "incomplete or rejected fragments must not publish a handler"
        );
        tokio::time::advance(Duration::from_millis(999)).await;
        let still_blocked =
            crate::fragment_probe::split(&udp_packet_for(ipv6, 40003), 4, 8).unwrap();
        for fragment in &still_blocked {
            channels.ingress.try_inject(fragment).unwrap();
        }
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            channels.udp.try_recv().is_err(),
            "unexpired tombstones must retain capacity"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let fresh = crate::fragment_probe::split(&udp_packet_for(ipv6, 40004), 5, 8).unwrap();
        for fragment in &fresh {
            channels.ingress.try_inject(fragment).unwrap();
        }
        let mut association = channels.udp.recv().await.unwrap();
        assert_eq!(association.metadata().source.port(), 40004);
        assert_eq!(association.recv().await.unwrap().payload(), b"sample");
        assert!(
            channels.udp.try_recv().is_err(),
            "rejected fragments must not be replayed"
        );
        channels.shutdown.send(()).unwrap();
        let report = runner.await.unwrap().unwrap();
        assert_eq!(report.fragment_timeouts, 2);
        assert_eq!(report.reassembled, 1);
        assert_eq!(report.admitted, 1);
        assert_eq!(report.rejected, 6);
    }
}

#[test]
fn ingress_reserves_capacity_before_copying_and_rejects_oversized_input() {
    let (_runtime, channels) = runtime(1);
    assert_eq!(
        channels.ingress.try_inject(&vec![0; MTU + 1]),
        Err(Error::PacketTooLarge)
    );
    channels.ingress.try_inject(b"sample").unwrap();
    assert_eq!(
        channels.ingress.try_inject(b"second"),
        Err(Error::QueueFull)
    );
    assert!(matches!(
        Runtime::new(
            adapter::Limits::default(),
            udp_adapter::Limits::default(),
            crate::udp_probe::select_backend,
            0
        ),
        Err(Error::InvalidCapacity)
    ));
}

fn udp_packet(port: u16) -> Vec<u8> {
    udp_packet_for(false, port)
}

fn udp_packet_for(ipv6: bool, port: u16) -> Vec<u8> {
    let source = if ipv6 { "fd66:66::2" } else { "10.66.66.2" };
    let destination = if ipv6 {
        "[fd66:66::91]:9000"
    } else {
        "10.66.66.91:9000"
    };
    let mut peer = crate::packet_peer::Peer::new(source.parse().unwrap(), port).unwrap();
    peer.sockets
        .get_mut::<smoltcp::socket::udp::Socket>(peer.udp)
        .send_slice(b"sample", destination.parse::<SocketAddr>().unwrap())
        .unwrap();
    peer.poll(0);
    peer.device.outgoing.pop_front().unwrap()
}

#[tokio::test(start_paused = true)]
async fn udp_idle_expiry_runs_without_packet_or_application_activity() {
    let (runtime, mut channels) = Runtime::new(
        adapter::Limits::default(),
        udp_adapter::Limits {
            idle_timeout: Duration::from_secs(1),
            ..udp_adapter::Limits::default()
        },
        crate::udp_probe::select_backend,
        2,
    )
    .unwrap();
    let runner = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let mut association = channels.udp.recv().await.unwrap();
    drop(association.recv().await.unwrap());
    let start = Instant::now();
    assert!(matches!(
        association.recv().await,
        Err(udp_adapter::Error::TimedOut)
    ));
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.udp_timed_out, 1);
    assert_eq!(report.timer_wakes, 1);
}

#[tokio::test(start_paused = true)]
async fn blocked_output_does_not_spin_and_shutdown_withdraws_queued_packets() {
    let (runtime, mut channels) = runtime(1);
    let runner = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let mut association = channels.udp.recv().await.unwrap();
    drop(association.recv().await.unwrap());
    for _ in 0..4 {
        association.try_reply(b"reply").unwrap();
    }
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.emitted_udp, 1);
    assert!(
        report.turns < 12,
        "blocked output must wait for capacity or lifecycle expiry"
    );
    assert_eq!(report.timer_wakes, 0);
    assert!(
        channels.packets.recv().await.is_none(),
        "shutdown cannot release stale queued output"
    );
    assert!(matches!(
        association.recv().await,
        Err(udp_adapter::Error::Cancelled)
    ));
}

#[tokio::test(start_paused = true)]
async fn output_capacity_restoration_resumes_replies_in_order() {
    let (runtime, mut channels) = runtime(1);
    let runner = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let mut association = channels.udp.recv().await.unwrap();
    drop(association.recv().await.unwrap());
    association.try_reply(b"first").unwrap();
    association.try_reply(b"second").unwrap();
    let first = channels.packets.recv().await.unwrap();
    let second = channels.packets.recv().await.unwrap();
    assert_eq!(&first[28..], b"first");
    assert_eq!(&second[28..], b"second");
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.emitted_udp, 2);
    assert_eq!(report.timer_wakes, 0);
}

#[tokio::test(start_paused = true)]
async fn ingress_egress_and_shutdown_owner_loss_are_typed_and_cancel_accepted_handles() {
    for cause in [
        Error::IngressClosed,
        Error::EgressClosed,
        Error::ShutdownOwnerLost,
    ] {
        let (runtime, mut channels) = runtime(2);
        let runner = tokio::spawn(runtime.run());
        channels.ingress.try_inject(&udp_packet(40000)).unwrap();
        let mut association = channels.udp.recv().await.unwrap();
        drop(association.recv().await.unwrap());
        match cause {
            Error::IngressClosed => drop(channels.ingress),
            Error::EgressClosed => drop(channels.packets),
            Error::ShutdownOwnerLost => drop(channels.shutdown),
            _ => unreachable!("fixed test cases"),
        }
        let failure = runner.await.unwrap().unwrap_err();
        assert_eq!(failure.cause, cause);
        assert_eq!(failure.report.admitted, 1);
        assert!(matches!(
            association.recv().await,
            Err(udp_adapter::Error::Cancelled)
        ));
        assert!(channels.udp.recv().await.is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn rejected_packets_are_counted_without_stopping_runtime_or_emitting_output() {
    let (runtime, mut channels) = runtime(4);
    let runner = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&[]).unwrap();
    channels.ingress.try_inject(&[0x40; 20]).unwrap();
    let mut malformed = udp_packet(40000);
    *malformed.last_mut().unwrap() ^= 1;
    channels.ingress.try_inject(&malformed).unwrap();
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let mut association = channels.udp.recv().await.unwrap();
    assert_eq!(association.recv().await.unwrap().payload(), b"sample");
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.rejected, 3);
    assert_eq!(report.admitted, 1);
    assert!(channels.packets.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn aborting_and_joining_runner_cancels_handles_and_closes_packet_ingress() {
    let (runtime, mut channels) = runtime(2);
    let runner = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let mut association = channels.udp.recv().await.unwrap();
    drop(association.recv().await.unwrap());
    runner.abort();
    assert!(runner.await.unwrap_err().is_cancelled());
    assert!(matches!(
        association.recv().await,
        Err(udp_adapter::Error::Cancelled)
    ));
    assert!(channels.packets.recv().await.is_none());
    assert_eq!(
        channels.ingress.try_inject(&udp_packet(40000)),
        Err(Error::IngressClosed)
    );
}

#[tokio::test(start_paused = true)]
async fn tcp_setup_deadline_expires_with_no_ack_and_a_blocked_packet_sink() {
    let (runtime, mut channels) = Runtime::new(
        adapter::Limits {
            setup_timeout: Duration::from_secs(1),
            ..adapter::Limits::default()
        },
        udp_adapter::Limits::default(),
        crate::udp_probe::select_backend,
        1,
    )
    .unwrap();
    let runner = tokio::spawn(runtime.run());
    let mut peer = crate::packet_peer::Peer::new("10.66.66.2".parse().unwrap(), 40000).unwrap();
    peer.sockets
        .get_mut::<smoltcp::socket::tcp::Socket>(peer.tcp)
        .connect(
            peer.interface.context(),
            "10.66.66.91:9000".parse::<SocketAddr>().unwrap(),
            "10.66.66.2:40001".parse::<SocketAddr>().unwrap(),
        )
        .unwrap();
    peer.poll(0);
    channels
        .ingress
        .try_inject(&peer.device.outgoing.pop_front().unwrap())
        .unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        channels.tcp.try_recv().is_err(),
        "an incomplete handshake cannot publish a stream"
    );
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.tcp_timed_out, 1);
    assert!(report.timer_wakes >= 1);
    assert!(
        report.turns < 12,
        "blocked SYN-ACK must not cause a transport timer spin"
    );
    assert!(channels.packets.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn accepted_tcp_idle_expiry_wakes_reader_without_network_activity() {
    use tokio::io::AsyncReadExt;
    let (runtime, mut channels) = Runtime::new(
        adapter::Limits {
            idle_timeout: Duration::from_secs(1),
            ..adapter::Limits::default()
        },
        udp_adapter::Limits::default(),
        crate::udp_probe::select_backend,
        2,
    )
    .unwrap();
    let runner = tokio::spawn(runtime.run());
    let mut peer = crate::packet_peer::Peer::new("10.66.66.2".parse().unwrap(), 40000).unwrap();
    peer.sockets
        .get_mut::<smoltcp::socket::tcp::Socket>(peer.tcp)
        .connect(
            peer.interface.context(),
            "10.66.66.91:9000".parse::<SocketAddr>().unwrap(),
            "10.66.66.2:40001".parse::<SocketAddr>().unwrap(),
        )
        .unwrap();
    peer.poll(0);
    channels
        .ingress
        .try_inject(&peer.device.outgoing.pop_front().unwrap())
        .unwrap();
    peer.device
        .inject(channels.packets.recv().await.unwrap())
        .unwrap();
    peer.poll(0);
    while let Some(packet) = peer.device.outgoing.pop_front() {
        channels.ingress.try_inject(&packet).unwrap();
    }
    let mut flow = channels.tcp.recv().await.unwrap();
    let start = Instant::now();
    let error = flow.stream.read(&mut [0; 1]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.tcp_timed_out, 1);
}

#[tokio::test(start_paused = true)]
async fn udp_application_drop_wakes_retirement_without_new_input_or_timer() {
    let (runtime, mut channels) = runtime(2);
    let runner = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let association = channels.udp.recv().await.unwrap();
    drop(association);
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.udp_application_closed, 1);
    assert_eq!(report.timer_wakes, 0);
}

#[tokio::test(start_paused = true)]
async fn udp_expiry_remains_scheduled_while_packet_output_is_blocked() {
    let (runtime, mut channels) = Runtime::new(
        adapter::Limits::default(),
        udp_adapter::Limits {
            idle_timeout: Duration::from_secs(1),
            ..udp_adapter::Limits::default()
        },
        crate::udp_probe::select_backend,
        1,
    )
    .unwrap();
    let runner = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&udp_packet(40000)).unwrap();
    let mut association = channels.udp.recv().await.unwrap();
    drop(association.recv().await.unwrap());
    for _ in 0..4 {
        association.try_reply(b"reply").unwrap();
    }
    assert!(matches!(
        association.recv().await,
        Err(udp_adapter::Error::TimedOut)
    ));
    channels.shutdown.send(()).unwrap();
    let report = runner.await.unwrap().unwrap();
    assert_eq!(report.emitted_udp, 1);
    assert_eq!(report.udp_timed_out, 1);
    assert!(report.turns < 12);
}

#[tokio::test]
async fn output_drain_alternates_ready_protocols_within_its_batch_budget() {
    let (mut runtime, mut channels) = runtime(2);
    let mut peer = crate::packet_peer::Peer::new("10.66.66.2".parse().unwrap(), 40000).unwrap();
    peer.sockets
        .get_mut::<smoltcp::socket::tcp::Socket>(peer.tcp)
        .connect(
            peer.interface.context(),
            "10.66.66.91:9000".parse::<SocketAddr>().unwrap(),
            "10.66.66.2:40001".parse::<SocketAddr>().unwrap(),
        )
        .unwrap();
    peer.poll(0);
    runtime
        .tcp
        .inject(&peer.device.outgoing.pop_front().unwrap())
        .unwrap();
    runtime.udp.inject(&udp_packet(40000)).unwrap();
    let association = channels.udp.try_recv().unwrap();
    association.try_reply(b"reply").unwrap();
    runtime
        .tcp
        .poll_io(&mut Context::from_waker(Waker::noop()), Duration::ZERO)
        .unwrap();
    runtime.udp.poll(Duration::ZERO).unwrap();
    runtime.drain_output();
    assert_eq!(channels.packets.recv().await.unwrap()[9], 6);
    assert_eq!(channels.packets.recv().await.unwrap()[9], 17);
    assert_eq!(runtime.report.emitted_tcp, 1);
    assert_eq!(runtime.report.emitted_udp, 1);
}

#[tokio::test]
async fn queued_shutdown_or_owner_loss_precedes_input_and_discards_queued_ingress() {
    for explicit in [false, true] {
        let (runtime, mut channels) = runtime(2);
        channels.ingress.try_inject(&udp_packet(40000)).unwrap();
        channels.ingress.try_inject(&udp_packet(40001)).unwrap();
        if explicit {
            channels.shutdown.send(()).unwrap();
        } else {
            drop(channels.shutdown);
        }
        let report = if explicit {
            runtime.run().await.unwrap()
        } else {
            let failure = runtime.run().await.unwrap_err();
            assert_eq!(failure.cause, Error::ShutdownOwnerLost);
            failure.report
        };
        assert_eq!(report.turns, 0);
        assert_eq!(report.admitted, 0);
        assert_eq!(report.discarded_packets, 2);
        assert!(channels.udp.recv().await.is_none());
        assert!(channels.packets.recv().await.is_none());
    }
}

#[tokio::test]
async fn shutdown_guard_rechecks_a_previously_pending_packet_receive() {
    use futures::FutureExt;
    let (runtime, mut channels) = runtime(2);
    let mut receive = Box::pin(channels.packets.recv());
    assert!(receive.as_mut().now_or_never().is_none());
    runtime.output.try_send(vec![0x31]).unwrap();
    runtime.output.try_send(vec![0x72]).unwrap();
    drop(runtime);
    assert!(
        receive.await.is_none(),
        "queued output must not cross the stopped guard after a wait"
    );
}

#[tokio::test]
async fn output_batch_limit_schedules_remaining_work_without_waiting_for_new_input() {
    use futures::FutureExt;
    let (mut runtime, mut channels) = Runtime::new(
        adapter::Limits::default(),
        udp_adapter::Limits {
            associations: 9,
            accepted: 9,
            datagrams: 32,
            ..udp_adapter::Limits::default()
        },
        crate::udp_probe::select_backend,
        64,
    )
    .unwrap();
    let mut associations = Vec::new();
    for port in 40000..40009 {
        runtime.udp.inject(&udp_packet(port)).unwrap();
        let association = channels.udp.try_recv().unwrap();
        association.try_reply(b"reply").unwrap();
        associations.push(association);
    }
    runtime.udp.poll(Duration::ZERO).unwrap();
    assert!(
        runtime
            .application_wake
            .0
            .notified()
            .now_or_never()
            .is_none()
    );
    runtime.drain_output();
    assert_eq!(runtime.report.emitted_udp, 8);
    assert!(runtime.udp.has_packet());
    assert!(
        runtime
            .application_wake
            .0
            .notified()
            .now_or_never()
            .is_some()
    );
    runtime.drain_output();
    assert_eq!(runtime.report.emitted_udp, 9);
    assert!(!runtime.udp.has_packet());
}
