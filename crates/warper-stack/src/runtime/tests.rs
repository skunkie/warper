// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Owner-loss, delayed ingress, cancellation and bounded channel behavior.

use super::*;
use crate::fixture::Peer;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warper_core::{BackendId, routing::Entry};

fn create(capacity: usize) -> (Runtime, Channels) {
    let policy = Arc::new(
        Policy::new(
            &[Entry {
                network: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                backend: BackendId(70000),
            }],
            1,
        )
        .unwrap(),
    );
    Runtime::new(Limits::default(), policy, capacity, Seed::fixture()).unwrap()
}

#[tokio::test]
async fn local_dns_runtime_dispatches_tcp_separately_and_cancels_retained_streams() {
    let endpoint = "192.0.2.9:53".parse().unwrap();
    let (runtime, mut channels) = Runtime::with_dns(
        Limits::default(),
        Arc::new(Policy::new(&[], 1).unwrap()),
        8,
        Seed::fixture(),
        udp_dns::Config {
            endpoint,
            requests: 1,
        },
    )
    .unwrap();
    let mut dns = channels.tcp_dns.take().unwrap();
    let mut peer = Peer::with_destination(false, 50000, endpoint);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let task = tokio::spawn(runtime.run());
    let syn_ack = channels.packets.recv().await.unwrap();
    peer.device.inject(syn_ack.into_bytes()).unwrap();
    peer.poll(Duration::ZERO);
    while let Some(packet) = peer.device.outgoing.pop_front() {
        channels.ingress.try_inject(&packet).unwrap();
    }
    let mut flow = tokio::time::timeout(Duration::from_secs(1), dns.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.metadata.source, peer.source);
    assert_eq!(flow.metadata.destination, endpoint);
    assert!(channels.tcp.try_recv().is_err());
    let (owner, _) = tokio::sync::watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(1);
    flow.stream
        .dns_output()
        .unwrap()
        .begin(warper_core::transport::Request {
            deadline,
            cancellation: owner.subscribe(),
        })
        .unwrap();
    flow.stream.write_all(b"response").await.unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = channels.packets.recv().await.unwrap();
            if packet.request().is_some() {
                break packet;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(packet.request().unwrap().deadline, deadline);
    assert!(!*packet.cancellation().unwrap().borrow());
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert!(*packet.cancellation().unwrap().borrow());
    packet.complete(Err(delivery::Failure::Cancelled)).unwrap();
    assert_eq!(report.tcp.accepted, 1);
    assert_eq!(report.udp_dns.received, 0);
    assert_eq!(report.retained_streams, 1);
    assert_eq!(
        flow.stream.read(&mut [0]).await.unwrap_err().kind(),
        std::io::ErrorKind::Interrupted
    );
    drop(flow);
    assert_eq!(channels.publication.retained_flows(), 0);
}

#[tokio::test]
async fn local_dns_tcp_consumer_loss_stops_the_runtime() {
    let (runtime, mut channels) = Runtime::with_dns(
        Limits::default(),
        Arc::new(Policy::new(&[], 1).unwrap()),
        8,
        Seed::fixture(),
        udp_dns::Config {
            endpoint: "192.0.2.9:53".parse().unwrap(),
            requests: 1,
        },
    )
    .unwrap();
    drop(channels.tcp_dns.take());
    let result = runtime.run().await.unwrap_err();
    assert_eq!(result.cause, Error::ConsumerClosed);
    assert_eq!(result.report.retained_streams, 0);
    assert!(!channels.publication.is_published());
}

#[tokio::test(start_paused = true)]
async fn long_idle_admission_uses_the_wake_clock_and_shutdown_closes_retained_streams() {
    let (runtime, mut channels) = create(8);
    let task = tokio::spawn(runtime.run());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(600)).await;
    let mut peer = Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let syn_ack = channels.packets.recv().await.unwrap();
    peer.device.inject(syn_ack.into_bytes()).unwrap();
    peer.poll(Duration::from_secs(600));
    while let Some(packet) = peer.device.outgoing.pop_front() {
        channels.ingress.try_inject(&packet).unwrap();
    }
    let mut flow = channels.tcp.recv().await.unwrap();
    assert_eq!(flow.metadata.source, peer.source);
    assert_eq!(flow.metadata.backend, BackendId(70000));
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.tcp.accepted, 1);
    assert_eq!(report.tcp.timed_out, 0);
    assert_eq!(report.retained_streams, 1);
    assert!(!channels.publication.is_published());
    assert!(channels.publication.is_quiescent());
    assert_eq!(channels.publication.retained_flows(), 1);
    assert!(channels.packets.recv().await.is_none());
    let mut byte = [0; 1];
    assert_eq!(
        flow.stream.read(&mut byte).await.unwrap_err().kind(),
        std::io::ErrorKind::Interrupted
    );
    drop(flow);
    assert_eq!(channels.publication.retained_flows(), 0);
}

#[tokio::test]
async fn queued_stop_discards_input_without_publishing_output_or_accepting_flows() {
    let (runtime, mut channels) = create(3);
    for _ in 0..3 {
        channels.ingress.try_inject(&[0]).unwrap();
    }
    assert_eq!(channels.ingress.try_inject(&[0]), Err(Error::QueueFull));
    assert_eq!(
        channels.ingress.try_inject(&vec![0; MTU + 1]),
        Err(Error::PacketTooLarge)
    );
    channels.shutdown.send(()).unwrap();
    let report = runtime.run().await.unwrap();
    assert_eq!(report.discarded_ingress, 3);
    assert_eq!(report.admitted_packets, 0);
    assert!(channels.packets.recv().await.is_none());
    assert!(channels.tcp.recv().await.is_none());
    assert_eq!(channels.ingress.try_inject(&[0]), Err(Error::IngressClosed));
}

#[tokio::test]
async fn rejected_packet_categories_are_counted_without_accepting_a_flow() {
    let (runtime, mut channels) = create(8);
    channels.ingress.try_inject(&[0]).unwrap();
    let mut peer = Peer::new(false, 50000);
    let syn = peer.syn();
    let mut udp = syn.clone();
    udp[9] = 17;
    smoltcp::wire::Ipv4Packet::new_unchecked(&mut udp).fill_checksum();
    channels.ingress.try_inject(&udp).unwrap();
    channels.ingress.try_inject(&syn).unwrap();
    let task = tokio::spawn(runtime.run());
    // FIFO ingress: the final SYN's reply proves both rejections were processed.
    drop(
        tokio::time::timeout(Duration::from_secs(1), channels.packets.recv())
            .await
            .unwrap()
            .unwrap(),
    );
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.rejected_packets, 2);
    assert_eq!(report.unsupported_packets, 1);
    assert_eq!(report.tcp.admitted, 1);
    assert!(channels.tcp.recv().await.is_none());
    assert!(channels.packets.recv().await.is_none());
}

#[tokio::test]
async fn lost_input_output_acceptance_or_shutdown_owners_surface_failures() {
    for expected in [
        Error::IngressClosed,
        Error::EgressClosed,
        Error::ConsumerClosed,
        Error::ShutdownOwnerLost,
    ] {
        let (runtime, channels) = create(2);
        let Channels {
            ingress,
            packets,
            tcp,
            udp_dns: _,
            tcp_dns: _,
            admission: _,
            publication,
            shutdown,
        } = channels;
        let mut ingress = Some(ingress);
        let mut packets = Some(packets);
        let mut tcp = Some(tcp);
        let mut shutdown = Some(shutdown);
        match expected {
            Error::IngressClosed => {
                drop(ingress.take());
                assert!(!publication.is_published());
            }
            Error::EgressClosed => drop(packets.take()),
            Error::ConsumerClosed => drop(tcp.take()),
            Error::ShutdownOwnerLost => drop(shutdown.take()),
            _ => unreachable!(),
        }
        let failure = tokio::time::timeout(Duration::from_secs(1), runtime.run())
            .await
            .expect("a metadata observer must not hide required owner loss")
            .unwrap_err();
        assert_eq!(failure.cause, expected);
        drop((ingress, packets, tcp, shutdown));
    }
}

#[tokio::test]
async fn dropping_an_owned_runtime_task_cancels_and_joins_without_emitting_late_packets() {
    let (runtime, mut channels) = create(2);
    let task = tokio::spawn(runtime.run());
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(channels.packets.recv().await.is_none());
    assert!(channels.tcp.recv().await.is_none());
    assert_eq!(channels.ingress.try_inject(&[0]), Err(Error::IngressClosed));
}

#[test]
fn constructor_and_reservation_reject_invalid_capacity_before_allocating_channels() {
    for capacity in [0, 65] {
        assert_eq!(
            Runtime::required_buffer_capacity(Limits::default(), capacity),
            Err(Error::InvalidCapacity)
        );
    }
    let (runtime, _channels) = create(64);
    assert_eq!(
        runtime.buffer_capacity(),
        Runtime::required_buffer_capacity(Limits::default(), 64).unwrap()
    );
    assert!(runtime.buffer_capacity() < 1024 * 1024);
}

fn observation(owner: &tokio::sync::watch::Sender<bool>) -> warper_core::transport::Request {
    warper_core::transport::Request {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: owner.subscribe(),
    }
}

#[tokio::test(start_paused = true)]
async fn quiescence_waits_retain_work_and_unread_results_until_joined() {
    let (runtime, mut channels) = create(8);
    let (owner, _) = tokio::sync::watch::channel(false);
    let mut receipt = channels.admission.quiesce().unwrap();
    assert!(matches!(
        channels.admission.quiesce(),
        Err(Error::ControlBusy)
    ));
    assert_eq!(
        receipt.wait(observation(&owner)).await,
        Err(Error::WaitDeadline)
    );
    owner.send_replace(true);
    assert_eq!(
        receipt.wait(observation(&owner)).await,
        Err(Error::WaitCancelled)
    );
    owner.send_replace(false);
    let (detached, cancellation) = tokio::sync::watch::channel(false);
    drop(detached);
    assert_eq!(
        receipt
            .wait(warper_core::transport::Request {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation
            })
            .await,
        Err(Error::WaitCancelled)
    );
    let mut peer = Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let task = tokio::spawn(runtime.run());
    // A reset proves the command took effect while its receipt is unread.
    let packet = tokio::time::timeout(Duration::from_secs(1), channels.packets.recv())
        .await
        .unwrap()
        .unwrap();
    peer.device.inject(packet.into_bytes()).unwrap();
    peer.poll(Duration::ZERO);
    assert_eq!(peer.tcp().state(), smoltcp::socket::tcp::State::Closed);
    assert!(matches!(
        channels.admission.quiesce(),
        Err(Error::ControlBusy)
    ));
    assert_eq!(
        receipt.wait(observation(&owner)).await.unwrap(),
        AdmissionSnapshot {
            active_flows: 0,
            retained_streams: 0
        }
    );
    assert_eq!(
        receipt.wait(observation(&owner)).await,
        Err(Error::AlreadyJoined)
    );
    let mut repeated = channels.admission.quiesce().unwrap();
    assert_eq!(
        repeated
            .wait(observation(&owner))
            .await
            .unwrap()
            .active_flows,
        0
    );
    assert!(!task.is_finished());
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.tcp.admitted, 0);
    assert_eq!(report.retained_streams, 0);
    assert!(channels.tcp.try_recv().is_err());
}

#[tokio::test]
async fn dropped_observer_does_not_retract_quiescence_or_terminate_the_runtime() {
    let (runtime, mut channels) = create(8);
    let (owner, _) = tokio::sync::watch::channel(false);
    let receipt = channels.admission.quiesce().unwrap();
    drop(receipt);
    assert!(matches!(
        channels.admission.quiesce(),
        Err(Error::ControlBusy)
    ));
    let mut peer = Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let task = tokio::spawn(runtime.run());
    let packet = tokio::time::timeout(Duration::from_secs(1), channels.packets.recv())
        .await
        .unwrap()
        .unwrap();
    peer.device.inject(packet.into_bytes()).unwrap();
    peer.poll(Duration::ZERO);
    assert_eq!(peer.tcp().state(), smoltcp::socket::tcp::State::Closed);
    let mut receipt = channels.admission.quiesce().unwrap();
    receipt.wait(observation(&owner)).await.unwrap();
    assert!(!task.is_finished());
    channels.shutdown.send(()).unwrap();
    assert_eq!(task.await.unwrap().unwrap().tcp.accepted, 0);
}

#[tokio::test]
async fn admission_owner_loss_disables_commands_without_spinning_or_stopping_packets() {
    let (runtime, mut channels) = create(8);
    let task = tokio::spawn(runtime.run());
    tokio::task::yield_now().await;
    drop(channels.admission);
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished());
    let mut peer = Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(1), channels.packets.recv())
        .await
        .unwrap()
        .unwrap();
    peer.device.inject(packet.into_bytes()).unwrap();
    peer.poll(Duration::ZERO);
    assert_eq!(peer.tcp().state(), smoltcp::socket::tcp::State::Established);
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.tcp.admitted, 1);
    assert!(report.turns < 16, "a closed control queue must not spin");
}

#[tokio::test]
async fn runtime_loss_surfaces_failed_quiescence_and_closes_future_admission() {
    let (runtime, channels) = create(8);
    let (owner, _) = tokio::sync::watch::channel(false);
    let mut receipt = channels.admission.quiesce().unwrap();
    drop(runtime);
    assert_eq!(
        receipt.wait(observation(&owner)).await,
        Err(Error::ControlOwnerLost)
    );
    assert!(matches!(
        channels.admission.quiesce(),
        Err(Error::ControlClosed)
    ));
}

#[tokio::test]
async fn publications_observe_quiescence_and_distinguish_equal_policy_runtimes() {
    let (runtime, channels) = create(8);
    let (other, other_channels) = create(8);
    let publication = channels.publication.clone();
    assert!(publication.same_runtime(&channels.publication));
    assert!(!publication.same_runtime(&other_channels.publication));
    assert_eq!(publication.entries(), other_channels.publication.entries());
    assert!(publication.is_published());
    assert!(!publication.is_quiescent());
    assert_eq!(publication.retained_flows(), 0);
    let (owner, _) = tokio::sync::watch::channel(false);
    let mut receipt = channels.admission.quiesce().unwrap();
    let task = tokio::spawn(runtime.run());
    receipt.wait(observation(&owner)).await.unwrap();
    assert!(publication.is_published());
    assert!(publication.is_quiescent());
    channels.shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert!(!publication.is_published());
    assert!(publication.is_quiescent());
    drop(other);
    assert!(!other_channels.publication.is_published());
    assert!(other_channels.publication.is_quiescent());
}

async fn cancel_idle_flow(ipv6: bool) -> (Duration, u64, usize) {
    use std::future::{Future, poll_fn};
    let mut peer = Peer::new(ipv6, 50000);
    let policy = Arc::new(
        Policy::new(
            &[Entry {
                network: peer.destination.ip(),
                prefix_len: if ipv6 { 128 } else { 32 },
                backend: BackendId(70000),
            }],
            1,
        )
        .unwrap(),
    );
    let (runtime, mut channels) =
        Runtime::new(Limits::default(), policy, 8, Seed::fixture()).unwrap();
    let task = tokio::spawn(runtime.run());
    channels.ingress.try_inject(&peer.syn()).unwrap();
    peer.device
        .inject(channels.packets.recv().await.unwrap().into_bytes())
        .unwrap();
    peer.poll(Duration::ZERO);
    while let Some(packet) = peer.device.outgoing.pop_front() {
        channels.ingress.try_inject(&packet).unwrap();
    }
    let mut flow = channels.tcp.recv().await.unwrap();
    let (parked, ready) = oneshot::channel();
    let mut reader = tokio::spawn(async move {
        let mut parked = Some(parked);
        let mut byte = [0];
        let outcome = {
            let mut read = std::pin::pin!(flow.stream.read(&mut byte));
            poll_fn(|context| {
                let result = read.as_mut().poll(context);
                if result.is_pending()
                    && let Some(parked) = parked.take()
                {
                    parked.send(()).unwrap();
                }
                result
            })
            .await
        };
        (flow, outcome)
    });
    ready.await.unwrap();
    let (owner, _) = tokio::sync::watch::channel(false);
    let started = std::time::Instant::now();
    let mut receipt = channels.admission.cancel_flows().unwrap();
    assert!(matches!(
        channels.admission.quiesce(),
        Err(Error::ControlBusy)
    ));
    let snapshot = receipt.wait(observation(&owner)).await.unwrap();
    assert_eq!(snapshot.active_flows, 0);
    assert_eq!(snapshot.retained_streams, 1);
    assert!(channels.publication.is_published());
    assert!(channels.publication.is_quiescent());
    // The join timeout cannot poll/wake the independently parked read.
    let read_result = tokio::time::timeout(Duration::from_secs(1), &mut reader).await;
    if read_result.is_err() {
        reader.abort();
        assert!(matches!(reader.await, Err(error) if error.is_cancelled()));
        channels.shutdown.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(
            read_result.is_ok(),
            "flow cancellation must wake a parked application read"
        );
        return (Duration::ZERO, 0, 0);
    }
    let (flow, outcome) = read_result.unwrap().unwrap();
    assert_eq!(outcome.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
    assert_eq!(channels.publication.retained_flows(), 1);
    let mut repeated = channels.admission.cancel_flows().unwrap();
    assert_eq!(repeated.wait(observation(&owner)).await.unwrap(), snapshot);
    drop(flow);
    assert_eq!(channels.publication.retained_flows(), 0);
    let latency = started.elapsed();
    let discarded = channels.packets.discard_pending();
    let mut rejected = Peer::new(ipv6, 50001);
    channels.ingress.try_inject(&rejected.syn()).unwrap();
    loop {
        let packet = channels.packets.recv().await.unwrap();
        rejected.device.inject(packet.into_bytes()).unwrap();
        rejected.poll(Duration::ZERO);
        if rejected.tcp().state() == smoltcp::socket::tcp::State::Closed {
            break;
        }
    }
    assert!(channels.publication.is_published());
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.tcp.accepted, 1);
    assert_eq!(report.tcp.cancelled, 1);
    assert_eq!(report.retained_streams, 0);
    (latency, report.emitted_packets, discarded)
}

#[tokio::test(start_paused = true)]
async fn forced_flow_cancellation_wakes_idle_io_and_retains_the_policy_and_stream_reservation() {
    for ipv6 in [false, true] {
        cancel_idle_flow(ipv6).await;
    }
}

#[tokio::test]
async fn packet_discard_is_bounded_and_keeps_the_runtime_output_owner_alive() {
    for capacity in [1, 3, MAX_QUEUE] {
        let (sender, receiver) = mpsc::channel(capacity);
        let mut packets = Egress {
            receiver,
            stopped: Arc::new(AtomicBool::new(false)),
        };
        for _ in 0..capacity {
            sender
                .try_send(delivery::Packet::untracked(vec![7; MTU]))
                .unwrap();
        }
        assert_eq!(packets.discard_pending(), capacity);
        assert_eq!(packets.discard_pending(), 0);
        sender
            .try_send(delivery::Packet::untracked(vec![17]))
            .unwrap();
        assert_eq!(packets.recv().await.unwrap().into_bytes(), vec![17]);
        drop(sender);
        assert!(packets.recv().await.is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn dropped_cancel_observer_cancels_buffered_queued_streams_without_unpublishing_the_mapping()
{
    let (runtime, mut channels) = create(8);
    let task = tokio::spawn(runtime.run());
    let mut peer = Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    peer.device
        .inject(channels.packets.recv().await.unwrap().into_bytes())
        .unwrap();
    peer.poll(Duration::ZERO);
    peer.tcp().send_slice(b"q").unwrap();
    peer.poll(Duration::ZERO);
    while let Some(packet) = peer.device.outgoing.pop_front() {
        channels.ingress.try_inject(&packet).unwrap();
    }
    // A data ACK is emitted after the stream has been published into the
    // still-unread acceptance queue and its byte copied into bounded storage.
    let packet = tokio::time::timeout(Duration::from_secs(1), channels.packets.recv())
        .await
        .unwrap()
        .unwrap();
    peer.device.inject(packet.into_bytes()).unwrap();
    peer.poll(Duration::from_millis(10));
    assert_eq!(channels.tcp.len(), 1);
    drop(channels.admission.cancel_flows().unwrap());
    let reset = tokio::time::timeout(Duration::from_secs(1), channels.packets.recv())
        .await
        .unwrap()
        .unwrap();
    peer.device.inject(reset.into_bytes()).unwrap();
    peer.poll(Duration::from_millis(10));
    assert_eq!(peer.tcp().state(), smoltcp::socket::tcp::State::Closed);
    assert_eq!(channels.publication.retained_flows(), 1);
    let (owner, _) = tokio::sync::watch::channel(false);
    let mut receipt = channels.admission.quiesce().unwrap();
    assert_eq!(
        receipt.wait(observation(&owner)).await.unwrap(),
        AdmissionSnapshot {
            active_flows: 0,
            retained_streams: 1
        }
    );
    let mut flow = channels.tcp.recv().await.unwrap();
    let mut byte = [0];
    assert_eq!(
        flow.stream.read(&mut byte).await.unwrap_err().kind(),
        std::io::ErrorKind::Interrupted,
        "buffered bytes must not escape after explicit cancellation"
    );
    drop(flow);
    assert_eq!(channels.publication.retained_flows(), 0);
    assert!(channels.publication.is_published());
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.tcp.cancelled, 1);
    assert_eq!(report.retained_streams, 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "controlled release workload"]
async fn forced_flow_cancellation_workload() {
    fn cpu_ns() -> i128 {
        let value = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec)
    }
    let started = std::time::Instant::now();
    let cpu = cpu_ns();
    let mut latencies = Vec::with_capacity(100);
    let mut emitted = 0;
    let mut discarded = 0;
    for _ in 0..100 {
        let (latency, packets, dropped) = cancel_idle_flow(false).await;
        latencies.push(latency.as_nanos());
        emitted += packets;
        discarded += dropped;
    }
    let elapsed = started.elapsed().as_nanos();
    let cpu = cpu_ns() - cpu;
    latencies.sort_unstable();
    let memory = std::fs::read_to_string("/proc/self/status").unwrap();
    let peak = memory
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .unwrap();
    println!(
        "iterations=100 concurrency=1 elapsed_ns={elapsed} cpu_ns={cpu} cancel_p50_ns={} cancel_p95_ns={} cancel_p99_ns={} emitted_ip_packets={emitted} discarded_pending_packets={discarded} app_bytes=0 failures=0 kernel_drops=unmeasured {peak}",
        latencies[49], latencies[94], latencies[98]
    );
}

#[tokio::test]
async fn forced_cancellation_releases_staged_and_queued_input_before_acknowledging() {
    let (mut runtime, mut channels) = create(3);
    runtime.pending = Some(vec![0]);
    for _ in 0..3 {
        channels.ingress.try_inject(&[0]).unwrap();
    }
    let (owner, _) = tokio::sync::watch::channel(false);
    let mut receipt = channels.admission.cancel_flows().unwrap();
    // Drive the actual queued command before polling packets: acknowledgment
    // must release capacity now, not rely on later packet processing to do it.
    let command = runtime.commands.try_recv().unwrap();
    runtime.apply_admission(command).unwrap();
    assert_eq!(
        receipt.wait(observation(&owner)).await.unwrap(),
        AdmissionSnapshot {
            active_flows: 0,
            retained_streams: 0
        }
    );
    let mut peer = Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let task = tokio::spawn(runtime.run());
    let packet = channels.packets.recv().await.unwrap();
    peer.device.inject(packet.into_bytes()).unwrap();
    peer.poll(Duration::ZERO);
    assert_eq!(peer.tcp().state(), smoltcp::socket::tcp::State::Closed);
    channels.shutdown.send(()).unwrap();
    let report = task.await.unwrap().unwrap();
    assert_eq!(report.discarded_ingress, 4);
    assert_eq!(report.rejected_packets, 1);
    assert_eq!(report.tcp.admitted, 0);
}

#[tokio::test]
async fn selector_owner_failure_terminates_the_runtime_and_reaches_its_joiner() {
    use crate::routing_fixture::LeaseRoutes;
    use std::sync::atomic::Ordering;

    let mut peer = Peer::new(false, 50000);
    let routes = LeaseRoutes::new(peer.destination.ip());
    let (runtime, channels) =
        Runtime::with_selector(Limits::default(), routes.clone(), 2, Seed::fixture()).unwrap();
    assert_eq!(
        channels
            .publication
            .selected_backend(peer.destination.ip())
            .unwrap(),
        BackendId(70000)
    );
    assert_eq!(
        routes.ledger.lock().unwrap().stats().flows,
        0,
        "publication lookup must not create a flow"
    );
    routes.behavior.store(3, Ordering::Release);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let task = tokio::spawn(runtime.run());
    let failure = task.await.unwrap().unwrap_err();
    assert_eq!(
        failure.cause,
        Error::Host(AdmissionError::SelectionUnavailable)
    );
    assert_eq!(failure.report.retained_streams, 0);
    assert!(!channels.publication.is_published());
}
