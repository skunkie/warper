// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Owner-loss, delayed ingress, cancellation and bounded channel behavior.

use super::*;
use crate::fixture::Peer;
use std::time::Duration;
use tokio::io::AsyncReadExt;
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

#[tokio::test(start_paused = true)]
async fn long_idle_admission_uses_the_wake_clock_and_shutdown_closes_retained_streams() {
    let (runtime, mut channels) = create(8);
    let task = tokio::spawn(runtime.run());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(600)).await;
    let mut peer = Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    let syn_ack = channels.packets.recv().await.unwrap();
    peer.device.inject(syn_ack).unwrap();
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
    assert!(channels.packets.recv().await.is_none());
    let mut byte = [0; 1];
    assert_eq!(
        flow.stream.read(&mut byte).await.unwrap_err().kind(),
        std::io::ErrorKind::Interrupted
    );
    drop(flow);
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
    tokio::time::timeout(Duration::from_secs(1), channels.packets.recv())
        .await
        .unwrap()
        .unwrap();
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
            admission: _,
            shutdown,
        } = channels;
        let mut ingress = Some(ingress);
        let mut packets = Some(packets);
        let mut tcp = Some(tcp);
        let mut shutdown = Some(shutdown);
        match expected {
            Error::IngressClosed => drop(ingress.take()),
            Error::EgressClosed => drop(packets.take()),
            Error::ConsumerClosed => drop(tcp.take()),
            Error::ShutdownOwnerLost => drop(shutdown.take()),
            _ => unreachable!(),
        }
        let failure = runtime.run().await.unwrap_err();
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
    peer.device.inject(packet).unwrap();
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
    peer.device.inject(packet).unwrap();
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
    peer.device.inject(packet).unwrap();
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
