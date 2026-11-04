// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded in-memory packet transport exercises direction ownership and failure.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Mutex, mpsc};
use warper_stack::{Seed, host::Limits, runtime::Runtime};

struct FakePort {
    incoming: Mutex<mpsc::Receiver<Result<Vec<u8>, PacketError>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    send_error: Option<PacketError>,
    send_calls: AtomicUsize,
}
impl PacketIo for FakePort {
    async fn recv(
        &self,
        buffer: &mut [u8; BUFFER_BYTES],
        mut request: Request,
    ) -> Result<usize, PacketError> {
        tokio::select! { biased;
            _ = request.cancellation.wait_for(|stop| *stop) => Err(PacketError::Cancelled),
            () = tokio::time::sleep_until(request.deadline) => Err(PacketError::Deadline),
            packet = async { self.incoming.lock().await.recv().await } => {
                let packet = packet.ok_or(PacketError::Closed)??;
                buffer[..packet.len()].copy_from_slice(&packet);
                Ok(packet.len())
            },
        }
    }
    async fn send(&self, packet: &[u8], mut request: Request) -> Result<(), PacketError> {
        self.send_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.send_error {
            return Err(error);
        }
        tokio::select! { biased;
            _ = request.cancellation.wait_for(|stop| *stop) => Err(PacketError::Cancelled),
            () = tokio::time::sleep_until(request.deadline) => Err(PacketError::Deadline),
            result = self.outgoing.send(packet.to_vec()) => result.map_err(|_| PacketError::Closed),
        }
    }
}
impl PacketOutput for mpsc::Receiver<Vec<u8>> {
    async fn recv(&mut self) -> Option<OutputPacket> {
        self.recv().await.map(OutputPacket::untracked)
    }
}
type Input = mpsc::Sender<Result<Vec<u8>, PacketError>>;

impl PacketOutput for mpsc::Receiver<OutputPacket> {
    async fn recv(&mut self) -> Option<OutputPacket> {
        self.recv().await
    }
}

struct Tracked {
    host: tokio::task::JoinHandle<Result<runtime::Report, runtime::Failure>>,
    channels: runtime::Channels,
    endpoint: runtime::udp_dns::Endpoint,
    packet: Option<OutputPacket>,
    receipt: Option<runtime::delivery::Receipt>,
    operation: watch::Sender<bool>,
}
impl Tracked {
    async fn new() -> Self {
        let policy = Arc::new(warper_core::routing::Policy::new(&[], 1).unwrap());
        let (runtime, mut channels) = Runtime::with_udp_dns(
            Limits::default(),
            policy,
            2,
            Seed::generate().unwrap(),
            runtime::udp_dns::Config {
                endpoint: "192.0.2.9:53".parse().unwrap(),
                requests: 1,
            },
        )
        .unwrap();
        let mut endpoint = channels.udp_dns.take().unwrap();
        let host = tokio::spawn(runtime.run());
        // Controlled IPv4/UDP query, checksum b6c1, allowed IPv4 UDP checksum 0.
        channels
            .ingress
            .try_inject(&[
                0x45, 0, 0, 32, 0, 0, 0x40, 0, 64, 17, 0xb6, 0xc1, 192, 0, 2, 2, 192, 0, 2, 9,
                0xc3, 0x50, 0, 53, 0, 12, 0, 0, b't', b'e', b's', b't',
            ])
            .unwrap();
        let datagram = endpoint.requests.recv().await.unwrap();
        let (operation, _) = watch::channel(false);
        let receipt = datagram
            .respond(
                b"reply",
                Request {
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancellation: operation.subscribe(),
                },
            )
            .unwrap();
        let packet = channels.packets.recv().await.unwrap();
        Self {
            host,
            channels,
            endpoint,
            packet: Some(packet),
            receipt: Some(receipt),
            operation,
        }
    }
    async fn close(self) {
        assert_eq!(self.endpoint.retained_requests(), 0);
        self.channels.shutdown.send(()).unwrap();
        self.host.await.unwrap().unwrap();
    }
}
fn observer(owner: &watch::Sender<bool>) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: owner.subscribe(),
    }
}

#[tokio::test(start_paused = true)]
async fn delivery_receipt_waits_for_full_native_write_and_resumes_after_observer_timeout() {
    let mut fixture = Tracked::new().await;
    let (port, _incoming, mut sent) = port(None);
    port.outgoing.send(vec![0]).await.unwrap(); // Hold the native writer pending.
    let (packets, mut output) = mpsc::channel(1);
    packets.send(fixture.packet.take().unwrap()).await.unwrap();
    let (stop, cancellation) = watch::channel(false);
    let writer = tokio::spawn(async move {
        let mut report = Report::default();
        let result = write(
            port.as_ref(),
            &mut output,
            Duration::from_secs(1),
            cancellation,
            &mut report,
        )
        .await;
        (result, report)
    });
    let (owner, _) = watch::channel(false);
    let mut wait = observer(&owner);
    wait.deadline = Instant::now() + Duration::from_millis(10);
    let timed_out = fixture.receipt.as_mut().unwrap().wait(wait).await;
    let retained = fixture.endpoint.retained_requests();
    assert_eq!(sent.recv().await.unwrap(), vec![0]);
    let written = sent.recv().await.unwrap();
    let delivered = fixture
        .receipt
        .as_mut()
        .unwrap()
        .wait(observer(&owner))
        .await;
    stop.send_replace(true);
    let (result, report) = writer.await.unwrap();
    fixture.close().await;
    assert_eq!(timed_out, Err(runtime::delivery::Error::WaitDeadline));
    assert_eq!(retained, 1);
    assert_eq!(&written[28..], b"reply");
    delivered.unwrap();
    result.unwrap();
    assert_eq!(report.sent_packets, 1);
    assert_eq!(report.lost_delivery_receipts, 0);
}

#[tokio::test(start_paused = true)]
async fn expired_or_cancelled_tracked_output_is_not_written_or_replayed_and_other_output_continues()
{
    for case in 0..4 {
        let mut fixture = Tracked::new().await;
        let (owner, _) = watch::channel(false);
        if case == 1 {
            tokio::time::advance(Duration::from_secs(2)).await;
        } else if case == 0 {
            fixture.operation.send_replace(true);
        } else if case == 2 {
            fixture
                .channels
                .admission
                .cancel_flows()
                .unwrap()
                .wait(observer(&owner))
                .await
                .unwrap();
        } else {
            drop(std::mem::replace(
                &mut fixture.operation,
                watch::channel(false).0,
            ));
        }
        let (port, _incoming, mut sent) = port(None);
        let retained_port = port.clone();
        let (packets, mut output) = mpsc::channel(2);
        packets.send(fixture.packet.take().unwrap()).await.unwrap();
        let (stop, cancellation) = watch::channel(false);
        let writer = tokio::spawn(async move {
            let mut report = Report::default();
            let result = write(
                port.as_ref(),
                &mut output,
                Duration::from_secs(1),
                cancellation,
                &mut report,
            )
            .await;
            (result, report)
        });
        let result = fixture
            .receipt
            .as_mut()
            .unwrap()
            .wait(observer(&owner))
            .await;
        let calls_before = retained_port.send_calls.load(Ordering::Relaxed);
        packets
            .send(OutputPacket::untracked(vec![7; 32]))
            .await
            .unwrap();
        let written = sent.recv().await.unwrap();
        stop.send_replace(true);
        let (joined, report) = writer.await.unwrap();
        fixture.close().await;
        let expected = if case == 1 {
            runtime::delivery::Failure::Deadline
        } else {
            runtime::delivery::Failure::Cancelled
        };
        assert_eq!(result, Err(runtime::delivery::Error::Delivery(expected)));
        assert_eq!(calls_before, 0);
        assert_eq!(written, vec![7; 32]);
        joined.unwrap();
        assert_eq!(report.discarded_output, 1);
        assert_eq!(report.sent_packets, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn tracked_native_io_joins_cancellation_and_clamps_writer_deadlines() {
    for case in 0..4 {
        let mut fixture = Tracked::new().await;
        let (port, _incoming, mut sent) = port(None);
        port.outgoing.send(vec![0]).await.unwrap();
        let retained = port.clone();
        let (packets, mut output) = mpsc::channel(1);
        packets.send(fixture.packet.take().unwrap()).await.unwrap();
        let (stop, cancellation) = watch::channel(false);
        let budget = if case == 3 {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(1)
        };
        let writer = tokio::spawn(async move {
            let mut report = Report::default();
            let result = write(
                port.as_ref(),
                &mut output,
                budget,
                cancellation,
                &mut report,
            )
            .await;
            (result, report)
        });
        for _ in 0..100 {
            if retained.send_calls.load(Ordering::Relaxed) != 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let calls = retained.send_calls.load(Ordering::Relaxed);
        let (owner, _) = watch::channel(false);
        match case {
            0 => {
                fixture
                    .channels
                    .admission
                    .cancel_flows()
                    .unwrap()
                    .wait(observer(&owner))
                    .await
                    .unwrap();
            }
            1 => {
                fixture.operation.send_replace(true);
            }
            2 => {
                stop.send_replace(true);
            }
            _ => {} // The writer budget expires before the original request.
        }
        let delivery = fixture
            .receipt
            .as_mut()
            .unwrap()
            .wait(observer(&owner))
            .await;
        stop.send_replace(true);
        let (result, report) = writer.await.unwrap();
        let initial = sent.recv().await.unwrap();
        let unexpected = sent.try_recv();
        fixture.close().await;
        assert_eq!(
            calls, 1,
            "the test must interrupt actual blocked native I/O"
        );
        let expected = if case == 3 {
            runtime::delivery::Failure::Deadline
        } else {
            runtime::delivery::Failure::Cancelled
        };
        assert_eq!(delivery, Err(runtime::delivery::Error::Delivery(expected)));
        result.unwrap();
        assert_eq!(report.discarded_output, 1);
        assert_eq!(report.sent_packets, 0);
        assert_eq!(initial, vec![0]);
        assert!(unexpected.is_err());
    }
}

#[tokio::test]
async fn failed_native_delivery_is_uncertain_and_observer_loss_preserves_the_primary_error() {
    for failure in [
        None,
        Some(PacketError::PartialWrite),
        Some(PacketError::Io(std::io::ErrorKind::PermissionDenied)),
    ] {
        for lost in [false, true] {
            let mut fixture = Tracked::new().await;
            let (port, _incoming, _sent) = port(failure);
            let (packets, mut output) = mpsc::channel(1);
            packets.send(fixture.packet.take().unwrap()).await.unwrap();
            let (stop, cancellation) = watch::channel(false);
            // Losing the receipt must be a surfaced worker failure, including when
            // the native write itself succeeded. Admission remains with the packet.
            if lost {
                drop(fixture.receipt.take());
            }
            let writer = tokio::spawn(async move {
                let mut report = Report::default();
                let result = write(
                    port.as_ref(),
                    &mut output,
                    Duration::from_secs(1),
                    cancellation,
                    &mut report,
                )
                .await;
                (result, report)
            });
            let (owner, _) = watch::channel(false);
            let delivery = if let Some(receipt) = &mut fixture.receipt {
                Some(receipt.wait(observer(&owner)).await)
            } else {
                None
            };
            if !lost {
                stop.send_replace(true);
            }
            let (result, report) = writer.await.unwrap();
            fixture.close().await;
            let expected = match failure {
                Some(error) => Err(Error::Native(error)),
                None if lost => Err(Error::DeliveryOwnerLost),
                None => Ok(()),
            };
            assert_eq!(result, expected);
            assert_eq!(report.lost_delivery_receipts, u64::from(lost));
            if !lost {
                assert_eq!(
                    delivery,
                    Some(if failure.is_none() {
                        Ok(())
                    } else {
                        Err(runtime::delivery::Error::Delivery(
                            runtime::delivery::Failure::Uncertain,
                        ))
                    })
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn losing_a_cancelled_reply_observer_is_a_worker_failure_without_native_io() {
    for expired in [false, true] {
        let mut fixture = Tracked::new().await;
        if expired {
            tokio::time::advance(Duration::from_secs(2)).await;
        } else {
            fixture.operation.send_replace(true);
        }
        drop(fixture.receipt.take());
        let (port, _incoming, _sent) = port(None);
        let (packets, mut output) = mpsc::channel(1);
        packets.send(fixture.packet.take().unwrap()).await.unwrap();
        let (_stop, cancellation) = watch::channel(false);
        let mut report = Report::default();
        let result = write(
            port.as_ref(),
            &mut output,
            Duration::from_secs(1),
            cancellation,
            &mut report,
        )
        .await;
        let calls = port.send_calls.load(Ordering::Relaxed);
        fixture.close().await;
        assert_eq!(result, Err(Error::DeliveryOwnerLost));
        assert_eq!(calls, 0);
        assert_eq!(report.discarded_output, 1);
        assert_eq!(report.lost_delivery_receipts, 1);
    }
}

fn port(send_error: Option<PacketError>) -> (Arc<FakePort>, Input, mpsc::Receiver<Vec<u8>>) {
    let (input, incoming) = mpsc::channel(4);
    let (outgoing, output) = mpsc::channel(1);
    (
        Arc::new(FakePort {
            incoming: Mutex::new(incoming),
            outgoing,
            send_error,
            send_calls: AtomicUsize::new(0),
        }),
        input,
        output,
    )
}
fn host() -> (Runtime, runtime::Channels) {
    let policy = Arc::new(warper_core::routing::Policy::new(&[], 1).unwrap());
    Runtime::new(Limits::default(), policy, 1, Seed::generate().unwrap()).unwrap()
}
fn task(
    port: Arc<FakePort>,
    ingress: Ingress,
    mut output: mpsc::Receiver<Vec<u8>>,
    cancel: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<Report, Failure>> {
    tokio::spawn(async move {
        drive(
            port.as_ref(),
            ingress,
            &mut output,
            Duration::from_secs(1),
            cancel,
        )
        .await
    })
}

#[test]
fn packet_write_deadline_has_a_positive_bounded_range() {
    assert_eq!(
        validate_timeout(Duration::ZERO),
        Err(Error::InvalidDeadline)
    );
    assert_eq!(
        validate_timeout(Duration::from_secs(31)),
        Err(Error::InvalidDeadline)
    );
    validate_timeout(Duration::from_nanos(1)).unwrap();
    validate_timeout(Duration::from_secs(30)).unwrap();
}

#[tokio::test]
async fn duplex_packets_and_ingress_exhaustion_have_bounded_counters() {
    let (_runtime, channels) = host();
    let (port, incoming, mut sent) = port(None);
    let (output, packets) = mpsc::channel(1);
    let (stop, cancellation) = watch::channel(false);
    let owner = task(port, channels.ingress, packets, cancellation);
    incoming.send(Ok(vec![1; 1280])).await.unwrap();
    incoming.send(Ok(vec![2; 1280])).await.unwrap();
    output.send(vec![3; 1280]).await.unwrap();
    assert_eq!(sent.recv().await.unwrap(), vec![3; 1280]);
    // Wait until both bounded inputs have been consumed before requesting stop.
    for _ in 0..100 {
        if incoming.capacity() == 4 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(incoming.capacity(), 4);
    stop.send(true).unwrap();
    let report = owner.await.unwrap().unwrap();
    assert_eq!(report.captured_packets, 2);
    assert_eq!(report.captured_bytes, 2560);
    assert_eq!(report.ingress_drops, 1);
    assert_eq!(report.sent_packets, 1);
    assert_eq!(report.sent_bytes, 1280);
    assert_eq!(report.write_waits.iter().sum::<u64>(), 1);
    assert_eq!(report.discarded_output, 0);
}

#[tokio::test]
async fn write_failure_is_not_retried_and_cancels_the_reader() {
    for error in [
        PacketError::PartialWrite,
        PacketError::Io(std::io::ErrorKind::BrokenPipe),
    ] {
        let (_runtime, channels) = host();
        let (port, _incoming, _sent) = port(Some(error));
        let (output, packets) = mpsc::channel(1);
        output.send(vec![1; 40]).await.unwrap();
        let (_stop, cancellation) = watch::channel(false);
        let failure = task(port.clone(), channels.ingress, packets, cancellation)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.cause, Error::Native(error));
        assert_eq!(port.send_calls.load(Ordering::Relaxed), 1);
        assert_eq!(failure.report.sent_packets, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn write_timeout_is_terminal_and_idle_reads_renew_until_explicit_stop() {
    let (_runtime, channels) = host();
    let (port, _incoming, _sent) = port(None);
    port.outgoing.send(vec![9]).await.unwrap();
    let (output, packets) = mpsc::channel(1);
    output.send(vec![1; 40]).await.unwrap();
    let (_stop, cancellation) = watch::channel(false);
    let failure = task(port.clone(), channels.ingress, packets, cancellation)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.cause, Error::Native(PacketError::Deadline));
    assert_eq!(port.send_calls.load(Ordering::Relaxed), 1);

    let (_runtime, channels) = host();
    let (port, _incoming, _sent) = self::port(None);
    let (_output, packets) = mpsc::channel(1);
    let (stop, cancellation) = watch::channel(false);
    let owner = task(port, channels.ingress, packets, cancellation);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert!(!owner.is_finished());
    stop.send(true).unwrap();
    owner.await.unwrap().unwrap();
}

#[tokio::test]
async fn canceling_a_blocked_write_joins_it_and_counts_its_discard() {
    let (_runtime, channels) = host();
    let (port, _incoming, _sent) = port(None);
    port.outgoing.send(vec![9]).await.unwrap();
    let (output, packets) = mpsc::channel(1);
    output.send(vec![1; 40]).await.unwrap();
    let (stop, cancellation) = watch::channel(false);
    let owner = task(port.clone(), channels.ingress, packets, cancellation);
    for _ in 0..100 {
        if port.send_calls.load(Ordering::Relaxed) != 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(port.send_calls.load(Ordering::Relaxed), 1);
    stop.send(true).unwrap();
    let report = owner.await.unwrap().unwrap();
    assert_eq!(report.discarded_output, 1);
    assert_eq!(report.sent_packets, 0);
}

#[tokio::test]
async fn owner_loss_and_closed_host_channels_surface_as_failures() {
    let (_runtime, channels) = host();
    let (port, _incoming, _sent) = port(None);
    let (_output, packets) = mpsc::channel(1);
    let (stop, cancellation) = watch::channel(false);
    drop(stop);
    let failure = task(port, channels.ingress, packets, cancellation)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.cause, Error::CancellationOwnerLost);

    let (_runtime, channels) = host();
    let (port, _incoming, _sent) = self::port(None);
    let (output, packets) = mpsc::channel(1);
    drop(output);
    let (_stop, cancellation) = watch::channel(false);
    let failure = task(port, channels.ingress, packets, cancellation)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.cause, Error::OutputClosed);

    let (runtime, channels) = host();
    drop(runtime);
    let (port, incoming, _sent) = self::port(None);
    incoming.send(Ok(vec![1; 40])).await.unwrap();
    let (_output, packets) = mpsc::channel(1);
    let (_stop, cancellation) = watch::channel(false);
    let failure = task(port, channels.ingress, packets, cancellation)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.cause, Error::Input(runtime::Error::IngressClosed));
}

struct BurstPort(AtomicUsize);
impl PacketIo for BurstPort {
    async fn recv(
        &self,
        buffer: &mut [u8; BUFFER_BYTES],
        _request: Request,
    ) -> Result<usize, PacketError> {
        if self.0.fetch_add(1, Ordering::Relaxed) >= 17 {
            return std::future::pending().await;
        }
        buffer[0] = 1;
        Ok(1)
    }
    async fn send(&self, _packet: &[u8], _request: Request) -> Result<(), PacketError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[tokio::test]
async fn always_ready_directions_yield_within_a_bounded_packet_batch() {
    use std::{future::poll_fn, task::Poll};
    let (_runtime, channels) = host();
    let port = BurstPort(AtomicUsize::new(0));
    let (_stop, cancellation) = watch::channel(false);
    let mut report = Report::default();
    {
        let reader = read(&port, channels.ingress, cancellation.clone(), &mut report);
        tokio::pin!(reader);
        poll_fn(|context| {
            assert!(reader.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert_eq!(
        port.0.load(Ordering::Relaxed),
        8,
        "ready input must allow supervisor and writer progress"
    );
    assert_eq!(report.ingress_drops, 7);

    let port = BurstPort(AtomicUsize::new(0));
    let (sender, mut packets) = mpsc::channel(16);
    for _ in 0..16 {
        sender.send(vec![1; 40]).await.unwrap();
    }
    let mut report = Report::default();
    {
        let writer = write(
            &port,
            &mut packets,
            Duration::from_secs(1),
            cancellation,
            &mut report,
        );
        tokio::pin!(writer);
        poll_fn(|context| {
            assert!(writer.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert_eq!(
        port.0.load(Ordering::Relaxed),
        8,
        "ready output must allow supervisor and reader progress"
    );
    assert_eq!(report.sent_packets, 8);
}

#[tokio::test]
async fn invalid_input_and_native_read_failure_stop_both_directions() {
    for (input, expected) in [
        (Ok(vec![]), PacketError::InvalidPacket),
        (Ok(vec![1; BUFFER_BYTES]), PacketError::InvalidPacket),
        (Err(PacketError::Oversized), PacketError::Oversized),
        (
            Err(PacketError::Io(std::io::ErrorKind::BrokenPipe)),
            PacketError::Io(std::io::ErrorKind::BrokenPipe),
        ),
    ] {
        let (_runtime, channels) = host();
        let (port, incoming, _sent) = port(None);
        incoming.send(input).await.unwrap();
        let (_output, packets) = mpsc::channel(1);
        let (_stop, cancellation) = watch::channel(false);
        let failure = task(port, channels.ingress, packets, cancellation)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.cause, Error::Native(expected));
        assert_eq!(failure.report.captured_packets, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn stopped_packet_driver_retains_host_output_until_explicit_runtime_shutdown() {
    let (runtime, mut channels) = host();
    let mut host = tokio::spawn(runtime.run());
    let (port, _incoming, _sent) = port(None);
    let (stop, cancellation) = watch::channel(false);

    // Exercise the actual host receiver, not a synthetic output channel.
    // The separate read future is idle; the supervisor explicitly stops it.
    {
        let running = drive(
            port.as_ref(),
            channels.ingress.clone(),
            &mut channels.packets,
            Duration::from_secs(1),
            cancellation,
        );
        tokio::pin!(running);
        std::future::poll_fn(|context| {
            assert!(running.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        stop.send(true).unwrap();
        running.await.unwrap();
    }
    // A stopped driver still owns the receiver so host termination can remain
    // an explicit service decision rather than accidental EgressClosed.
    assert!(
        tokio::time::timeout(Duration::from_millis(1), &mut host)
            .await
            .is_err(),
        "stopping packet I/O must preserve explicit runtime shutdown ownership"
    );
    channels.shutdown.send(()).unwrap();
    host.await.unwrap().unwrap();
}
