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
    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv().await
    }
}
type Input = mpsc::Sender<Result<Vec<u8>, PacketError>>;

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
