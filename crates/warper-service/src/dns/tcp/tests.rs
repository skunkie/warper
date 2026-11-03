// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use std::{
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::DuplexStream,
    sync::{oneshot, watch},
    time::Instant,
};
use warper_core::transport::{Capabilities, OpenTcp, TcpStream};

use super::*;

const UPSTREAM: &str = "192.0.2.53:53";

struct MockBackend {
    stream: Mutex<Option<DuplexStream>>,
    calls: AtomicUsize,
    capabilities: Capabilities,
}

struct RejectingDirect {
    calls: AtomicUsize,
}

impl EndpointConnector for RejectingDirect {
    fn connect_tcp(&self, endpoint: SocketAddr, _request: Request) -> OpenTcp<'_> {
        assert_eq!(endpoint, UPSTREAM.parse().unwrap());
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(BackendError::UnsupportedIntegration) })
    }
}

impl Backend for MockBackend {
    fn id(&self) -> BackendId {
        BackendId(7)
    }
    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
    fn open_tcp(&self, destination: SocketAddr, request: Request) -> OpenTcp<'_> {
        assert_eq!(destination, UPSTREAM.parse().unwrap());
        assert!(request.deadline > Instant::now());
        self.calls.fetch_add(1, Ordering::SeqCst);
        let stream = self.stream.lock().unwrap().take();
        Box::pin(async move {
            stream
                .map(|stream| Box::new(stream) as TcpStream)
                .ok_or(BackendError::ResourceLimit)
        })
    }
}

fn wire() -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    wire
}

fn limits() -> Limits {
    Limits::new(512, 16).unwrap()
}
fn query() -> Packet {
    Packet::request(&wire(), limits()).unwrap()
}
fn context() -> (watch::Sender<bool>, Request) {
    let (owner, cancellation) = watch::channel(false);
    (
        owner,
        Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        },
    )
}

fn fixture(capacity: usize) -> (Arc<MockBackend>, Admission, TcpTransport, DuplexStream) {
    let (stream, peer) = tokio::io::duplex(capacity);
    let backend = Arc::new(MockBackend {
        stream: Mutex::new(Some(stream)),
        calls: AtomicUsize::new(0),
        capabilities: Capabilities {
            ipv4: true,
            ipv6: false,
            tcp: true,
            udp: false,
        },
    });
    let admission = Admission::new(1).unwrap();
    let transport = TcpTransport::new(
        backend.clone(),
        UPSTREAM.parse().unwrap(),
        limits(),
        admission.clone(),
    )
    .unwrap();
    (backend, admission, transport, peer)
}

async fn read_query(peer: &mut DuplexStream) {
    let length = peer.read_u16().await.unwrap();
    assert_eq!(usize::from(length), wire().len());
    let mut bytes = vec![0; usize::from(length)];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, wire());
}

#[tokio::test]
async fn partial_frames_preserve_valid_negatives_without_retry() {
    for code in [0, 2, 3, 5] {
        let (backend, admission, transport, mut peer) = fixture(1);
        let task = tokio::spawn(async move {
            read_query(&mut peer).await;
            let mut response = wire();
            response[2] = 0x81;
            response[3] = 0x80 | code;
            let mut frame = (response.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&response);
            for byte in frame {
                peer.write_all(&[byte]).await.unwrap();
            }
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        });
        let (_owner, request) = context();
        let response = transport.exchange(&query(), request).await.unwrap();
        assert_eq!(response.response_code(), u16::from(code));
        assert_eq!(transport.backend(), BackendId(7));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        assert_eq!(admission.active(), 0);
        task.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_timeout_and_future_drop_release_stream_and_shared_admission() {
    for mode in ["cancel", "timeout", "drop"] {
        let (backend, admission, transport, mut peer) = fixture(64);
        let (ready, notified) = oneshot::channel();
        let task = tokio::spawn(async move {
            read_query(&mut peer).await;
            peer.write_all(&[0]).await.unwrap();
            ready.send(()).unwrap();
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        });
        let (owner, request) = context();
        let query = query();
        let mut exchange = Box::pin(transport.exchange(&query, request.clone()));
        tokio::select! { biased;
            result = &mut exchange => panic!("completed before the response prefix: {result:?}"),
            () = async { notified.await.unwrap() } => (),
        }
        assert_eq!(admission.active(), 1);
        let direct_connector = Arc::new(RejectingDirect {
            calls: AtomicUsize::new(0),
        });
        let direct = DirectTcpTransport::new(
            direct_connector.clone(),
            UPSTREAM.parse().unwrap(),
            limits(),
            admission.clone(),
        )
        .unwrap();
        assert!(matches!(
            direct.exchange(&query, request.clone()).await,
            Err(ExchangeError::ResourceLimit)
        ));
        assert_eq!(direct_connector.calls.load(Ordering::SeqCst), 0);
        let other = TcpTransport::new(
            backend.clone(),
            UPSTREAM.parse().unwrap(),
            limits(),
            admission.clone(),
        )
        .unwrap();
        assert!(matches!(
            other.exchange(&query, request.clone()).await,
            Err(ExchangeError::ResourceLimit)
        ));
        match mode {
            "cancel" => {
                owner.send(true).unwrap();
                assert!(matches!(
                    exchange.await,
                    Err(ExchangeError::Backend(BackendError::Cancelled))
                ));
            }
            "timeout" => {
                tokio::time::advance(Duration::from_secs(1)).await;
                assert!(matches!(
                    exchange.await,
                    Err(ExchangeError::Backend(BackendError::Timeout))
                ));
            }
            "drop" => drop(exchange),
            _ => unreachable!(),
        }
        task.await.unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        assert_eq!(admission.active(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn expired_cancelled_and_ownerless_requests_never_start_backend_work() {
    for mode in ["expired", "cancelled", "ownerless"] {
        let (backend, admission, transport, peer) = fixture(1);
        let (owner, mut request) = context();
        match mode {
            "expired" => request.deadline = Instant::now(),
            "cancelled" => owner.send(true).unwrap(),
            "ownerless" => drop(owner),
            _ => unreachable!(),
        }
        let result = transport.exchange(&query(), request).await;
        assert!(matches!(
            result,
            Err(ExchangeError::Backend(
                BackendError::Timeout | BackendError::Cancelled
            ))
        ));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.active(), 0);
        drop(peer);
    }
}

#[tokio::test]
async fn malformed_frames_and_tcp_truncation_do_not_retry_or_leak_admission() {
    for mode in [
        "oversize",
        "short",
        "prefix_eof",
        "body_eof",
        "mismatch",
        "truncated",
    ] {
        let (backend, admission, transport, mut peer) = fixture(1024);
        let task = tokio::spawn(async move {
            read_query(&mut peer).await;
            match mode {
                "oversize" => peer.write_all(&513_u16.to_be_bytes()).await.unwrap(),
                "short" => peer.write_all(&11_u16.to_be_bytes()).await.unwrap(),
                "prefix_eof" => peer.write_all(&[0]).await.unwrap(),
                "body_eof" => peer.write_all(&[0, 12, 1, 2]).await.unwrap(),
                _ => {
                    let mut response = wire();
                    response[2] = 0x81;
                    if mode == "mismatch" {
                        response[0] = 0;
                    } else {
                        response[2] |= 2;
                    }
                    peer.write_all(&(response.len() as u16).to_be_bytes())
                        .await
                        .unwrap();
                    peer.write_all(&response).await.unwrap();
                }
            }
            peer.shutdown().await.unwrap();
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        });
        let (_owner, request) = context();
        let result = transport.exchange(&query(), request).await;
        let expected = match mode {
            "oversize" => ExchangeError::ResourceLimit,
            "short" => ExchangeError::Packet(PacketError::Malformed),
            "prefix_eof" | "body_eof" => ExchangeError::Io(io::ErrorKind::UnexpectedEof),
            "mismatch" => ExchangeError::Packet(PacketError::MismatchedResponse),
            "truncated" => ExchangeError::Packet(PacketError::Truncated),
            _ => unreachable!(),
        };
        assert_eq!(result.unwrap_err(), expected, "{mode}");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        assert_eq!(admission.active(), 0);
        task.await.unwrap();
    }
}

#[test]
fn invalid_admission_upstream_or_capability_fails_before_opening() {
    assert!(matches!(
        Admission::new(0),
        Err(ExchangeError::InvalidAdmission)
    ));
    assert!(matches!(
        Admission::new(4097),
        Err(ExchangeError::InvalidAdmission)
    ));
    let (backend, admission, _, peer) = fixture(1);
    for address in [
        "0.0.0.0:53",
        "224.0.0.1:53",
        "255.255.255.255:53",
        "192.0.2.53:0",
    ] {
        assert!(matches!(
            TcpTransport::new(
                backend.clone(),
                address.parse().unwrap(),
                limits(),
                admission.clone()
            ),
            Err(ExchangeError::InvalidUpstream)
        ));
    }
    assert!(matches!(
        TcpTransport::new(
            backend.clone(),
            "[2001:db8::53]:53".parse().unwrap(),
            limits(),
            admission
        ),
        Err(ExchangeError::UnsupportedCapability)
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    drop(peer);
}

#[tokio::test(start_paused = true)]
async fn direct_failures_remain_typed_without_retry_or_backend_selection() {
    let connector = Arc::new(RejectingDirect {
        calls: AtomicUsize::new(0),
    });
    let admission = Admission::new(1).unwrap();
    assert!(matches!(
        DirectTcpTransport::new(
            connector.clone(),
            "0.0.0.0:53".parse().unwrap(),
            limits(),
            admission.clone()
        ),
        Err(ExchangeError::InvalidUpstream)
    ));
    let direct = DirectTcpTransport::new(
        connector.clone(),
        UPSTREAM.parse().unwrap(),
        limits(),
        admission.clone(),
    )
    .unwrap();
    let (_owner, mut request) = context();
    assert!(matches!(
        direct.exchange(&query(), request.clone()).await,
        Err(ExchangeError::Direct(BackendError::UnsupportedIntegration))
    ));
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    request.deadline = Instant::now();
    assert!(matches!(
        direct.exchange(&query(), request).await,
        Err(ExchangeError::Direct(BackendError::Timeout))
    ));
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    assert_eq!(admission.active(), 0);
}

#[tokio::test]
async fn invalid_requests_and_backend_or_write_failures_release_admission() {
    let (backend, admission, transport, peer) = fixture(1);
    let query = query();
    let mut response_wire = wire();
    response_wire[2] = 0x81;
    let response = Packet::response(&response_wire, &query, limits()).unwrap();
    let (_owner, request) = context();
    assert!(matches!(
        transport.exchange(&response, request.clone()).await,
        Err(ExchangeError::InvalidRequest)
    ));
    let small = TcpTransport::new(
        backend.clone(),
        UPSTREAM.parse().unwrap(),
        Limits::new(12, 1).unwrap(),
        admission.clone(),
    )
    .unwrap();
    assert!(matches!(
        small.exchange(&query, request.clone()).await,
        Err(ExchangeError::ResourceLimit)
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    drop(peer);
    assert!(matches!(
        transport.exchange(&query, request.clone()).await,
        Err(ExchangeError::Io(io::ErrorKind::BrokenPipe))
    ));
    assert_eq!(admission.active(), 0);
    assert!(matches!(
        transport.exchange(&query, request).await,
        Err(ExchangeError::Backend(BackendError::ResourceLimit))
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    assert_eq!(admission.active(), 0);
}

#[tokio::test]
async fn peer_close_after_length_prefix_reports_query_write_failure() {
    let (backend, admission, transport, mut peer) = fixture(1);
    let task = tokio::spawn(async move {
        assert_eq!(usize::from(peer.read_u16().await.unwrap()), wire().len());
        drop(peer);
    });
    let (_owner, request) = context();
    assert!(matches!(
        transport.exchange(&query(), request).await,
        Err(ExchangeError::Io(io::ErrorKind::BrokenPipe))
    ));
    task.await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(admission.active(), 0);
}
