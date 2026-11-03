// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::watch,
    time::Instant,
};
use warper_core::transport::{
    Error as TransportError, OpenTcp, TcpStream,
    datagram::{DatagramIo, OpenDatagram, Received, Socket},
};

const UPSTREAM: &str = "192.0.2.53:53";

type SentDatagrams = Arc<Mutex<Vec<Vec<u8>>>>;

struct FakeDatagram {
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
    send_error: Option<io::ErrorKind>,
    recv_error: Option<io::ErrorKind>,
    reply: Option<Vec<u8>>,
    truncated: bool,
    sent: SentDatagrams,
    closed: Arc<AtomicUsize>,
}
impl Drop for FakeDatagram {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}
impl DatagramIo for FakeDatagram {
    fn poll_send(&mut self, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<()>> {
        if let Some(error) = self.send_error.take() {
            return Poll::Ready(Err(error.into()));
        }
        self.sent.lock().unwrap().push(bytes.to_vec());
        Poll::Ready(Ok(()))
    }
    fn poll_recv(
        &mut self,
        context: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<Received>> {
        if let Some(delay) = &mut self.delay {
            if delay.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            self.delay = None;
        }
        if let Some(error) = self.recv_error.take() {
            return Poll::Ready(Err(error.into()));
        }
        let Some(reply) = self.reply.take() else {
            return Poll::Pending;
        };
        let length = reply.len().min(bytes.len());
        bytes[..length].copy_from_slice(&reply[..length]);
        Poll::Ready(Ok(Received {
            length,
            truncated: self.truncated || reply.len() > bytes.len(),
        }))
    }
}

struct MockPath {
    udp: Mutex<Option<FakeDatagram>>,
    tcp: Mutex<Option<DuplexStream>>,
    udp_calls: AtomicUsize,
    tcp_calls: AtomicUsize,
    deadlines: Mutex<Vec<Instant>>,
    closed: Arc<AtomicUsize>,
}
impl DatagramConnector for MockPath {
    fn connect_udp(&self, upstream: SocketAddr, request: Request) -> OpenDatagram<'_> {
        assert_eq!(upstream, UPSTREAM.parse().unwrap());
        self.udp_calls.fetch_add(1, Ordering::SeqCst);
        self.deadlines.lock().unwrap().push(request.deadline);
        let socket = self.udp.lock().unwrap().take();
        Box::pin(async move {
            socket
                .map(|socket| Box::new(socket) as Socket)
                .ok_or(TransportError::ResourceLimit)
        })
    }
}
impl EndpointConnector for MockPath {
    fn connect_tcp(&self, upstream: SocketAddr, request: Request) -> OpenTcp<'_> {
        assert_eq!(upstream, UPSTREAM.parse().unwrap());
        if self.udp_calls.load(Ordering::SeqCst) > 0 {
            assert_eq!(self.closed.load(Ordering::SeqCst), 1);
        }
        self.tcp_calls.fetch_add(1, Ordering::SeqCst);
        self.deadlines.lock().unwrap().push(request.deadline);
        let socket = self.tcp.lock().unwrap().take();
        Box::pin(async move {
            socket
                .map(|socket| Box::new(socket) as TcpStream)
                .ok_or(TransportError::UnsupportedIntegration)
        })
    }
}

fn wire() -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    bytes
}
fn reply(code: u8, tc: bool) -> Vec<u8> {
    let mut bytes = wire();
    bytes[2] = if tc { 0x83 } else { 0x81 };
    bytes[3] = 0x80 | code;
    bytes
}
fn limits() -> Limits {
    Limits::new(512, 16).unwrap()
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
fn fixture(
    reply: Option<Vec<u8>>,
    truncated: bool,
) -> (
    Arc<MockPath>,
    Admission,
    DirectUdpTransport,
    DuplexStream,
    SentDatagrams,
) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let closed = Arc::new(AtomicUsize::new(0));
    let (tcp, peer) = tokio::io::duplex(1);
    let path = Arc::new(MockPath {
        udp: Mutex::new(Some(FakeDatagram {
            delay: None,
            send_error: None,
            recv_error: None,
            reply,
            truncated,
            sent: sent.clone(),
            closed: closed.clone(),
        })),
        tcp: Mutex::new(Some(tcp)),
        udp_calls: AtomicUsize::new(0),
        tcp_calls: AtomicUsize::new(0),
        deadlines: Mutex::new(Vec::new()),
        closed,
    });
    let admission = Admission::new(1).unwrap();
    let transport = DirectUdpTransport::new(
        path.clone(),
        path.clone(),
        UPSTREAM.parse().unwrap(),
        limits(),
        admission.clone(),
    )
    .unwrap();
    (path, admission, transport, peer, sent)
}

#[tokio::test(start_paused = true)]
async fn tcp_retry_does_not_renew_the_original_deadline() {
    let (path, admission, transport, mut peer, _) = fixture(Some(reply(0, true)), false);
    path.udp.lock().unwrap().as_mut().unwrap().delay =
        Some(Box::pin(tokio::time::sleep(Duration::from_millis(600))));
    let (_owner, request) = context();
    let deadline = request.deadline;
    let query = Packet::request(&wire(), limits()).unwrap();
    let budget = QueryBudget::new(2).unwrap();
    assert!(matches!(
        transport.exchange(&query, request, &budget).await,
        Err(ExchangeError::Direct(TransportError::Timeout))
    ));
    assert_eq!(Instant::now(), deadline);
    assert!(
        path.deadlines
            .lock()
            .unwrap()
            .iter()
            .all(|value| *value == deadline)
    );
    assert_eq!(budget.used(), 2);
    assert_eq!(admission.active(), 0);
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        (&mut peer).take(33).read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(path.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn udp_io_errors_never_trigger_tcp_retry() {
    for sending in [false, true] {
        let (path, admission, transport, peer, sent) = fixture(Some(reply(0, true)), false);
        drop(peer);
        {
            let mut slot = path.udp.lock().unwrap();
            let socket = slot.as_mut().unwrap();
            if sending {
                socket.send_error = Some(io::ErrorKind::NetworkUnreachable);
            } else {
                socket.recv_error = Some(io::ErrorKind::NetworkUnreachable);
            }
        }
        let (_owner, request) = context();
        let query = Packet::request(&wire(), limits()).unwrap();
        let budget = QueryBudget::new(2).unwrap();
        assert!(matches!(
            transport.exchange(&query, request, &budget).await,
            Err(ExchangeError::Io(io::ErrorKind::NetworkUnreachable))
        ));
        assert_eq!(sent.lock().unwrap().len(), usize::from(!sending));
        assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.used(), 1);
        assert_eq!(admission.active(), 0);
    }
}

#[tokio::test]
async fn a_query_larger_than_udp_uses_tcp_without_opening_a_datagram_socket() {
    let (path, admission, _, old_peer, _) = fixture(None, false);
    drop(old_peer);
    let (tcp, mut peer) = tokio::io::duplex(131072);
    *path.tcp.lock().unwrap() = Some(tcp);
    let mut large = wire();
    large[11] = 1;
    let padding = 65510 - large.len() - 15;
    large.extend_from_slice(&[0, 0, 41, 0xff, 0xff, 0, 0, 0, 0]);
    large.extend_from_slice(&((padding + 4) as u16).to_be_bytes());
    large.extend_from_slice(&12_u16.to_be_bytes());
    large.extend_from_slice(&(padding as u16).to_be_bytes());
    large.resize(65510, 0);
    let limits = Limits::new(65535, 16).unwrap();
    let query = Packet::request(&large, limits).unwrap();
    let expected = query.encode().unwrap();
    assert!(expected.len() > MAX_UDP_BYTES);
    let task = tokio::spawn(async move {
        let length = usize::from(peer.read_u16().await.unwrap());
        assert_eq!(length, expected.len());
        let mut received = vec![0; length];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        let response = reply(3, false);
        peer.write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(&response).await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    });
    let transport = DirectUdpTransport::new(
        path.clone(),
        path.clone(),
        UPSTREAM.parse().unwrap(),
        limits,
        admission.clone(),
    )
    .unwrap();
    let (_owner, request) = context();
    let budget = QueryBudget::new(1).unwrap();
    assert_eq!(
        transport
            .exchange(&query, request, &budget)
            .await
            .unwrap()
            .response_code(),
        3
    );
    task.await.unwrap();
    assert_eq!(path.udp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(budget.used(), 1);
    assert_eq!(admission.active(), 0);
}

#[tokio::test]
async fn correlated_truncation_retries_tcp_under_the_same_permit_deadline_and_budget() {
    let (path, admission, transport, mut peer, sent) = fixture(Some(reply(0, true)), false);
    let task = tokio::spawn(async move {
        assert_eq!(usize::from(peer.read_u16().await.unwrap()), wire().len());
        let mut query = vec![0; wire().len()];
        peer.read_exact(&mut query).await.unwrap();
        assert_eq!(query, wire());
        let response = reply(3, false);
        peer.write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        for byte in response {
            peer.write_all(&[byte]).await.unwrap();
        }
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    });
    let (_owner, request) = context();
    let deadline = request.deadline;
    let budget = QueryBudget::new(2).unwrap();
    let query = Packet::request(&wire(), limits()).unwrap();
    assert_eq!(
        transport
            .exchange(&query, request, &budget)
            .await
            .unwrap()
            .response_code(),
        3
    );
    task.await.unwrap();
    assert_eq!(budget.used(), 2);
    assert_eq!(admission.active(), 0);
    assert_eq!(path.udp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(*path.deadlines.lock().unwrap(), vec![deadline, deadline]);
    assert_eq!(*sent.lock().unwrap(), vec![wire()]);
}

#[tokio::test]
async fn valid_negatives_do_not_trigger_tcp() {
    for code in [0, 2, 3, 5] {
        let (path, admission, transport, peer, _) = fixture(Some(reply(code, false)), false);
        drop(peer);
        let (_owner, request) = context();
        let budget = QueryBudget::new(1).unwrap();
        let query = Packet::request(&wire(), limits()).unwrap();
        assert_eq!(
            transport
                .exchange(&query, request, &budget)
                .await
                .unwrap()
                .response_code(),
            u16::from(code)
        );
        assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.used(), 1);
        assert_eq!(admission.active(), 0);
        assert_eq!(path.closed.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn mismatches_malformed_and_socket_truncation_never_retry_tcp() {
    for mode in ["mismatch", "malformed", "socket_truncation", "oversize"] {
        let mut response = reply(0, true);
        match mode {
            "mismatch" => response[0] = 0,
            "malformed" => response.truncate(14),
            "oversize" => response.resize(513, 0),
            _ => (),
        }
        let (path, admission, transport, peer, _) =
            fixture(Some(response), mode == "socket_truncation");
        drop(peer);
        let (_owner, request) = context();
        let budget = QueryBudget::new(2).unwrap();
        let query = Packet::request(&wire(), limits()).unwrap();
        let error = transport
            .exchange(&query, request, &budget)
            .await
            .unwrap_err();
        let expected = match mode {
            "mismatch" => ExchangeError::Packet(PacketError::MismatchedResponse),
            "malformed" => ExchangeError::Packet(PacketError::Malformed),
            _ => ExchangeError::ResourceLimit,
        };
        assert_eq!(error, expected, "{mode}");
        assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.used(), 1);
        assert_eq!(admission.active(), 0);
    }
}

#[tokio::test]
async fn exhausted_query_budget_refuses_tcp_before_dial() {
    let (path, admission, transport, peer, _) = fixture(Some(reply(0, true)), false);
    drop(peer);
    let (_owner, request) = context();
    let budget = QueryBudget::new(1).unwrap();
    let query = Packet::request(&wire(), limits()).unwrap();
    assert!(matches!(
        transport.exchange(&query, request, &budget).await,
        Err(ExchangeError::ResourceLimit)
    ));
    assert_eq!(path.udp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.used(), 1);
    assert_eq!(admission.active(), 0);
    assert_eq!(path.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn timeout_and_cancellation_close_udp_and_do_not_create_attempts_after_expiry() {
    for mode in ["timeout", "cancelled", "expired", "ownerless"] {
        let (path, admission, transport, peer, _) = fixture(None, false);
        drop(peer);
        let (owner, mut request) = context();
        match mode {
            "cancelled" => owner.send(true).unwrap(),
            "expired" => request.deadline = Instant::now(),
            "ownerless" => drop(owner),
            _ => (),
        }
        let budget = QueryBudget::new(2).unwrap();
        let query = Packet::request(&wire(), limits()).unwrap();
        let error = transport
            .exchange(&query, request, &budget)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ExchangeError::Direct(TransportError::Timeout | TransportError::Cancelled)
        ));
        assert_eq!(budget.used(), usize::from(mode == "timeout"));
        assert_eq!(admission.active(), 0);
        assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            path.udp_calls.load(Ordering::SeqCst),
            usize::from(mode == "timeout")
        );
    }
}

#[tokio::test]
async fn a_foreign_request_permit_cannot_authorize_tcp() {
    let (path, _, transport, peer, _) = fixture(None, false);
    drop(peer);
    let other = Admission::new(1).unwrap();
    let permit = other.reserve().unwrap();
    let (_owner, request) = context();
    let budget = QueryBudget::new(2).unwrap();
    let query = Packet::request(&wire(), limits()).unwrap();
    assert!(matches!(
        transport
            .tcp
            .exchange_admitted(&query, request, &budget, &permit)
            .await,
        Err(ExchangeError::InvalidAdmission)
    ));
    assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.used(), 0);
    let permit = transport.admission.reserve().unwrap();
    let response = Packet::response(&reply(3, false), &query, limits()).unwrap();
    let (_owner, mut request) = context();
    assert!(matches!(
        transport
            .tcp
            .exchange_admitted(&response, request.clone(), &budget, &permit)
            .await,
        Err(ExchangeError::InvalidRequest)
    ));
    request.deadline = Instant::now();
    let result = transport
        .tcp
        .exchange_admitted(&query, request, &budget, &permit)
        .await;
    assert_eq!(
        result.unwrap_err(),
        ExchangeError::Direct(TransportError::Timeout)
    );
    assert_eq!(transport.admission.active(), 1);
    assert_eq!(budget.used(), 0);
    drop(permit);
    assert_eq!(transport.admission.active(), 0);
}

#[tokio::test]
async fn validation_and_admission_refusals_never_charge_or_open_an_upstream() {
    let (path, admission, transport, peer, _) = fixture(Some(reply(3, false)), false);
    drop(peer);
    assert!(matches!(
        DirectUdpTransport::new(
            path.clone(),
            path.clone(),
            "0.0.0.0:53".parse().unwrap(),
            limits(),
            admission.clone()
        ),
        Err(ExchangeError::InvalidUpstream)
    ));
    let query = Packet::request(&wire(), limits()).unwrap();
    let budget = QueryBudget::new(1).unwrap();
    let response = Packet::response(&reply(3, false), &query, limits()).unwrap();
    let (_owner, request) = context();
    assert!(matches!(
        transport
            .exchange(&response, request.clone(), &budget)
            .await,
        Err(ExchangeError::InvalidRequest)
    ));
    let permit = admission.reserve().unwrap();
    assert!(matches!(
        transport.exchange(&query, request.clone(), &budget).await,
        Err(ExchangeError::ResourceLimit)
    ));
    drop(permit);
    let small = DirectUdpTransport::new(
        path.clone(),
        path.clone(),
        UPSTREAM.parse().unwrap(),
        Limits::new(12, 1).unwrap(),
        admission.clone(),
    )
    .unwrap();
    assert!(matches!(
        small.exchange(&query, request.clone(), &budget).await,
        Err(ExchangeError::ResourceLimit)
    ));
    assert_eq!(budget.used(), 0);
    assert_eq!(path.udp_calls.load(Ordering::SeqCst), 0);
    transport
        .exchange(&query, request.clone(), &budget)
        .await
        .unwrap();
    assert!(matches!(
        transport.exchange(&query, request, &budget).await,
        Err(ExchangeError::ResourceLimit)
    ));
    assert_eq!(budget.used(), 1);
    assert_eq!(path.udp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(admission.active(), 0);
}

#[tokio::test]
async fn failed_udp_setup_consumes_one_attempt_and_never_uses_tcp() {
    let (path, admission, transport, peer, sent) = fixture(None, false);
    drop(peer);
    drop(path.udp.lock().unwrap().take());
    let query = Packet::request(&wire(), limits()).unwrap();
    let budget = QueryBudget::new(2).unwrap();
    let (_owner, request) = context();
    assert!(matches!(
        transport.exchange(&query, request, &budget).await,
        Err(ExchangeError::Direct(TransportError::ResourceLimit))
    ));
    assert_eq!(budget.used(), 1);
    assert_eq!(path.udp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(path.tcp_calls.load(Ordering::SeqCst), 0);
    assert!(sent.lock().unwrap().is_empty());
    assert_eq!(admission.active(), 0);
}
