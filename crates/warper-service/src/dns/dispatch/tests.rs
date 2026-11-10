// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::dns::{Admission, Limits};
use std::{
    io,
    net::SocketAddr,
    sync::Mutex,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::watch,
    task::JoinHandle,
};
use warper_core::{
    dns::{Name, Rule, lease},
    routing,
    transport::{
        Backend, Capabilities, EndpointConnector, OpenTcp, TcpStream,
        datagram::{DatagramConnector, DatagramIo, OpenDatagram, Received, Socket},
    },
};

type Events = Arc<Mutex<Vec<(u8, Instant)>>>;
struct MockPeer {
    marker: u8,
    backend: BackendId,
    tcp: Mutex<Option<Result<DuplexStream, TransportError>>>,
    udp_error: Option<TransportError>,
    events: Events,
}
impl MockPeer {
    fn endpoint(&self) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, self.marker], 53))
    }
    fn selected(self: &Arc<Self>) -> Arc<TcpTransport> {
        Arc::new(
            TcpTransport::new(
                self.clone(),
                self.endpoint(),
                limits(),
                Admission::new(2).unwrap(),
            )
            .unwrap(),
        )
    }
    fn direct(self: &Arc<Self>) -> Arc<DirectUdpTransport> {
        Arc::new(
            DirectUdpTransport::new(
                self.clone(),
                self.clone(),
                self.endpoint(),
                limits(),
                Admission::new(2).unwrap(),
            )
            .unwrap(),
        )
    }
}
impl Backend for MockPeer {
    fn id(&self) -> BackendId {
        self.backend
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            ipv4: true,
            ipv6: false,
            tcp: true,
            udp: false,
        }
    }
    fn open_tcp(&self, endpoint: SocketAddr, request: Request) -> OpenTcp<'_> {
        assert_eq!(endpoint, self.endpoint());
        self.events
            .lock()
            .unwrap()
            .push((self.marker, request.deadline));
        let result = self.tcp.lock().unwrap().take().unwrap();
        Box::pin(async move { result.map(|stream| Box::new(stream) as TcpStream) })
    }
}
impl EndpointConnector for MockPeer {
    fn connect_tcp(&self, _: SocketAddr, _: Request) -> OpenTcp<'_> {
        Box::pin(async { Err(TransportError::UnsupportedIntegration) })
    }
}
struct EchoNegative(Option<Vec<u8>>);
impl DatagramIo for EchoNegative {
    fn poll_send(&mut self, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<()>> {
        assert!(self.0.is_none());
        self.0 = Some(bytes.to_vec());
        Poll::Ready(Ok(()))
    }
    fn poll_recv(&mut self, _: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<Received>> {
        let mut reply = self.0.take().unwrap();
        reply[2..4].copy_from_slice(&[0x81, 0x83]);
        bytes[..reply.len()].copy_from_slice(&reply);
        Poll::Ready(Ok(Received {
            length: reply.len(),
            truncated: false,
        }))
    }
}
impl DatagramConnector for MockPeer {
    fn connect_udp(&self, endpoint: SocketAddr, request: Request) -> OpenDatagram<'_> {
        assert_eq!(endpoint, self.endpoint());
        self.events
            .lock()
            .unwrap()
            .push((self.marker, request.deadline));
        let error = self.udp_error;
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(Box::new(EchoNegative(None)) as Socket),
            }
        })
    }
}
fn limits() -> Limits {
    Limits::new(512, 8).unwrap()
}
fn discovery() -> ServiceDiscoveryLimits {
    ServiceDiscoveryLimits {
        alias_hops: 4,
        addresses: 4,
        ipv6: false,
        work_items: 16,
    }
}
fn query(name: &str, kind: u16) -> Packet {
    let mut bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(Name::from_ascii(name).unwrap().wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    Packet::request(&bytes, limits()).unwrap()
}
fn request(owner: &watch::Sender<bool>) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(2),
        cancellation: owner.subscribe(),
    }
}
fn routes() -> Arc<Controller> {
    Arc::new(
        Controller::new(
            Arc::new(routing::Policy::new(&[], 4).unwrap()),
            lease::Limits {
                lease_entries: 4,
                route_entries: 4,
                response_entries: 4,
                flow_entries: 4,
                addresses_per_response: 4,
                bytes: 128 * 1024,
            },
            Instant::now(),
        )
        .unwrap(),
    )
}
fn domains() -> Arc<Policy> {
    Arc::new(Policy::new(&[Rule::new("example.test", BackendId(7)).unwrap()], 4).unwrap())
}
fn failed(marker: u8, error: TransportError, events: &Events) -> Arc<MockPeer> {
    Arc::new(MockPeer {
        marker,
        backend: BackendId(7),
        tcp: Mutex::new(Some(Err(error))),
        udp_error: Some(error),
        events: events.clone(),
    })
}
fn negative(marker: u8, code: u8, events: &Events) -> (Arc<MockPeer>, JoinHandle<()>) {
    response_peer(marker, code, None, events)
}
#[cfg(target_os = "linux")]
fn positive(marker: u8, events: &Events) -> (Arc<MockPeer>, JoinHandle<()>) {
    response_peer(marker, 0, Some([203, 0, 113, 7]), events)
}
fn response_peer(
    marker: u8,
    code: u8,
    address: Option<[u8; 4]>,
    events: &Events,
) -> (Arc<MockPeer>, JoinHandle<()>) {
    let (stream, mut server) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        let length = server.read_u16().await.unwrap();
        let mut bytes = vec![0; usize::from(length)];
        server.read_exact(&mut bytes).await.unwrap();
        bytes[2..4].copy_from_slice(&[0x81, 0x80 | code]);
        if let Some(address) = address {
            bytes[7] = 1;
            bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
            bytes.extend_from_slice(&address);
        }
        server.write_u16(bytes.len() as u16).await.unwrap();
        server.write_all(&bytes).await.unwrap();
        assert_eq!(server.read(&mut [0]).await.unwrap(), 0);
    });
    (
        Arc::new(MockPeer {
            marker,
            backend: BackendId(7),
            tcp: Mutex::new(Some(Ok(stream))),
            udp_error: None,
            events: events.clone(),
        }),
        task,
    )
}

#[tokio::test]
async fn selected_transport_retry_stays_on_backend_and_negative_answers_are_final() {
    for code in [0, 3] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first = failed(
            53,
            TransportError::Io(io::ErrorKind::ConnectionRefused),
            &events,
        );
        let (second, server) = negative(54, code, &events);
        let third = failed(55, TransportError::Protocol, &events);
        let direct = failed(56, TransportError::Protocol, &events);
        let dispatcher = Dispatcher::new(
            domains(),
            routes(),
            vec![Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![first.selected(), second.selected(), third.selected()],
            }],
            vec![direct.direct()],
            true,
            discovery(),
        )
        .unwrap();
        let (owner, _) = watch::channel(false);
        let operation = request(&owner);
        let deadline = operation.deadline;
        let budget = QueryBudget::new(4).unwrap();
        let Prepared::Upstream {
            packet,
            reservation,
            ..
        } = dispatcher
            .prepare(&query("selected.example.test", 1), operation, &budget)
            .await
            .unwrap()
        else {
            panic!("expected final upstream response");
        };
        assert_eq!(packet.response_code(), u16::from(code));
        assert!(reservation.is_none());
        server.await.unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            vec![(53, deadline), (54, deadline)]
        );
        assert_eq!(budget.used(), 2);
    }
}

#[tokio::test]
async fn selected_policy_authentication_and_admission_failures_never_try_another_role() {
    for error in [
        TransportError::Authentication,
        TransportError::ResourceLimit,
        TransportError::Protocol,
        TransportError::Cancelled,
        TransportError::Io(io::ErrorKind::OutOfMemory),
        TransportError::Io(io::ErrorKind::PermissionDenied),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first = failed(53, error, &events);
        let second = failed(54, TransportError::Protocol, &events);
        let direct = failed(55, TransportError::Protocol, &events);
        let dispatcher = Dispatcher::new(
            domains(),
            routes(),
            vec![Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![first.selected(), second.selected()],
            }],
            vec![direct.direct()],
            true,
            discovery(),
        )
        .unwrap();
        let (owner, _) = watch::channel(false);
        let operation = request(&owner);
        let deadline = operation.deadline;
        assert!(matches!(
            dispatcher
                .prepare(
                    &query("selected.example.test", 1),
                    operation,
                    &QueryBudget::new(4).unwrap()
                )
                .await,
            Err(Error::Selected(_))
        ));
        assert_eq!(*events.lock().unwrap(), vec![(53, deadline)]);
    }
}

#[tokio::test]
async fn unmatched_global_queries_use_only_ordered_direct_upstreams_without_reservations() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let first = failed(
        53,
        TransportError::Io(io::ErrorKind::ConnectionRefused),
        &events,
    );
    let second = Arc::new(MockPeer {
        marker: 54,
        backend: BackendId(7),
        tcp: Mutex::new(None),
        udp_error: None,
        events: events.clone(),
    });
    let dispatcher = Dispatcher::new(
        domains(),
        routes(),
        Vec::new(),
        vec![first.direct(), second.direct()],
        true,
        discovery(),
    )
    .unwrap();
    let (owner, _) = watch::channel(false);
    let operation = request(&owner);
    let deadline = operation.deadline;
    let budget = QueryBudget::new(4).unwrap();
    let Prepared::Upstream {
        packet,
        reservation,
        ..
    } = dispatcher
        .prepare(&query("unmatched.invalid", 1), operation, &budget)
        .await
        .unwrap()
    else {
        panic!("expected direct reply");
    };
    assert_eq!(packet.response_code(), 3);
    assert!(reservation.is_none());
    assert_eq!(
        *events.lock().unwrap(),
        vec![(53, deadline), (54, deadline)]
    );
    assert_eq!(budget.used(), 2);
}

#[tokio::test]
async fn split_unmatched_and_missing_backend_never_dial_and_disabled_aaaa_is_local() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = failed(53, TransportError::Protocol, &events);
    let dispatcher = Dispatcher::new(
        domains(),
        routes(),
        vec![Selected {
            mode: RoutingMode::Dynamic,
            upstreams: vec![peer.selected()],
        }],
        Vec::new(),
        false,
        discovery(),
    )
    .unwrap();
    let (owner, _) = watch::channel(false);
    assert!(matches!(
        dispatcher
            .prepare(
                &query("unmatched.invalid", 1),
                request(&owner),
                &QueryBudget::new(1).unwrap()
            )
            .await,
        Err(Error::Unmatched)
    ));
    assert!(matches!(
        dispatcher
            .prepare(
                &query("selected.example.test", 28),
                request(&owner),
                &QueryBudget::new(1).unwrap()
            )
            .await,
        Ok(Prepared::Local(_))
    ));
    let dispatcher = Dispatcher::new(
        domains(),
        routes(),
        Vec::new(),
        vec![peer.direct()],
        true,
        discovery(),
    )
    .unwrap();
    assert!(matches!(
        dispatcher
            .prepare(
                &query("selected.example.test", 1),
                request(&owner),
                &QueryBudget::new(1).unwrap()
            )
            .await,
        Err(Error::MissingBackend)
    ));
    assert!(events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn attempts_share_budget_and_closed_or_expired_sessions_never_start_io() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let first = failed(
        53,
        TransportError::Io(io::ErrorKind::ConnectionReset),
        &events,
    );
    let second = failed(54, TransportError::Protocol, &events);
    let controller = routes();
    let dispatcher = Dispatcher::new(
        domains(),
        controller.clone(),
        vec![Selected {
            mode: RoutingMode::Dynamic,
            upstreams: vec![first.selected(), second.selected()],
        }],
        Vec::new(),
        false,
        discovery(),
    )
    .unwrap();
    let (owner, _) = watch::channel(false);
    let budget = QueryBudget::new(1).unwrap();
    assert!(matches!(
        dispatcher
            .prepare(&query("selected.example.test", 1), request(&owner), &budget)
            .await,
        Err(Error::Selected(prepare::Error::Address(
            DiscoveryError::Exchange(ExchangeError::ResourceLimit)
        )))
    ));
    assert_eq!(budget.used(), 1);
    assert_eq!(events.lock().unwrap().len(), 1);
    let expired = Request {
        deadline: Instant::now(),
        cancellation: owner.subscribe(),
    };
    assert!(matches!(
        dispatcher
            .prepare(
                &query("selected.example.test", 1),
                expired,
                &QueryBudget::new(4).unwrap()
            )
            .await,
        Err(Error::Request(TransportError::Timeout))
    ));
    controller.close().unwrap();
    assert!(matches!(
        dispatcher
            .prepare(
                &query("selected.example.test", 1),
                request(&owner),
                &QueryBudget::new(4).unwrap()
            )
            .await,
        Err(Error::Closed)
    ));
    assert_eq!(events.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn invalid_registry_rejects_empty_duplicate_and_mixed_backend_groups() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = failed(53, TransportError::Protocol, &events);
    for groups in [
        vec![Selected {
            mode: RoutingMode::Dynamic,
            upstreams: Vec::new(),
        }],
        vec![
            Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![peer.selected()],
            },
            Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![peer.selected()],
            },
        ],
    ] {
        assert!(matches!(
            Dispatcher::new(domains(), routes(), groups, Vec::new(), false, discovery()),
            Err(Error::InvalidRegistry)
        ));
    }
    let other = Arc::new(MockPeer {
        marker: 54,
        backend: BackendId(8),
        tcp: Mutex::new(None),
        udp_error: None,
        events: events.clone(),
    });
    assert!(matches!(
        Dispatcher::new(
            domains(),
            routes(),
            vec![Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![peer.selected(), other.selected()]
            }],
            Vec::new(),
            false,
            discovery()
        ),
        Err(Error::InvalidRegistry)
    ));
    assert!(matches!(
        Dispatcher::new(
            domains(),
            routes(),
            Vec::new(),
            Vec::new(),
            true,
            discovery()
        ),
        Err(Error::InvalidRegistry)
    ));
    let mut invalid = discovery();
    invalid.addresses = 0;
    assert!(matches!(
        Dispatcher::new(
            domains(),
            routes(),
            Vec::new(),
            vec![peer.direct()],
            true,
            invalid
        ),
        Err(Error::Selected(prepare::Error::InvalidLimits))
    ));
    assert!(events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bad_edns_and_response_packets_are_rejected_locally_without_upstream_io() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = failed(53, TransportError::Protocol, &events);
    let dispatcher = Dispatcher::new(
        domains(),
        routes(),
        vec![Selected {
            mode: RoutingMode::Dynamic,
            upstreams: vec![peer.selected()],
        }],
        Vec::new(),
        false,
        discovery(),
    )
    .unwrap();
    let (owner, _) = watch::channel(false);
    let request_packet = query("selected.example.test", 1);
    let mut bytes = request_packet.encode().unwrap();
    bytes[11] = 1;
    bytes.extend_from_slice(&[0, 0, 41, 4, 208, 0, 1, 0, 0, 0, 0]);
    let sample = Packet::request(&bytes, limits()).unwrap();
    let Prepared::Local(wire) = dispatcher
        .prepare(&sample, request(&owner), &QueryBudget::new(1).unwrap())
        .await
        .unwrap()
    else {
        panic!("expected a local EDNS version reply");
    };
    assert_eq!(
        Packet::response(&wire, &sample, limits())
            .unwrap()
            .response_code(),
        16
    );
    let mut bytes = request_packet.encode().unwrap();
    bytes[2..4].copy_from_slice(&[0x81, 0x83]);
    let sample = Packet::response(&bytes, &request_packet, limits()).unwrap();
    assert!(matches!(
        dispatcher
            .prepare(&sample, request(&owner), &QueryBudget::new(1).unwrap())
            .await,
        Err(Error::Packet(crate::dns::Error::Malformed))
    ));
    assert!(events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn direct_authentication_protocol_and_resource_errors_are_final() {
    for error in [
        TransportError::Authentication,
        TransportError::Protocol,
        TransportError::ResourceLimit,
        TransportError::Cancelled,
        TransportError::Io(io::ErrorKind::OutOfMemory),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first = failed(53, error, &events);
        let second = failed(54, TransportError::Protocol, &events);
        let dispatcher = Dispatcher::new(
            domains(),
            routes(),
            Vec::new(),
            vec![first.direct(), second.direct()],
            true,
            discovery(),
        )
        .unwrap();
        let (owner, _) = watch::channel(false);
        assert!(
            matches!(dispatcher.prepare(&query("unmatched.invalid", 1), request(&owner), &QueryBudget::new(4).unwrap()).await, Err(Error::Direct(ExchangeError::Direct(actual))) if actual == error)
        );
        assert_eq!(events.lock().unwrap().len(), 1);
    }
}

#[cfg(target_os = "linux")]
#[path = "../server/tests.rs"]
mod server_tests;
