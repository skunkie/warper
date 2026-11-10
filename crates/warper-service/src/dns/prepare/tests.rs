// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::dns::{Admission, Limits};
use std::{collections::VecDeque, sync::Mutex, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::watch,
    task::JoinHandle,
};
use warper_core::{
    BackendId,
    dns::{Name, Rule, lease},
    routing,
    transport::{Backend, Capabilities, OpenTcp, TcpStream},
};

struct MockBackend {
    streams: Mutex<VecDeque<DuplexStream>>,
    deadlines: Mutex<Vec<Instant>>,
}
impl Backend for MockBackend {
    fn id(&self) -> BackendId {
        BackendId(7)
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            ipv4: true,
            ipv6: false,
            tcp: true,
            udp: false,
        }
    }
    fn open_tcp(&self, destination: std::net::SocketAddr, request: Request) -> OpenTcp<'_> {
        assert_eq!(destination, "192.0.2.53:53".parse().unwrap());
        self.deadlines.lock().unwrap().push(request.deadline);
        let stream = self.streams.lock().unwrap().pop_front();
        Box::pin(async move {
            stream
                .map(|stream| Box::new(stream) as TcpStream)
                .ok_or(RequestError::ResourceLimit)
        })
    }
}
struct Fixture {
    backend: Arc<MockBackend>,
    transport: TcpTransport,
    domains: Policy,
    routes: Controller,
    tasks: Vec<JoinHandle<()>>,
    owner: watch::Sender<bool>,
    operation: Request,
}
impl Fixture {
    fn new(program: Vec<(u16, Vec<u8>)>, static_routes: &[routing::Entry]) -> Self {
        let mut streams = VecDeque::new();
        let mut tasks = Vec::new();
        for (kind, reply) in program {
            let (stream, mut peer) = tokio::io::duplex(4096);
            streams.push_back(stream);
            tasks.push(tokio::spawn(async move {
                let size = peer.read_u16().await.unwrap();
                let mut bytes = vec![0; usize::from(size)];
                peer.read_exact(&mut bytes).await.unwrap();
                let query = Packet::request(&bytes, packet_limits()).unwrap();
                assert_eq!(query.question().record_type, kind);
                peer.write_u16(reply.len() as u16).await.unwrap();
                peer.write_all(&reply).await.unwrap();
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
            }));
        }
        let backend = Arc::new(MockBackend {
            streams: Mutex::new(streams),
            deadlines: Mutex::new(Vec::new()),
        });
        let transport = TcpTransport::new(
            backend.clone(),
            "192.0.2.53:53".parse().unwrap(),
            packet_limits(),
            Admission::new(1).unwrap(),
        )
        .unwrap();
        let domains = Policy::new(&[Rule::new("example.test", BackendId(7)).unwrap()], 1).unwrap();
        let routes = Controller::new(
            Arc::new(routing::Policy::new(static_routes, 4).unwrap()),
            lease::Limits {
                lease_entries: 4,
                route_entries: 4,
                response_entries: 2,
                flow_entries: 2,
                addresses_per_response: 4,
                bytes: 128 * 1024,
            },
            Instant::now(),
        )
        .unwrap();
        let (owner, cancellation) = watch::channel(false);
        let operation = Request {
            deadline: Instant::now() + Duration::from_secs(2),
            cancellation,
        };
        Self {
            backend,
            transport,
            domains,
            routes,
            tasks,
            owner,
            operation,
        }
    }
    fn resolver(&self, mode: RoutingMode) -> Resolver<'_> {
        Resolver::new(&self.transport, &self.domains, &self.routes, mode, bounds()).unwrap()
    }
    async fn finish(self, attempts: usize) {
        assert_eq!(
            self.backend.deadlines.lock().unwrap().as_slice(),
            vec![self.operation.deadline; attempts]
        );
        assert!(self.backend.streams.lock().unwrap().is_empty());
        for task in self.tasks {
            task.await.unwrap();
        }
        self.routes.close().unwrap();
        self.routes.finish_drain().unwrap();
    }
}
fn bounds() -> ServiceDiscoveryLimits {
    ServiceDiscoveryLimits {
        alias_hops: 4,
        addresses: 4,
        ipv6: false,
        work_items: 16,
    }
}
fn packet_limits() -> Limits {
    Limits::new(4096, 32).unwrap()
}
fn query(kind: u16) -> Packet {
    Packet::request(&wire(kind), packet_limits()).unwrap()
}
fn wire(kind: u16) -> Vec<u8> {
    let mut bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(Name::from_ascii("managed.example.test").unwrap().wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes
}
fn response(kind: u16, records: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = wire(kind);
    bytes[2..4].copy_from_slice(&[0x81, 0x80]);
    bytes[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for (kind, ttl, data) in records {
        bytes.extend_from_slice(&[0xc0, 12]);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
    }
    bytes
}

#[tokio::test(start_paused = true)]
async fn discovered_addresses_reserve_the_whole_set_without_authorizing_output() {
    let fixture = Fixture::new(
        vec![(
            1,
            response(1, &[(1, 0, vec![192, 0, 2, 7]), (1, 5, vec![192, 0, 2, 8])]),
        )],
        &[],
    );
    let budget = QueryBudget::new(1).unwrap();
    let prepared = fixture
        .resolver(RoutingMode::Dynamic)
        .prepare(&query(1), fixture.operation.clone(), &budget)
        .await
        .unwrap();
    let Prepared::Upstream {
        packet,
        received_at,
        udp_payload_limit,
        reservation: Some(reservation),
    } = prepared
    else {
        panic!("expected whole-response reservation")
    };
    assert_eq!(packet.question(), query(1).question());
    assert_eq!(received_at, Instant::now());
    assert_eq!(udp_payload_limit, 512);
    assert_eq!(fixture.routes.response_len(&reservation).unwrap(), 2);
    for index in 0..2 {
        let route = fixture.routes.response_route(&reservation, index).unwrap();
        assert_eq!(
            fixture.routes.route_info(route).unwrap().publication,
            lease::Publication::Preparing
        );
    }
    assert!(matches!(
        fixture.routes.begin_output(reservation),
        Err(routes::Error::Ledger(lease::Error::NotCommitted))
    ));
    assert_eq!(budget.used(), 1);
    fixture.routes.advance().unwrap();
    assert_eq!(fixture.routes.stats().unwrap().responses, 0);
    fixture.finish(1).await;
}

#[tokio::test(start_paused = true)]
async fn service_hints_and_resolved_endpoints_share_one_reservation() {
    let service = vec![0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 7];
    let fixture = Fixture::new(
        vec![
            (65, response(65, &[(65, 5, service)])),
            (1, response(1, &[(1, 2, vec![192, 0, 2, 8])])),
        ],
        &[],
    );
    let budget = QueryBudget::new(2).unwrap();
    let prepared = fixture
        .resolver(RoutingMode::Dynamic)
        .prepare(&query(65), fixture.operation.clone(), &budget)
        .await
        .unwrap();
    let Prepared::Upstream {
        reservation: Some(reservation),
        ..
    } = prepared
    else {
        panic!("expected service endpoint reservation")
    };
    assert_eq!(fixture.routes.response_len(&reservation).unwrap(), 2);
    assert_eq!(budget.used(), 2);
    drop(reservation);
    fixture.routes.advance().unwrap();
    fixture.finish(2).await;
}

#[tokio::test(start_paused = true)]
async fn negative_answers_and_disabled_aaaa_do_not_allocate_routes() {
    let fixture = Fixture::new(vec![(1, response(1, &[]))], &[]);
    let budget = QueryBudget::new(1).unwrap();
    let prepared = fixture
        .resolver(RoutingMode::Dynamic)
        .prepare(&query(1), fixture.operation.clone(), &budget)
        .await
        .unwrap();
    assert!(matches!(
        prepared,
        Prepared::Upstream {
            reservation: None,
            ..
        }
    ));
    drop(prepared);
    let prepared = fixture
        .resolver(RoutingMode::Dynamic)
        .prepare(&query(28), fixture.operation.clone(), &budget)
        .await
        .unwrap();
    let Prepared::Local(wire) = prepared else {
        panic!("expected local AAAA reply")
    };
    assert_eq!(
        Packet::response(&wire, &query(28), packet_limits())
            .unwrap()
            .response_code(),
        0
    );
    assert_eq!(budget.used(), 1);
    assert_eq!(fixture.routes.stats().unwrap().responses, 0);
    fixture.finish(1).await;
}

#[tokio::test(start_paused = true)]
async fn wrong_domain_deadline_and_cancellation_prevent_upstream_work() {
    let fixture = Fixture::new(vec![], &[]);
    let budget = QueryBudget::new(1).unwrap();
    let domains = Policy::new(&[Rule::new("example.test", BackendId(8)).unwrap()], 1).unwrap();
    let resolver = Resolver::new(
        &fixture.transport,
        &domains,
        &fixture.routes,
        RoutingMode::Dynamic,
        bounds(),
    )
    .unwrap();
    assert!(matches!(
        resolver
            .prepare(&query(1), fixture.operation.clone(), &budget)
            .await,
        Err(Error::DomainPolicy)
    ));
    let mut expired = fixture.operation.clone();
    expired.deadline = Instant::now();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&query(1), expired, &budget)
            .await,
        Err(Error::Request(RequestError::Timeout))
    ));
    fixture.owner.send_replace(true);
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&query(1), fixture.operation.clone(), &budget)
            .await,
        Err(Error::Request(RequestError::Cancelled))
    ));
    assert_eq!(budget.used(), 0);
    fixture.finish(0).await;
}

#[tokio::test(start_paused = true)]
async fn selected_backend_failure_and_missing_static_coverage_create_no_reservation() {
    let fixture = Fixture::new(vec![], &[]);
    let budget = QueryBudget::new(1).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&query(1), fixture.operation.clone(), &budget)
            .await,
        Err(Error::Address(_))
    ));
    assert_eq!(budget.used(), 1);
    fixture.finish(1).await;
    let fixture = Fixture::new(vec![(1, response(1, &[(1, 1, vec![192, 0, 2, 7])]))], &[]);
    let budget = QueryBudget::new(1).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Static)
            .prepare(&query(1), fixture.operation.clone(), &budget)
            .await,
        Err(Error::Routes(routes::Error::MissingStaticCoverage))
    ));
    assert_eq!(fixture.routes.stats().unwrap().responses, 0);
    fixture.finish(1).await;
}

#[tokio::test(start_paused = true)]
async fn badvers_unsupported_questions_and_invalid_limits_do_no_upstream_work() {
    let fixture = Fixture::new(vec![], &[]);
    let budget = QueryBudget::new(1).unwrap();
    let mut bytes = wire(28);
    bytes[11] = 1;
    bytes.extend_from_slice(&[0, 0, 41, 4, 208, 0, 1, 0, 0, 0, 0]);
    let query = Packet::request(&bytes, packet_limits()).unwrap();
    let prepared = fixture
        .resolver(RoutingMode::Dynamic)
        .prepare(&query, fixture.operation.clone(), &budget)
        .await
        .unwrap();
    let Prepared::Local(bytes) = prepared else {
        panic!("expected local BADVERS")
    };
    assert_eq!(
        Packet::response(&bytes, &query, packet_limits())
            .unwrap()
            .response_code(),
        16
    );
    let query = Packet::request(&wire(16), packet_limits()).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&query, fixture.operation.clone(), &budget)
            .await,
        Err(Error::UnsupportedQuestion)
    ));
    for limits in [
        ServiceDiscoveryLimits {
            addresses: 0,
            ..bounds()
        },
        ServiceDiscoveryLimits {
            addresses: 65537,
            ..bounds()
        },
        ServiceDiscoveryLimits {
            alias_hops: 65537,
            ..bounds()
        },
        ServiceDiscoveryLimits {
            work_items: 0,
            ..bounds()
        },
        ServiceDiscoveryLimits {
            work_items: 65537,
            ..bounds()
        },
    ] {
        assert!(matches!(
            Resolver::new(
                &fixture.transport,
                &fixture.domains,
                &fixture.routes,
                RoutingMode::Dynamic,
                limits
            ),
            Err(Error::InvalidLimits)
        ));
    }
    assert_eq!(budget.used(), 0);
    fixture.finish(0).await;
}

#[tokio::test(start_paused = true)]
async fn duplicate_service_provenance_uses_the_earliest_expiry_and_one_route() {
    let mut fixture = Fixture::new(
        vec![
            (
                65,
                response(65, &[(65, 5, vec![0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 7])]),
            ),
            (1, response(1, &[(1, 2, vec![192, 0, 2, 7])])),
        ],
        &[],
    );
    fixture.operation.deadline = Instant::now() + Duration::from_secs(30);
    let budget = QueryBudget::new(2).unwrap();
    let prepared = fixture
        .resolver(RoutingMode::Dynamic)
        .prepare(&query(65), fixture.operation.clone(), &budget)
        .await
        .unwrap();
    let Prepared::Upstream {
        reservation: Some(reservation),
        ..
    } = prepared
    else {
        panic!("expected coalesced reservation")
    };
    assert_eq!(fixture.routes.response_len(&reservation).unwrap(), 1);
    // Model the coordinator's confirmed publication; this tests metadata
    // expiry, not a native route acknowledgement.
    let route = fixture.routes.response_route(&reservation, 0).unwrap();
    fixture.routes.confirm_publication(route).unwrap();
    let mut reservation = reservation;
    fixture
        .routes
        .handoff(&mut reservation, Duration::ZERO)
        .unwrap();
    assert_eq!(
        fixture.routes.next_expiry().unwrap(),
        Some(Instant::now() + Duration::from_secs(2))
    );
    drop(reservation);
    fixture.routes.advance().unwrap();
    fixture.finish(2).await;
}

#[tokio::test(start_paused = true)]
async fn a_late_static_conflict_does_not_reserve_an_earlier_endpoint() {
    let fixture = Fixture::new(
        vec![(
            1,
            response(1, &[(1, 5, vec![192, 0, 2, 7]), (1, 5, vec![192, 0, 2, 8])]),
        )],
        &[routing::Entry {
            network: "192.0.2.8".parse().unwrap(),
            prefix_len: 32,
            backend: BackendId(8),
        }],
    );
    let budget = QueryBudget::new(1).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Mixed)
            .prepare(&query(1), fixture.operation.clone(), &budget)
            .await,
        Err(Error::Routes(routes::Error::StaticConflict))
    ));
    let stats = fixture.routes.stats().unwrap();
    assert_eq!(stats.responses, 0);
    assert_eq!(stats.routes, 0);
    fixture.finish(1).await;
}

#[tokio::test(start_paused = true)]
async fn incomplete_service_discovery_never_reserves_its_exposed_hint() {
    let fixture = Fixture::new(
        vec![(
            65,
            response(65, &[(65, 5, vec![0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 7])]),
        )],
        &[],
    );
    let budget = QueryBudget::new(1).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&query(65), fixture.operation.clone(), &budget)
            .await,
        Err(Error::Service(ServiceDiscoveryError::Exchange(
            super::super::ExchangeError::ResourceLimit
        )))
    ));
    assert_eq!(budget.used(), 1);
    let stats = fixture.routes.stats().unwrap();
    assert_eq!(stats.responses, 0);
    assert_eq!(stats.routes, 0);
    fixture.finish(1).await;
}

#[tokio::test(start_paused = true)]
async fn endpoint_family_must_be_supported_by_the_selected_backend() {
    let fixture = Fixture::new(
        vec![(
            28,
            response(
                28,
                &[(
                    28,
                    5,
                    "2001:db8::7"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                )],
            ),
        )],
        &[],
    );
    let resolver = Resolver::new(
        &fixture.transport,
        &fixture.domains,
        &fixture.routes,
        RoutingMode::Dynamic,
        ServiceDiscoveryLimits {
            ipv6: true,
            ..bounds()
        },
    )
    .unwrap();
    let budget = QueryBudget::new(1).unwrap();
    assert!(matches!(
        resolver
            .prepare(&query(28), fixture.operation.clone(), &budget)
            .await,
        Err(Error::UnsupportedFamily)
    ));
    assert_eq!(fixture.routes.stats().unwrap().responses, 0);
    fixture.finish(1).await;
}

#[tokio::test(start_paused = true)]
async fn closed_admission_and_unsupported_synthesis_prevent_upstream_work() {
    let fixture = Fixture::new(vec![], &[]);
    let budget = QueryBudget::new(1).unwrap();
    let mut bytes = wire(1);
    bytes[11] = 1;
    bytes.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 9]);
    let unsupported = Packet::request(&bytes, packet_limits()).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&unsupported, fixture.operation.clone(), &budget)
            .await,
        Err(Error::Packet(super::super::Error::UnsupportedOperation))
    ));
    fixture.routes.close().unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&query(1), fixture.operation.clone(), &budget)
            .await,
        Err(Error::Routes(routes::Error::Ledger(lease::Error::Closed)))
    ));
    assert_eq!(budget.used(), 0);
    fixture.finish(0).await;
}

#[tokio::test(start_paused = true)]
async fn shared_ip_conflict_preserves_the_original_backend_reservation() {
    let fixture = Fixture::new(vec![(1, response(1, &[(1, 5, vec![192, 0, 2, 7])]))], &[]);
    let existing = fixture
        .routes
        .reserve(
            RoutingMode::Dynamic,
            QuestionKey {
                backend: BackendId(8),
                name: Name::from_ascii("other.example.test").unwrap(),
                record_type: 1,
                class: 1,
            },
            &[Contribution {
                address: "192.0.2.7".parse().unwrap(),
                expires_at: Duration::from_secs(5),
            }],
            fixture.operation.deadline,
        )
        .unwrap();
    let budget = QueryBudget::new(1).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&query(1), fixture.operation.clone(), &budget)
            .await,
        Err(Error::Routes(routes::Error::Ledger(lease::Error::Conflict)))
    ));
    assert_eq!(fixture.routes.response_len(&existing).unwrap(), 1);
    assert_eq!(fixture.routes.stats().unwrap().responses, 1);
    drop(existing);
    fixture.routes.advance().unwrap();
    fixture.finish(1).await;
}

#[tokio::test]
async fn contribution_storage_shortage_releases_discovery_without_reserving_routes() {
    let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let sample = Packet::request_with_budget(&wire(1), packet_limits(), &buffers).unwrap();
    let query_storage = buffers.used();
    let reply = response(1, &[(1, 10, vec![192, 0, 2, 7])]);
    let decoded = Packet::response(&reply, &sample, packet_limits()).unwrap();
    let response_storage = buffers.used() - query_storage;
    drop(decoded);
    let lookup = size_of::<crate::dns::AddressLookup>()
        + size_of::<crate::dns::AddressAnswer>()
        + size_of::<super::super::memory::Reservation>()
        + 2 * size_of::<usize>();
    let header = size_of::<Vec<Contribution>>() + size_of::<super::super::memory::Reservation>();
    let allowed = header
        + response_storage
        + lookup
        + 2 * size_of::<crate::dns::Address>()
        + 2 * size_of::<Contribution>()
        - 1;
    let competing = buffers
        .reserve(buffers.limit() - query_storage - allowed)
        .unwrap();
    let retained = buffers.used();
    let fixture = Fixture::new(vec![(1, reply)], &[]);
    let attempts = QueryBudget::new(1).unwrap();
    assert!(matches!(
        fixture
            .resolver(RoutingMode::Dynamic)
            .prepare(&sample, fixture.operation.clone(), &attempts)
            .await,
        Err(Error::ResourceLimit)
    ));
    assert_eq!(attempts.used(), 1);
    assert_eq!(fixture.routes.stats().unwrap().responses, 0);
    assert_eq!(fixture.routes.stats().unwrap().routes, 0);
    assert_eq!(buffers.used(), retained);
    fixture.finish(1).await;
    drop(competing);
    drop(sample);
    assert_eq!(buffers.used(), 0);
}
