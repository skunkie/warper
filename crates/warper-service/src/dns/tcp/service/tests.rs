// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use std::{sync::Mutex, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use warper_core::{
    dns::Rule,
    transport::{Backend, Capabilities, Error as BackendError, OpenTcp, TcpStream},
};

use super::*;
use crate::dns::{Admission, Limits};

struct MockBackend {
    sender: mpsc::Sender<DuplexStream>,
    admission: Admission,
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
        assert_eq!(self.admission.active(), 1);
        self.deadlines.lock().unwrap().push(request.deadline);
        Box::pin(request.run(async {
            let (stream, peer) = tokio::io::duplex(4096);
            self.sender
                .send(peer)
                .await
                .map_err(|_| BackendError::ResourceLimit)?;
            Ok(Box::new(stream) as TcpStream)
        }))
    }
}

struct Fixture {
    backend: Arc<MockBackend>,
    seen: watch::Receiver<usize>,
    task: JoinHandle<Vec<Question>>,
}
impl Fixture {
    async fn finish(self, transport: TcpTransport) -> Vec<Question> {
        assert_eq!(self.backend.admission.active(), 0);
        drop(transport);
        drop(self.backend);
        self.task.await.unwrap()
    }
}

enum Reply {
    Packet(Vec<u8>, Duration),
    Stall,
}

fn fixture(program: Vec<(&str, u16, Reply)>) -> (Fixture, TcpTransport) {
    let (sender, mut receiver) = mpsc::channel::<DuplexStream>(1);
    let (notice, seen) = watch::channel(0);
    let program = program
        .into_iter()
        .map(|(owner, kind, reply)| (question(owner, kind), reply))
        .collect::<Vec<_>>();
    let task = tokio::spawn(async move {
        let mut queries = Vec::new();
        while let Some(mut peer) = receiver.recv().await {
            let length = peer.read_u16().await.unwrap();
            let mut bytes = vec![0; usize::from(length)];
            peer.read_exact(&mut bytes).await.unwrap();
            let query = Packet::request(&bytes, packet_limits()).unwrap();
            queries.push(query.question());
            notice.send_replace(queries.len());
            let reply = &program
                .iter()
                .find(|(question, _)| *question == query.question())
                .expect("unexpected dependency question")
                .1;
            if let Reply::Packet(reply, delay) = reply {
                tokio::time::sleep(*delay).await;
                let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(reply);
                peer.write_all(&frame).await.unwrap();
            }
            assert_eq!(
                peer.read(&mut [0]).await.unwrap(),
                0,
                "every query stream must close"
            );
        }
        queries
    });
    let admission = Admission::new(1).unwrap();
    let backend = Arc::new(MockBackend {
        sender,
        admission: admission.clone(),
        deadlines: Mutex::new(Vec::new()),
    });
    let transport = TcpTransport::new(
        backend.clone(),
        "192.0.2.53:53".parse().unwrap(),
        packet_limits(),
        admission,
    )
    .unwrap();
    (
        Fixture {
            backend,
            seen,
            task,
        },
        transport,
    )
}

fn name(value: &str) -> Name {
    Name::from_ascii(value).unwrap()
}
fn question(owner: &str, record_type: u16) -> Question {
    Question {
        name: name(owner),
        record_type,
        class: 1,
    }
}
fn packet_limits() -> Limits {
    Limits::new(65535, 128).unwrap()
}
fn bounds(ipv6: bool) -> ServiceDiscoveryLimits {
    ServiceDiscoveryLimits {
        alias_hops: 8,
        addresses: 64,
        ipv6,
        work_items: 4096,
    }
}
fn policy() -> Policy {
    Policy::new(&[Rule::new("example.test", BackendId(7)).unwrap()], 1).unwrap()
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
fn wire(owner: &str, kind: u16, response: bool) -> Vec<u8> {
    let mut bytes = vec![
        0,
        21,
        if response { 0x81 } else { 1 },
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    bytes.extend_from_slice(name(owner).wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    bytes
}
fn query() -> Packet {
    Packet::request(&wire("start.example.test", 65, false), packet_limits()).unwrap()
}
fn record(bytes: &mut Vec<u8>, section: usize, owner: &str, kind: u16, ttl: u32, data: &[u8]) {
    bytes[section + 1] += 1;
    bytes.extend_from_slice(name(owner).wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(data);
}
fn service(bytes: &mut Vec<u8>, owner: &str, priority: u16, target: &str, ttl: u32, hints: &[u8]) {
    let mut data = priority.to_be_bytes().to_vec();
    data.extend_from_slice(name(target).wire());
    if !hints.is_empty() {
        data.extend_from_slice(&[0, 4]);
        data.extend_from_slice(&(hints.len() as u16).to_be_bytes());
        data.extend_from_slice(hints);
    }
    record(bytes, 6, owner, 65, ttl, &data);
}
fn answer(owner: &str, kind: u16, code: u8, ip: &[u8]) -> Reply {
    let mut bytes = wire(owner, kind, true);
    bytes[3] = code;
    if !ip.is_empty() {
        record(&mut bytes, 6, owner, kind, 30, ip);
    }
    Reply::Packet(bytes, Duration::ZERO)
}
fn ready(bytes: Vec<u8>) -> Reply {
    Reply::Packet(bytes, Duration::ZERO)
}
fn has_ip(result: &ServiceResolution, ip: &str) -> bool {
    result
        .endpoints
        .iter()
        .any(|endpoint| endpoint.ip == ip.parse::<IpAddr>().unwrap())
}

#[tokio::test(start_paused = true)]
async fn complete_inline_graph_covers_priorities_hints_related_addresses_and_alias_fallbacks() {
    let mut bytes = wire("start.example.test", 65, true);
    record(
        &mut bytes,
        6,
        "start.example.test",
        5,
        20,
        name("alias.example.test").wire(),
    );
    service(
        &mut bytes,
        "alias.example.test",
        0,
        "service.example.test",
        10,
        &[],
    );
    service(
        &mut bytes,
        "service.example.test",
        1,
        "one.example.test",
        5,
        &[192, 0, 2, 1],
    );
    service(
        &mut bytes,
        "service.example.test",
        99,
        "two.example.test",
        5,
        &[192, 0, 2, 2],
    );
    for (owner, last) in [
        ("one.example.test", 11),
        ("two.example.test", 12),
        ("service.example.test", 13),
    ] {
        record(&mut bytes, 10, owner, 1, 30, &[192, 0, 2, last]);
        let ip: std::net::Ipv6Addr = format!("2001:db8::{last}").parse().unwrap();
        record(&mut bytes, 10, owner, 28, 30, &ip.octets());
    }
    let expected = bytes.clone();
    let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(bytes))]);
    let budget = QueryBudget::new(1).unwrap();
    let (_owner, request) = context();
    let now = Instant::now();
    let result = transport
        .discover_service_bindings(&query(), request, &budget, &policy(), bounds(true))
        .await
        .unwrap();
    for ip in [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.11",
        "192.0.2.12",
        "192.0.2.13",
        "2001:db8::11",
        "2001:db8::12",
        "2001:db8::13",
    ] {
        assert!(has_ip(&result, ip), "endpoint {ip}");
    }
    assert_eq!(result.backend, BackendId(7));
    assert_eq!(
        budget.used(),
        1,
        "complete inline data must not need more upstream attempts"
    );
    assert!(
        result
            .endpoints
            .iter()
            .any(|endpoint| endpoint.source == EndpointSource::Hint)
    );
    for endpoint in &result.endpoints {
        let path = result.paths[endpoint.path];
        assert_eq!(path.alias_hops, 2);
        let ttl = if path.kind == DependencyKind::AliasFallback {
            10
        } else {
            5
        };
        assert_eq!(endpoint.expires_at, now + Duration::from_secs(ttl));
    }
    let parsed = Packet::response(&expected, &query(), packet_limits()).unwrap();
    assert_eq!(result.response.encode().unwrap(), parsed.encode().unwrap());
    assert_eq!(
        fixture.finish(transport).await,
        [question("start.example.test", 65)]
    );
}

#[tokio::test(start_paused = true)]
async fn shared_missing_target_queries_are_coalesced_without_renewing_observation_time() {
    let mut bytes = wire("start.example.test", 65, true);
    service(
        &mut bytes,
        "start.example.test",
        1,
        "target.example.test",
        10,
        &[192, 0, 2, 1],
    );
    service(
        &mut bytes,
        "start.example.test",
        9,
        "target.example.test",
        10,
        &[192, 0, 2, 2],
    );
    let (fixture, transport) = fixture(vec![
        ("start.example.test", 65, ready(bytes)),
        (
            "target.example.test",
            1,
            answer("target.example.test", 1, 0, &[192, 0, 2, 3]),
        ),
    ]);
    let budget = QueryBudget::new(2).unwrap();
    let (_owner, request) = context();
    let deadline = request.deadline;
    let result = transport
        .discover_service_bindings(&query(), request, &budget, &policy(), bounds(false))
        .await
        .unwrap();
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        assert!(has_ip(&result, ip));
    }
    assert_eq!(budget.used(), 2);
    assert_eq!(
        result
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.source == EndpointSource::Resolved)
            .count(),
        2
    );
    assert_eq!(
        *fixture.backend.deadlines.lock().unwrap(),
        [deadline, deadline]
    );
    assert_eq!(fixture.finish(transport).await.len(), 2);
}

#[tokio::test]
async fn alias_fallback_resolves_final_owner_even_when_service_target_has_addresses() {
    let mut bytes = wire("start.example.test", 65, true);
    service(
        &mut bytes,
        "start.example.test",
        0,
        "service.example.test",
        10,
        &[],
    );
    service(
        &mut bytes,
        "service.example.test",
        1,
        "target.example.test",
        5,
        &[],
    );
    record(
        &mut bytes,
        10,
        "target.example.test",
        1,
        30,
        &[192, 0, 2, 1],
    );
    let (fixture, transport) = fixture(vec![
        ("start.example.test", 65, ready(bytes)),
        (
            "service.example.test",
            1,
            answer("service.example.test", 1, 0, &[192, 0, 2, 2]),
        ),
    ]);
    let (_owner, request) = context();
    let result = transport
        .discover_service_bindings(
            &query(),
            request,
            &QueryBudget::new(2).unwrap(),
            &policy(),
            bounds(false),
        )
        .await
        .unwrap();
    assert!(has_ip(&result, "192.0.2.1"));
    assert!(has_ip(&result, "192.0.2.2"));
    assert!(
        result
            .endpoints
            .iter()
            .any(|endpoint| result.paths[endpoint.path].kind == DependencyKind::AliasFallback)
    );
    assert_eq!(fixture.finish(transport).await.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn service_reply_retains_original_observation_and_releases_shared_packet_ownership() {
    let mut bytes = wire("start.example.test", 65, true);
    service(
        &mut bytes,
        "start.example.test",
        1,
        "target.example.test",
        10,
        &[192, 0, 2, 1],
    );
    let Reply::Packet(dependency, _) = answer("target.example.test", 1, 0, &[192, 0, 2, 2]) else {
        unreachable!()
    };
    let (fixture, transport) = fixture(vec![
        ("start.example.test", 65, ready(bytes)),
        (
            "target.example.test",
            1,
            Reply::Packet(dependency, Duration::from_millis(250)),
        ),
    ]);
    let (_owner, request) = context();
    let buffers = crate::dns::memory::Budget::new(64 * 1024 * 1024).unwrap();
    let root = Packet::request_with_budget(
        &wire("start.example.test", 65, false),
        packet_limits(),
        &buffers,
    )
    .unwrap();
    let query_storage = buffers.used();
    let start = Instant::now();
    let mut result = transport
        .discover_service_bindings(
            &root,
            request,
            &QueryBudget::new(2).unwrap(),
            &policy(),
            bounds(false),
        )
        .await
        .unwrap();
    assert_eq!(result.response_received_at, start);
    assert_eq!(Instant::now() - start, Duration::from_millis(250));
    Arc::get_mut(&mut result.response)
        .expect("discovery must release internal observations")
        .age_response(Instant::now() - result.response_received_at)
        .unwrap();
    let mut expected = wire("start.example.test", 65, true);
    service(
        &mut expected,
        "start.example.test",
        1,
        "target.example.test",
        9,
        &[192, 0, 2, 1],
    );
    assert_eq!(
        result.response.encode().unwrap(),
        Packet::response(&expected, &query(), packet_limits())
            .unwrap()
            .encode()
            .unwrap()
    );
    let retained = buffers.used();
    let sample = Packet::response(&expected, &root, packet_limits()).unwrap();
    let response_storage = buffers.used() - retained;
    drop(sample);
    let packet_storage = query_storage + response_storage;
    assert!(retained > packet_storage);
    let shared = result.response.clone();
    let mut endpoints = result.endpoints.into_iter();
    drop(result.paths);
    drop(result.response);
    assert_eq!(buffers.used(), retained);
    assert!(endpoints.next().is_some());
    for _ in &mut endpoints {}
    assert_eq!(
        buffers.used(),
        retained,
        "an exhausted iterator still owns its allocation"
    );
    drop(endpoints);
    assert_eq!(buffers.used(), packet_storage);
    drop(shared);
    assert_eq!(buffers.used(), query_storage);
    drop(root);
    assert_eq!(buffers.used(), 0);
    assert_eq!(fixture.finish(transport).await.len(), 2);
}

#[tokio::test]
async fn all_alias_alternatives_are_covered_and_unavailable_root_never_becomes_a_query() {
    let mut bytes = wire("start.example.test", 65, true);
    service(
        &mut bytes,
        "start.example.test",
        0,
        "one.example.test",
        10,
        &[],
    );
    service(
        &mut bytes,
        "start.example.test",
        0,
        "two.example.test",
        10,
        &[],
    );
    service(&mut bytes, "start.example.test", 0, ".", 10, &[]);
    service(
        &mut bytes,
        "start.example.test",
        1,
        "ignored.foreign.test",
        10,
        &[192, 0, 2, 99],
    );
    for owner in ["one.example.test", "two.example.test"] {
        service(&mut bytes, owner, 1, ".", 10, &[]);
    }
    record(&mut bytes, 10, "one.example.test", 1, 30, &[192, 0, 2, 1]);
    record(&mut bytes, 10, "two.example.test", 1, 30, &[192, 0, 2, 2]);
    let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(bytes))]);
    let (_owner, request) = context();
    let result = transport
        .discover_service_bindings(
            &query(),
            request,
            &QueryBudget::new(1).unwrap(),
            &policy(),
            bounds(false),
        )
        .await
        .unwrap();
    assert!(has_ip(&result, "192.0.2.1") && has_ip(&result, "192.0.2.2"));
    assert!(!has_ip(&result, "192.0.2.99"));
    assert_eq!(fixture.finish(transport).await.len(), 1);
}

#[tokio::test]
async fn every_target_and_related_alias_must_have_the_original_winning_backend() {
    for (target, related) in [
        ("foreign.test", false),
        ("foreign.example.test", false),
        ("safe.example.test", true),
    ] {
        let mut bytes = wire("start.example.test", 65, true);
        service(
            &mut bytes,
            "start.example.test",
            1,
            target,
            10,
            &[192, 0, 2, 1],
        );
        if related {
            record(&mut bytes, 10, target, 5, 10, name("foreign.test").wire());
        }
        let rules = [
            Rule::new("example.test", BackendId(7)).unwrap(),
            Rule::new("foreign.example.test", BackendId(8)).unwrap(),
        ];
        let policy = Policy::new(&rules, 2).unwrap();
        let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(bytes))]);
        let (_owner, request) = context();
        let budget = QueryBudget::new(8).unwrap();
        assert!(matches!(
            transport
                .discover_service_bindings(&query(), request, &budget, &policy, bounds(false))
                .await,
            Err(ServiceDiscoveryError::DomainPolicy)
        ));
        assert_eq!(
            budget.used(),
            1,
            "forbidden dependencies must never be queried"
        );
        assert_eq!(fixture.finish(transport).await.len(), 1);
    }
}

#[tokio::test]
async fn disabled_ipv6_rejects_hints_and_related_addresses_before_positive_release() {
    for hint in [true, false] {
        let mut bytes = wire("start.example.test", 65, true);
        if hint {
            let mut data = vec![0, 1, 0, 0, 6, 0, 16];
            data.extend_from_slice(&[1; 16]);
            record(&mut bytes, 6, "start.example.test", 65, 10, &data);
        } else {
            service(
                &mut bytes,
                "start.example.test",
                1,
                "target.example.test",
                10,
                &[],
            );
            record(&mut bytes, 10, "target.example.test", 28, 10, &[1; 16]);
        }
        let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(bytes))]);
        let (_owner, request) = context();
        let budget = QueryBudget::new(8).unwrap();
        assert!(matches!(
            transport
                .discover_service_bindings(&query(), request, &budget, &policy(), bounds(false))
                .await,
            Err(ServiceDiscoveryError::DisabledFamily)
        ));
        assert_eq!(budget.used(), 1);
        fixture.finish(transport).await;
    }
}

#[tokio::test]
async fn negatives_are_final_only_when_no_exposed_hint_depends_on_them() {
    for (code, hint, expected_error) in [
        (0, false, false),
        (3, false, false),
        (2, false, true),
        (0, true, true),
        (3, true, true),
    ] {
        let mut bytes = wire("start.example.test", 65, true);
        service(
            &mut bytes,
            "start.example.test",
            1,
            "target.example.test",
            10,
            if hint { &[192, 0, 2, 1] } else { &[] },
        );
        let (fixture, transport) = fixture(vec![
            ("start.example.test", 65, ready(bytes)),
            (
                "target.example.test",
                1,
                answer("target.example.test", 1, code, &[]),
            ),
        ]);
        let (_owner, request) = context();
        let result = transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(2).unwrap(),
                &policy(),
                bounds(false),
            )
            .await;
        if expected_error {
            assert!(
                matches!(result, Err(ServiceDiscoveryError::NegativeDependency(value)) if value == u16::from(code))
            );
        } else {
            assert!(result.unwrap().endpoints.is_empty());
        }
        fixture.finish(transport).await;
    }
    for code in [2, 3, 5] {
        let (fixture, transport) = fixture(vec![(
            "start.example.test",
            65,
            answer("start.example.test", 65, code, &[]),
        )]);
        let (_owner, request) = context();
        let result = transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(1).unwrap(),
                &policy(),
                bounds(false),
            )
            .await
            .unwrap();
        assert!(result.endpoints.is_empty());
        assert_eq!(result.response.response_code(), u16::from(code));
        fixture.finish(transport).await;
    }
}

#[tokio::test]
async fn loops_hop_endpoint_and_work_budgets_fail_the_entire_discovery() {
    for case in 0..4 {
        let mut bytes = wire("start.example.test", 65, true);
        let mut limits = bounds(false);
        match case {
            0 => service(
                &mut bytes,
                "start.example.test",
                0,
                "start.example.test",
                10,
                &[],
            ),
            1 => {
                service(
                    &mut bytes,
                    "start.example.test",
                    0,
                    "target.example.test",
                    10,
                    &[],
                );
                limits.alias_hops = 0;
            }
            2 => {
                service(
                    &mut bytes,
                    "start.example.test",
                    1,
                    "target.example.test",
                    10,
                    &[192, 0, 2, 1, 192, 0, 2, 2],
                );
                limits.addresses = 1;
            }
            _ => {
                service(
                    &mut bytes,
                    "start.example.test",
                    1,
                    "target.example.test",
                    10,
                    &[],
                );
                limits.work_items = 3;
            }
        }
        let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(bytes))]);
        let (_owner, request) = context();
        let result = transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(1).unwrap(),
                &policy(),
                limits,
            )
            .await;
        if case == 0 {
            assert!(matches!(result, Err(ServiceDiscoveryError::AliasLoop)));
        } else {
            assert!(matches!(result, Err(ServiceDiscoveryError::ResourceLimit)));
        }
        fixture.finish(transport).await;
    }
    let mut bytes = wire("start.example.test", 65, true);
    service(
        &mut bytes,
        "start.example.test",
        1,
        "target.example.test",
        10,
        &[],
    );
    let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(bytes))]);
    let (_owner, request) = context();
    assert!(matches!(
        transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(1).unwrap(),
                &policy(),
                bounds(false)
            )
            .await,
        Err(ServiceDiscoveryError::Exchange(
            ExchangeError::ResourceLimit
        ))
    ));
    assert_eq!(fixture.finish(transport).await.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn delayed_service_reply_and_stalled_address_lookup_share_the_original_deadline() {
    let mut bytes = wire("start.example.test", 65, true);
    service(
        &mut bytes,
        "start.example.test",
        1,
        "target.example.test",
        10,
        &[],
    );
    let (fixture, transport) = fixture(vec![
        (
            "start.example.test",
            65,
            Reply::Packet(bytes, Duration::from_millis(600)),
        ),
        ("target.example.test", 1, Reply::Stall),
    ]);
    let (_owner, request) = context();
    let deadline = request.deadline;
    let now = Instant::now();
    assert!(matches!(
        transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(2).unwrap(),
                &policy(),
                bounds(false)
            )
            .await,
        Err(ServiceDiscoveryError::Exchange(ExchangeError::Backend(
            BackendError::Timeout
        )))
    ));
    assert_eq!(Instant::now() - now, Duration::from_secs(1));
    assert_eq!(
        *fixture.backend.deadlines.lock().unwrap(),
        [deadline, deadline]
    );
    fixture.finish(transport).await;
}

#[tokio::test]
async fn cancellation_and_future_drop_close_dependency_streams_without_background_work() {
    for cancel in [true, false] {
        let mut bytes = wire("start.example.test", 65, true);
        service(
            &mut bytes,
            "start.example.test",
            1,
            "target.example.test",
            10,
            &[],
        );
        let (mut fixture, transport) = fixture(vec![
            ("start.example.test", 65, ready(bytes)),
            ("target.example.test", 1, Reply::Stall),
        ]);
        let (owner, request) = context();
        let buffers = crate::dns::memory::Budget::new(64 * 1024 * 1024).unwrap();
        let query =
            Packet::request_with_budget(&query().encode().unwrap(), packet_limits(), &buffers)
                .unwrap();
        let query_storage = buffers.used();
        let budget = QueryBudget::new(2).unwrap();
        let policy = policy();
        let mut operation = Box::pin(transport.discover_service_bindings(
            &query,
            request,
            &budget,
            &policy,
            bounds(false),
        ));
        let observed = async {
            while *fixture.seen.borrow_and_update() < 2 {
                fixture.seen.changed().await.unwrap();
            }
        };
        tokio::select! { result = &mut operation => panic!("dependency unexpectedly completed: {result:?}"), () = observed => {} }
        assert_eq!(fixture.backend.admission.active(), 1);
        assert!(buffers.used() > query_storage);
        if cancel {
            owner.send(true).unwrap();
            assert!(matches!(
                operation.as_mut().await,
                Err(ServiceDiscoveryError::Exchange(ExchangeError::Backend(
                    BackendError::Cancelled
                )))
            ));
        }
        drop(operation);
        assert_eq!(buffers.used(), query_storage);
        drop(query);
        assert_eq!(buffers.used(), 0);
        assert_eq!(budget.used(), 2);
        fixture.finish(transport).await;
    }
}

#[tokio::test]
async fn invalid_inputs_and_unconfigured_root_never_open_an_upstream() {
    for case in 0..4 {
        let (fixture, transport) = fixture(Vec::new());
        let (_owner, request) = context();
        let mut limits = bounds(false);
        let policy = if case == 0 {
            Policy::new(&[], 1).unwrap()
        } else {
            policy()
        };
        match case {
            1 => limits.addresses = 0,
            2 => limits.work_items = 0,
            3 => limits.work_items = MAX_WORK_ITEMS + 1,
            _ => {}
        }
        let budget = QueryBudget::new(1).unwrap();
        let result = transport
            .discover_service_bindings(&query(), request, &budget, &policy, limits)
            .await;
        if case == 0 {
            assert!(matches!(result, Err(ServiceDiscoveryError::DomainPolicy)));
        } else {
            assert!(matches!(result, Err(ServiceDiscoveryError::InvalidLimits)));
        }
        assert_eq!(budget.used(), 0);
        assert!(fixture.finish(transport).await.is_empty());
    }
}

#[tokio::test]
async fn fetched_service_data_cannot_hide_original_response_additional_endpoints() {
    let mut original = wire("start.example.test", 65, true);
    service(
        &mut original,
        "start.example.test",
        0,
        "service.example.test",
        10,
        &[],
    );
    record(
        &mut original,
        10,
        "service.example.test",
        1,
        10,
        &[192, 0, 2, 1],
    );
    let mut dependent = wire("service.example.test", 65, true);
    service(
        &mut dependent,
        "service.example.test",
        1,
        "target.example.test",
        10,
        &[],
    );
    record(
        &mut dependent,
        10,
        "target.example.test",
        1,
        10,
        &[192, 0, 2, 2],
    );
    let (fixture, transport) = fixture(vec![
        ("start.example.test", 65, ready(original)),
        ("service.example.test", 65, ready(dependent)),
    ]);
    let (_owner, request) = context();
    let budget = QueryBudget::new(2).unwrap();
    let result = transport
        .discover_service_bindings(&query(), request, &budget, &policy(), bounds(false))
        .await
        .unwrap();
    assert!(
        has_ip(&result, "192.0.2.1"),
        "original Additional fallback data remains exposed to the client"
    );
    assert!(has_ip(&result, "192.0.2.2"));
    assert_eq!(budget.used(), 2);
    fixture.finish(transport).await;
}

#[tokio::test]
async fn generic_svcb_and_prefixed_https_keep_alias_targets_without_reapplying_prefixes() {
    for (kind, owner) in [
        (64_u16, "_8443._custom.example.test"),
        (65, "_8443._https.example.test"),
    ] {
        let mut bytes = wire(owner, kind, true);
        let mut alias = vec![0, 0];
        alias.extend_from_slice(name("alias.example.test").wire());
        record(&mut bytes, 6, owner, kind, 10, &alias);
        record(&mut bytes, 6, "alias.example.test", kind, 10, &[0, 1, 0]);
        record(&mut bytes, 10, "alias.example.test", 1, 30, &[192, 0, 2, 1]);
        let (fixture, transport) = fixture(vec![(owner, kind, ready(bytes))]);
        let query = Packet::request(&wire(owner, kind, false), packet_limits()).unwrap();
        let (_owner, request) = context();
        let result = transport
            .discover_service_bindings(
                &query,
                request,
                &QueryBudget::new(1).unwrap(),
                &policy(),
                bounds(false),
            )
            .await
            .unwrap();
        assert!(has_ip(&result, "192.0.2.1"));
        assert!(
            result
                .paths
                .iter()
                .filter(|path| path.parent.is_some())
                .all(|path| path.question.name == name("alias.example.test"))
        );
        assert_eq!(fixture.finish(transport).await.len(), 1);
    }
}

#[tokio::test]
async fn alias_hops_include_service_and_related_address_cnames() {
    for alias_hops in [1, 2] {
        let mut bytes = wire("start.example.test", 65, true);
        service(
            &mut bytes,
            "start.example.test",
            0,
            "service.example.test",
            10,
            &[],
        );
        service(
            &mut bytes,
            "service.example.test",
            1,
            "address.example.test",
            10,
            &[],
        );
        record(
            &mut bytes,
            10,
            "service.example.test",
            1,
            30,
            &[192, 0, 2, 1],
        );
        record(
            &mut bytes,
            10,
            "address.example.test",
            5,
            30,
            name("canonical.example.test").wire(),
        );
        record(
            &mut bytes,
            10,
            "canonical.example.test",
            1,
            30,
            &[192, 0, 2, 2],
        );
        let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(bytes))]);
        let (_owner, request) = context();
        let limits = ServiceDiscoveryLimits {
            alias_hops,
            ..bounds(false)
        };
        let result = transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(1).unwrap(),
                &policy(),
                limits,
            )
            .await;
        if alias_hops == 1 {
            assert!(matches!(result, Err(ServiceDiscoveryError::ResourceLimit)));
        } else {
            assert!(has_ip(&result.unwrap(), "192.0.2.2"));
        }
        fixture.finish(transport).await;
    }
}

#[tokio::test]
async fn address_lookup_additional_data_can_satisfy_the_sibling_family() {
    let mut original = wire("start.example.test", 65, true);
    service(
        &mut original,
        "start.example.test",
        1,
        "target.example.test",
        10,
        &[],
    );
    let mut addresses = wire("target.example.test", 28, true);
    record(&mut addresses, 6, "target.example.test", 28, 30, &[1; 16]);
    record(
        &mut addresses,
        10,
        "target.example.test",
        1,
        30,
        &[192, 0, 2, 1],
    );
    let (fixture, transport) = fixture(vec![
        ("start.example.test", 65, ready(original)),
        ("target.example.test", 28, ready(addresses)),
    ]);
    let (_owner, request) = context();
    let budget = QueryBudget::new(2).unwrap();
    let result = transport
        .discover_service_bindings(&query(), request, &budget, &policy(), bounds(true))
        .await
        .unwrap();
    assert!(has_ip(&result, "192.0.2.1"));
    assert!(
        result
            .endpoints
            .iter()
            .any(|endpoint| endpoint.ip.is_ipv6())
    );
    assert_eq!(budget.used(), 2);
    fixture.finish(transport).await;
}

#[tokio::test]
async fn metadata_exhaustion_is_independent_of_unique_endpoint_count() {
    let mut original = wire("start.example.test", 65, true);
    for priority in 1..100 {
        service(
            &mut original,
            "start.example.test",
            priority,
            ".",
            10,
            &[192, 0, 2, 1],
        );
    }
    record(
        &mut original,
        10,
        "start.example.test",
        1,
        30,
        &[192, 0, 2, 1],
    );
    let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(original))]);
    let (_owner, request) = context();
    let limits = ServiceDiscoveryLimits {
        addresses: 1,
        work_items: 20,
        ..bounds(false)
    };
    assert!(matches!(
        transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(1).unwrap(),
                &policy(),
                limits
            )
            .await,
        Err(ServiceDiscoveryError::ResourceLimit)
    ));
    fixture.finish(transport).await;
}

#[tokio::test]
async fn converging_alias_paths_share_the_same_service_query() {
    let mut original = wire("start.example.test", 65, true);
    service(
        &mut original,
        "start.example.test",
        0,
        "one.example.test",
        10,
        &[],
    );
    service(
        &mut original,
        "start.example.test",
        0,
        "two.example.test",
        10,
        &[],
    );
    service(
        &mut original,
        "one.example.test",
        0,
        "shared.example.test",
        10,
        &[],
    );
    service(
        &mut original,
        "two.example.test",
        0,
        "shared.example.test",
        10,
        &[],
    );
    record(
        &mut original,
        10,
        "shared.example.test",
        1,
        30,
        &[192, 0, 2, 1],
    );
    let mut dependent = wire("shared.example.test", 65, true);
    service(&mut dependent, "shared.example.test", 1, ".", 10, &[]);
    let (fixture, transport) = fixture(vec![
        ("start.example.test", 65, ready(original)),
        ("shared.example.test", 65, ready(dependent)),
    ]);
    let (_owner, request) = context();
    let budget = QueryBudget::new(2).unwrap();
    let result = transport
        .discover_service_bindings(&query(), request, &budget, &policy(), bounds(false))
        .await
        .unwrap();
    assert!(has_ip(&result, "192.0.2.1"));
    assert_eq!(budget.used(), 2);
    assert_eq!(fixture.finish(transport).await.len(), 2);
}

#[tokio::test]
async fn alias_without_service_records_uses_fallback_but_nxdomain_cannot_expose_original_addresses()
{
    for code in [0, 2, 3] {
        let mut original = wire("start.example.test", 65, true);
        service(
            &mut original,
            "start.example.test",
            0,
            "target.example.test",
            10,
            &[],
        );
        record(
            &mut original,
            10,
            "target.example.test",
            1,
            30,
            &[192, 0, 2, 1],
        );
        let (fixture, transport) = fixture(vec![
            ("start.example.test", 65, ready(original)),
            (
                "target.example.test",
                65,
                answer("target.example.test", 65, code, &[]),
            ),
        ]);
        let (_owner, request) = context();
        let result = transport
            .discover_service_bindings(
                &query(),
                request,
                &QueryBudget::new(2).unwrap(),
                &policy(),
                bounds(false),
            )
            .await;
        if code == 0 {
            assert!(has_ip(&result.unwrap(), "192.0.2.1"));
        } else {
            assert!(
                matches!(result, Err(ServiceDiscoveryError::NegativeDependency(value)) if value == u16::from(code))
            );
        }
        fixture.finish(transport).await;
    }
}

#[tokio::test]
async fn discovery_metadata_shortage_fails_before_any_upstream_attempt() {
    let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
    for kind in [1, 65] {
        let sample = Packet::request_with_budget(
            &wire("start.example.test", kind, false),
            packet_limits(),
            &buffers,
        )
        .unwrap();
        let used = buffers.used();
        let competing = buffers.reserve(buffers.limit() - used).unwrap();
        let (fixture, transport) = fixture(Vec::new());
        let (_owner, request) = context();
        let attempts = QueryBudget::new(2).unwrap();
        if kind == 65 {
            assert!(matches!(
                transport
                    .discover_service_bindings(
                        &sample,
                        request,
                        &attempts,
                        &policy(),
                        bounds(false)
                    )
                    .await,
                Err(ServiceDiscoveryError::ResourceLimit)
            ));
        } else {
            assert!(matches!(
                transport
                    .discover_addresses(
                        &sample,
                        request,
                        &attempts,
                        crate::dns::AddressDiscoveryLimits {
                            alias_hops: 8,
                            addresses: 64
                        }
                    )
                    .await,
                Err(crate::dns::DiscoveryError::Answer(
                    crate::dns::AddressError::ResourceLimit
                ))
            ));
        }
        assert_eq!(attempts.used(), 0);
        assert!(fixture.backend.deadlines.lock().unwrap().is_empty());
        assert_eq!(buffers.used(), buffers.limit());
        assert!(fixture.finish(transport).await.is_empty());
        drop(competing);
        assert_eq!(buffers.used(), used);
        drop(sample);
        assert_eq!(buffers.used(), 0);
    }
}

#[tokio::test]
async fn traversal_storage_exhaustion_releases_saved_responses_and_partial_metadata() {
    let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let sample = Packet::request_with_budget(
        &wire("start.example.test", 65, false),
        packet_limits(),
        &buffers,
    )
    .unwrap();
    let used = buffers.used();
    let mut response = wire("start.example.test", 65, true);
    service(
        &mut response,
        "start.example.test",
        1,
        "target.example.test",
        10,
        &[192, 0, 2, 1],
    );
    let decoded = Packet::response(&response, &sample, packet_limits()).unwrap();
    let response_bytes = buffers.used() - used;
    drop(decoded);
    let fixed = size_of::<Discovery<'_>>()
        + size_of::<ServiceResolution>()
        + size_of::<Reservation>()
        + 2 * size_of::<usize>();
    let allowed =
        fixed + response_bytes + 2 * size_of::<Observed>() + 2 * size_of::<EndpointPath>() - 1;
    let competing = buffers.reserve(buffers.limit() - used - allowed).unwrap();
    let retained = buffers.used();
    let (fixture, transport) = fixture(vec![("start.example.test", 65, ready(response))]);
    let (_owner, request) = context();
    let attempts = QueryBudget::new(2).unwrap();
    assert!(matches!(
        transport
            .discover_service_bindings(&sample, request, &attempts, &policy(), bounds(false))
            .await,
        Err(ServiceDiscoveryError::ResourceLimit)
    ));
    assert_eq!(attempts.used(), 1);
    assert_eq!(fixture.finish(transport).await.len(), 1);
    assert_eq!(buffers.used(), retained);
    drop(competing);
    drop(sample);
    assert_eq!(buffers.used(), 0);
}

#[tokio::test]
async fn address_result_storage_follows_both_moved_vectors_after_packet_release() {
    let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let sample = Packet::request_with_budget(
        &wire("start.example.test", 1, false),
        packet_limits(),
        &buffers,
    )
    .unwrap();
    let query_storage = buffers.used();
    let mut reply = wire("start.example.test", 1, true);
    record(
        &mut reply,
        6,
        "start.example.test",
        5,
        20,
        name("target.example.test").wire(),
    );
    record(&mut reply, 6, "target.example.test", 1, 20, &[192, 0, 2, 7]);
    let decoded = Packet::response(&reply, &sample, packet_limits()).unwrap();
    let response_storage = buffers.used() - query_storage;
    drop(decoded);
    let (fixture, transport) = fixture(vec![("start.example.test", 1, ready(reply))]);
    let (_owner, request) = context();
    let result = transport
        .discover_addresses(
            &sample,
            request,
            &QueryBudget::new(1).unwrap(),
            crate::dns::AddressDiscoveryLimits {
                alias_hops: 8,
                addresses: 64,
            },
        )
        .await
        .unwrap();
    let retained = buffers.used();
    assert!(retained > query_storage + response_storage);
    let mut aliases = result.answer.aliases.into_iter();
    let mut addresses = result.answer.addresses.into_iter();
    drop(result.response);
    assert_eq!(buffers.used(), retained - response_storage);
    assert_eq!(aliases.next(), Some(name("target.example.test")));
    assert_eq!(aliases.next(), None);
    drop(aliases);
    assert_eq!(buffers.used(), retained - response_storage);
    assert_eq!(
        addresses.next().unwrap().ip,
        "192.0.2.7".parse::<IpAddr>().unwrap()
    );
    assert_eq!(addresses.next(), None);
    drop(addresses);
    assert_eq!(buffers.used(), query_storage);
    drop(sample);
    assert_eq!(buffers.used(), 0);
    assert_eq!(fixture.finish(transport).await.len(), 1);
}

#[tokio::test]
async fn address_storage_refusal_releases_partial_alias_and_address_state() {
    for short_alias in [true, false] {
        let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
        let sample = Packet::request_with_budget(
            &wire("start.example.test", 1, false),
            packet_limits(),
            &buffers,
        )
        .unwrap();
        let query_storage = buffers.used();
        let mut reply = wire("start.example.test", 1, true);
        record(
            &mut reply,
            6,
            "start.example.test",
            5,
            20,
            name("target.example.test").wire(),
        );
        record(&mut reply, 6, "target.example.test", 1, 20, &[192, 0, 2, 7]);
        let decoded = Packet::response(&reply, &sample, packet_limits()).unwrap();
        let response_storage = buffers.used() - query_storage;
        drop(decoded);
        let fixed = size_of::<crate::dns::AddressLookup>()
            + size_of::<crate::dns::AddressAnswer>()
            + size_of::<Reservation>()
            + 2 * size_of::<usize>();
        let extra = if short_alias {
            0
        } else {
            2 * size_of::<crate::dns::Address>()
        };
        let allowed = fixed + response_storage + 2 * size_of::<Name>() + extra - 1;
        let competing = buffers
            .reserve(buffers.limit() - query_storage - allowed)
            .unwrap();
        let retained = buffers.used();
        let (fixture, transport) = fixture(vec![("start.example.test", 1, ready(reply))]);
        let (_owner, request) = context();
        let attempts = QueryBudget::new(1).unwrap();
        assert!(matches!(
            transport
                .discover_addresses(
                    &sample,
                    request,
                    &attempts,
                    crate::dns::AddressDiscoveryLimits {
                        alias_hops: 8,
                        addresses: 64
                    }
                )
                .await,
            Err(crate::dns::DiscoveryError::Answer(
                crate::dns::AddressError::ResourceLimit
            ))
        ));
        assert_eq!(attempts.used(), 1);
        assert_eq!(fixture.finish(transport).await.len(), 1);
        assert_eq!(buffers.used(), retained);
        drop(competing);
        drop(sample);
        assert_eq!(buffers.used(), 0);
    }
}
