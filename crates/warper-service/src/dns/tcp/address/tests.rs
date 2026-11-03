// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{oneshot, watch},
};
use warper_core::{
    dns::Name,
    transport::{Backend, Capabilities, Error as BackendError, OpenTcp, TcpStream},
};

use super::*;
use crate::dns::{Admission, Limits};

struct MockBackend {
    streams: Mutex<VecDeque<DuplexStream>>,
    deadlines: Mutex<Vec<Instant>>,
    admission: Admission,
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
        assert_eq!(
            self.admission.active(),
            1,
            "all dependencies retain the same root slot"
        );
        self.deadlines.lock().unwrap().push(request.deadline);
        let stream = self.streams.lock().unwrap().pop_front();
        Box::pin(async move {
            stream
                .map(|stream| Box::new(stream) as TcpStream)
                .ok_or(BackendError::ResourceLimit)
        })
    }
}

fn wire(owner: &str) -> Vec<u8> {
    let mut bytes = vec![0, 17, 1, 0x10, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(Name::from_ascii(owner).unwrap().wire());
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    bytes
}

fn reply(owner: &str, target: Option<&str>, code: u8) -> Vec<u8> {
    let mut bytes = wire(owner);
    bytes[2] = 0x81;
    bytes[3] = 0x80 | code;
    if code != 0 {
        return bytes;
    }
    bytes[7] = 1;
    bytes.extend_from_slice(&[0xc0, 12]);
    bytes.extend_from_slice(&[0, if target.is_some() { 5 } else { 1 }, 0, 1]);
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    let data = target
        .map(|name| Name::from_ascii(name).unwrap().wire().to_vec())
        .unwrap_or_else(|| vec![192, 0, 2, 1]);
    bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&data);
    bytes
}

fn fixture(count: usize) -> (Arc<MockBackend>, TcpTransport, Vec<DuplexStream>) {
    let admission = Admission::new(1).unwrap();
    let mut peers = Vec::new();
    let mut streams = VecDeque::new();
    for _ in 0..count {
        let (stream, peer) = tokio::io::duplex(256);
        streams.push_back(stream);
        peers.push(peer);
    }
    let backend = Arc::new(MockBackend {
        streams: Mutex::new(streams),
        deadlines: Mutex::new(Vec::new()),
        admission: admission.clone(),
    });
    let transport = TcpTransport::new(
        backend.clone(),
        "192.0.2.53:53".parse().unwrap(),
        limits(),
        admission,
    )
    .unwrap();
    (backend, transport, peers)
}

fn limits() -> Limits {
    Limits::new(512, 16).unwrap()
}
fn query() -> Packet {
    Packet::request(&wire("start.test"), limits()).unwrap()
}
fn bounds() -> AddressDiscoveryLimits {
    AddressDiscoveryLimits {
        alias_hops: 2,
        addresses: 1,
    }
}
fn request() -> (watch::Sender<bool>, Request) {
    let (owner, cancellation) = watch::channel(false);
    (
        owner,
        Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        },
    )
}

async fn read(peer: &mut DuplexStream, owner: &str) {
    let length = peer.read_u16().await.unwrap();
    let mut bytes = vec![0; usize::from(length)];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, wire(owner));
}

async fn respond(mut peer: DuplexStream, owner: &str, response: Vec<u8>) {
    read(&mut peer, owner).await;
    peer.write_u16(response.len() as u16).await.unwrap();
    peer.write_all(&response).await.unwrap();
    assert_eq!(
        peer.read(&mut [0]).await.unwrap(),
        0,
        "each dependency stream must close"
    );
}

#[tokio::test]
async fn selected_dependencies_share_one_slot_budget_deadline_and_backend() {
    let (backend, transport, mut peers) = fixture(2);
    let first_reply = reply("start.test", Some("end.test"), 0);
    let expected = first_reply.clone();
    let second = peers.pop().unwrap();
    let first = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        respond(first, "start.test", first_reply).await;
        respond(second, "end.test", reply("end.test", None, 0)).await;
    });
    let budget = QueryBudget::new(2).unwrap();
    let (_owner, context) = request();
    let deadline = context.deadline;
    let result = transport
        .discover_addresses(&query(), context, &budget, bounds())
        .await
        .unwrap();
    assert_eq!(result.backend, BackendId(7));
    assert_eq!(result.answer.question, query().question());
    assert_eq!(
        result.answer.canonical_name,
        Name::from_ascii("end.test").unwrap()
    );
    assert_eq!(result.answer.addresses.len(), 1);
    assert_eq!(
        result.response.encode().unwrap(),
        Packet::response(&expected, &query(), limits())
            .unwrap()
            .encode()
            .unwrap()
    );
    assert_eq!(budget.used(), 2);
    assert_eq!(*backend.deadlines.lock().unwrap(), [deadline, deadline]);
    assert_eq!(backend.admission.active(), 0);
    peer.await.unwrap();
}

#[tokio::test]
async fn exhausted_parent_budget_stops_before_dependency_dial() {
    let (backend, transport, mut peers) = fixture(1);
    let peer = tokio::spawn(respond(
        peers.pop().unwrap(),
        "start.test",
        reply("start.test", Some("end.test"), 0),
    ));
    let budget = QueryBudget::new(1).unwrap();
    let (_owner, context) = request();
    let result = transport
        .discover_addresses(&query(), context, &budget, bounds())
        .await;
    assert!(matches!(
        result,
        Err(DiscoveryError::Exchange(ExchangeError::ResourceLimit))
    ));
    assert_eq!(backend.deadlines.lock().unwrap().len(), 1);
    assert_eq!(backend.admission.active(), 0);
    assert_eq!(budget.used(), 1);
    peer.await.unwrap();
}

#[tokio::test]
async fn negative_answers_are_final_and_setup_failure_never_changes_backend() {
    for code in [2, 3, 5] {
        let (backend, transport, mut peers) = fixture(1);
        let peer = tokio::spawn(respond(
            peers.pop().unwrap(),
            "start.test",
            reply("start.test", None, code),
        ));
        let budget = QueryBudget::new(4).unwrap();
        let (_owner, context) = request();
        let result = transport
            .discover_addresses(&query(), context, &budget, bounds())
            .await
            .unwrap();
        assert_eq!(result.answer.response_code, u16::from(code));
        assert!(result.answer.addresses.is_empty());
        assert_eq!(budget.used(), 1);
        assert_eq!(backend.admission.active(), 0);
        peer.await.unwrap();
    }
    let (backend, transport, mut peers) = fixture(1);
    let peer = tokio::spawn(respond(
        peers.pop().unwrap(),
        "start.test",
        reply("start.test", Some("end.test"), 0),
    ));
    let (_owner, context) = request();
    let budget = QueryBudget::new(4).unwrap();
    assert!(matches!(
        transport
            .discover_addresses(&query(), context, &budget, bounds())
            .await,
        Err(DiscoveryError::Exchange(ExchangeError::Backend(
            BackendError::ResourceLimit
        )))
    ));
    assert_eq!(budget.used(), 2, "failed setup still consumes its attempt");
    assert_eq!(backend.deadlines.lock().unwrap().len(), 2);
    assert_eq!(backend.admission.active(), 0);
    peer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn delayed_initial_answer_does_not_renew_the_dependency_deadline() {
    let (backend, transport, mut peers) = fixture(2);
    let mut second = peers.pop().unwrap();
    let mut first = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        read(&mut first, "start.test").await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        let bytes = reply("start.test", Some("end.test"), 0);
        first.write_u16(bytes.len() as u16).await.unwrap();
        first.write_all(&bytes).await.unwrap();
        assert_eq!(first.read(&mut [0]).await.unwrap(), 0);
        read(&mut second, "end.test").await;
        assert_eq!(
            second.read(&mut [0]).await.unwrap(),
            0,
            "parent timeout closes the dependency"
        );
    });
    let budget = QueryBudget::new(2).unwrap();
    let (_owner, context) = request();
    let start = Instant::now();
    let deadline = context.deadline;
    assert!(matches!(
        transport
            .discover_addresses(&query(), context, &budget, bounds())
            .await,
        Err(DiscoveryError::Exchange(ExchangeError::Backend(
            BackendError::Timeout
        )))
    ));
    assert_eq!(Instant::now() - start, Duration::from_secs(1));
    assert_eq!(*backend.deadlines.lock().unwrap(), [deadline, deadline]);
    assert_eq!(backend.admission.active(), 0);
    peer.await.unwrap();
}

#[tokio::test]
async fn cancellation_during_dependency_closes_stream_and_releases_admission() {
    let (backend, transport, mut peers) = fixture(2);
    let mut second = peers.pop().unwrap();
    let first = peers.pop().unwrap();
    let (ready, waiting) = oneshot::channel();
    let peer = tokio::spawn(async move {
        respond(
            first,
            "start.test",
            reply("start.test", Some("end.test"), 0),
        )
        .await;
        read(&mut second, "end.test").await;
        ready.send(()).unwrap();
        assert_eq!(second.read(&mut [0]).await.unwrap(), 0);
    });
    let budget = QueryBudget::new(2).unwrap();
    let (owner, context) = request();
    let cancel = async {
        waiting.await.unwrap();
        assert_eq!(backend.admission.active(), 1);
        let (_owner, other) = request();
        assert!(matches!(
            transport
                .discover_addresses(&query(), other, &QueryBudget::new(1).unwrap(), bounds())
                .await,
            Err(DiscoveryError::Exchange(ExchangeError::ResourceLimit))
        ));
        owner.send(true).unwrap();
    };
    let query = query();
    let (result, ()) = tokio::join!(
        transport.discover_addresses(&query, context, &budget, bounds()),
        cancel
    );
    assert!(matches!(
        result,
        Err(DiscoveryError::Exchange(ExchangeError::Backend(
            BackendError::Cancelled
        )))
    ));
    assert_eq!(backend.admission.active(), 0);
    peer.await.unwrap();
}

#[tokio::test]
async fn invalid_input_and_pre_cancelled_requests_do_not_open_a_backend() {
    let (backend, transport, _) = fixture(0);
    let budget = QueryBudget::new(2).unwrap();
    let (_owner, context) = request();
    let mut bytes = wire("start.test");
    let end = bytes.len();
    bytes[end - 3] = 16;
    let invalid_query = Packet::request(&bytes, limits()).unwrap();
    assert!(matches!(
        transport
            .discover_addresses(&invalid_query, context, &budget, bounds())
            .await,
        Err(DiscoveryError::Answer(AddressError::InvalidQuestion))
    ));
    let (owner, context) = request();
    owner.send(true).unwrap();
    assert!(matches!(
        transport
            .discover_addresses(&query(), context, &budget, bounds())
            .await,
        Err(DiscoveryError::Exchange(ExchangeError::Backend(
            BackendError::Cancelled
        )))
    ));
    assert_eq!(budget.used(), 0);
    assert!(backend.deadlines.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_alias_data_discards_the_discovery_and_releases_admission() {
    let (backend, transport, mut peers) = fixture(1);
    let peer = tokio::spawn(respond(
        peers.pop().unwrap(),
        "start.test",
        reply("start.test", Some("start.test"), 0),
    ));
    let budget = QueryBudget::new(2).unwrap();
    let (_owner, context) = request();
    assert!(matches!(
        transport
            .discover_addresses(&query(), context, &budget, bounds())
            .await,
        Err(DiscoveryError::Answer(AddressError::AliasLoop))
    ));
    assert_eq!(budget.used(), 1);
    assert_eq!(backend.admission.active(), 0);
    peer.await.unwrap();
}
