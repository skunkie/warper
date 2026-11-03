// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real selected SOCKS5 streams for complete service-binding dependency I/O.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::Instant,
};
use warper_backends::socks5::Socks5;
use warper_core::{
    BackendId,
    dns::{Name, Policy, Rule},
    transport::{EndpointConnector, Error, OpenTcp, Request, TcpStream as BoxedTcp},
};
use warper_service::dns::QueryBudget;
use warper_service::dns::{
    Admission, EndpointSource, Limits, Packet, ServiceDiscoveryLimits, TcpTransport,
};

struct MockConnector {
    endpoint: SocketAddr,
    calls: AtomicUsize,
}
impl EndpointConnector for MockConnector {
    fn connect_tcp(&self, endpoint: SocketAddr, request: Request) -> OpenTcp<'_> {
        assert_eq!(endpoint, self.endpoint);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(request.run(async move {
            let stream = TcpStream::connect(endpoint)
                .await
                .map_err(|error| Error::Io(error.kind()))?;
            Ok(Box::new(stream) as BoxedTcp)
        }))
    }
}

fn wire(owner: &str, kind: u16) -> Vec<u8> {
    let mut bytes = vec![0, 77, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(Name::from_ascii(owner).unwrap().wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    bytes
}
fn record(bytes: &mut Vec<u8>, section: usize, owner: &str, kind: u16, ttl: u32, data: &[u8]) {
    bytes[section + 1] += 1;
    bytes.extend_from_slice(Name::from_ascii(owner).unwrap().wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(data);
}
fn service(bytes: &mut Vec<u8>, owner: &str, priority: u16, target: &str, hint: Option<[u8; 4]>) {
    let mut data = priority.to_be_bytes().to_vec();
    data.extend_from_slice(Name::from_ascii(target).unwrap().wire());
    if let Some(hint) = hint {
        data.extend_from_slice(&[0, 4, 0, 4]);
        data.extend_from_slice(&hint);
    }
    record(bytes, 6, owner, 65, 5, &data);
}

async fn controlled_service_discovery() -> (Duration, usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let connector = Arc::new(MockConnector {
            endpoint,
            calls: AtomicUsize::new(0),
        });
        let backend =
            Arc::new(Socks5::new(BackendId(8), endpoint, None, 1, connector.clone()).unwrap());
        let admission = Admission::new(1).unwrap();
        let limits = Limits::new(4096, 64).unwrap();
        let transport = TcpTransport::new(
            backend,
            "192.0.2.53:53".parse().unwrap(),
            limits,
            admission.clone(),
        )
        .unwrap();
        let policy = Policy::new(&[Rule::new("example.test", BackendId(8)).unwrap()], 1).unwrap();
        let active = admission.clone();
        let peer = tokio::spawn(async move {
            let mut transferred = 0;
            for (owner, kind) in [
                ("start.example.test", 65),
                ("service.example.test", 65),
                ("target.example.test", 1),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(active.active(), 1);
                let mut hello = [0; 3];
                stream.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut connect = [0; 10];
                stream.read_exact(&mut connect).await.unwrap();
                assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 53, 0, 53]);
                stream
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut bytes = vec![0; usize::from(length)];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(bytes, wire(owner, kind));
                transferred += bytes.len() + 2;
                bytes[2] = 0x81;
                bytes[3] = 0x80;
                match kind {
                    65 if owner == "start.example.test" => {
                        service(&mut bytes, owner, 0, "service.example.test", None);
                        record(
                            &mut bytes,
                            10,
                            "service.example.test",
                            1,
                            30,
                            &[192, 0, 2, 5],
                        );
                    }
                    65 => {
                        service(
                            &mut bytes,
                            owner,
                            1,
                            "target.example.test",
                            Some([192, 0, 2, 1]),
                        );
                        service(
                            &mut bytes,
                            owner,
                            99,
                            "target.example.test",
                            Some([192, 0, 2, 2]),
                        );
                    }
                    _ => {
                        record(
                            &mut bytes,
                            6,
                            owner,
                            5,
                            20,
                            Name::from_ascii("canonical.example.test").unwrap().wire(),
                        );
                        record(
                            &mut bytes,
                            6,
                            "canonical.example.test",
                            1,
                            30,
                            &[192, 0, 2, 3],
                        );
                    }
                }
                let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&bytes);
                transferred += frame.len();
                stream.write_all(&frame).await.unwrap();
                assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            }
            transferred
        });
        let query = Packet::request(&wire("start.example.test", 65), limits).unwrap();
        let (_owner, cancellation) = watch::channel(false);
        let budget = QueryBudget::new(3).unwrap();
        let start = Instant::now();
        let result = transport
            .discover_service_bindings(
                &query,
                Request {
                    deadline: start + Duration::from_secs(2),
                    cancellation,
                },
                &budget,
                &policy,
                ServiceDiscoveryLimits {
                    alias_hops: 8,
                    addresses: 4,
                    ipv6: false,
                    work_items: 4096,
                },
            )
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(result.backend, BackendId(8));
        for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.5"] {
            assert!(
                result
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.ip == ip.parse::<std::net::IpAddr>().unwrap()),
                "endpoint {ip}"
            );
        }
        assert!(
            result
                .endpoints
                .iter()
                .any(|endpoint| endpoint.source == EndpointSource::Hint)
        );
        assert!(
            result
                .endpoints
                .iter()
                .any(|endpoint| endpoint.source == EndpointSource::Resolved)
        );
        assert!(
            result
                .endpoints
                .iter()
                .any(|endpoint| endpoint.source == EndpointSource::Additional)
        );
        assert_eq!(result.response.question(), query.question());
        assert_eq!(budget.used(), 3);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 3);
        assert_eq!(admission.active(), 0);
        assert!(!format!("{result:?}").contains("example.test"));
        (elapsed, peer.await.unwrap())
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn service_alternatives_dependencies_and_fallbacks_use_the_selected_socks5_backend() {
    controlled_service_discovery().await;
}

#[tokio::test]
#[ignore = "controlled local workload; run explicitly in release mode"]
async fn service_discovery_workload() {
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut transferred = 0;
    for _ in 0..100 {
        let (elapsed, bytes) = controlled_service_discovery().await;
        latencies.push(elapsed.as_nanos());
        transferred += bytes;
    }
    latencies.sort_unstable();
    println!(
        "service discovery workload requests=100 attempts=300 dns_framed_bytes={transferred} elapsed_ns={} p50_ns={} p95_ns={} p99_ns={}; controlled loopback SOCKS5 peers, no induced loss, three fresh streams per request",
        start.elapsed().as_nanos(),
        latencies[49],
        latencies[94],
        latencies[98]
    );
}
