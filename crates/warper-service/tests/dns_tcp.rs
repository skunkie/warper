// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Actual DNS frames through explicit selected SOCKS5 and direct TCP paths.

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
    transport::{EndpointConnector, Error, OpenTcp, Request, TcpStream as BoxedTcp},
};
use warper_service::dns::{
    Admission, DirectTcpTransport, Limits, Packet, QueryBudget, TcpTransport,
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

async fn controlled_exchange(direct: bool) -> (Duration, usize) {
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
        let limits = Limits::new(512, 16).unwrap();
        let transport = TcpTransport::new(
            backend,
            "192.0.2.53:53".parse().unwrap(),
            limits,
            admission.clone(),
        )
        .unwrap();
        let direct_transport =
            DirectTcpTransport::new(connector.clone(), endpoint, limits, admission.clone())
                .unwrap();
        let mut query_wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query_wire.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
        let query = Packet::request(&query_wire, limits).unwrap();
        let budget = QueryBudget::new(32).unwrap();
        let expected = query_wire.clone();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if !direct {
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
            }
            let length = stream.read_u16().await.unwrap();
            assert_eq!(usize::from(length), expected.len());
            let mut bytes = vec![0; usize::from(length)];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, expected);
            bytes[2] = 0x81;
            bytes[3] = 0x83;
            let mut response = (bytes.len() as u16).to_be_bytes().to_vec();
            response.extend_from_slice(&bytes);
            for byte in response {
                stream.write_all(&[byte]).await.unwrap();
            }
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        });
        let (_owner, cancellation) = watch::channel(false);
        let request = Request {
            deadline: Instant::now() + Duration::from_secs(3),
            cancellation,
        };
        let started = Instant::now();
        let exchange = async {
            if direct {
                direct_transport.exchange(&query, request, &budget).await
            } else {
                transport.exchange(&query, request, &budget).await
            }
        };
        let (response, peer_result) = tokio::join!(exchange, peer);
        peer_result.unwrap();
        let response = response.unwrap();
        assert_eq!(response.response_code(), 3);
        assert_eq!(response.question(), query.question());
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(admission.active(), 0);
        assert_eq!(budget.used(), 1);
        (started.elapsed(), query_wire.len() * 2 + 4)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn dns_tcp_uses_the_selected_socks5_peer_and_original_upstream() {
    controlled_exchange(false).await;
}

#[tokio::test]
async fn direct_dns_tcp_uses_only_its_explicit_connector() {
    controlled_exchange(true).await;
}

#[tokio::test]
#[ignore = "controlled release workload; run explicitly with --nocapture"]
async fn dns_tcp_workload() {
    workload(false).await;
}

#[tokio::test]
#[ignore = "controlled release workload; run explicitly with --nocapture"]
async fn direct_dns_tcp_workload() {
    workload(true).await;
}

async fn workload(direct: bool) {
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(100);
    let mut bytes = 0;
    for _ in 0..100 {
        let (latency, transferred) = controlled_exchange(direct).await;
        latencies.push(latency);
        bytes += transferred;
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    let setup_bytes = if direct { 0 } else { 2500 };
    println!(
        "direct={direct} requests=100 concurrency=1 dns_frame_bytes={bytes} socks5_setup_bytes={setup_bytes} elapsed_ms={:.3} queries_per_second={:.3} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} max_ms={:.3}",
        elapsed.as_secs_f64() * 1000.0,
        100.0 / elapsed.as_secs_f64(),
        latencies[49].as_secs_f64() * 1000.0,
        latencies[94].as_secs_f64() * 1000.0,
        latencies[98].as_secs_f64() * 1000.0,
        latencies[99].as_secs_f64() * 1000.0,
    );
}

async fn controlled_address_discovery() -> (Duration, usize) {
    use warper_core::dns::Name;
    use warper_service::dns::AddressDiscoveryLimits;

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
        let limits = Limits::new(512, 16).unwrap();
        let transport = TcpTransport::new(
            backend,
            "192.0.2.53:53".parse().unwrap(),
            limits,
            admission.clone(),
        )
        .unwrap();
        let question_wire = |owner: &str| {
            let mut bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            bytes.extend_from_slice(Name::from_ascii(owner).unwrap().wire());
            bytes.extend_from_slice(&[0, 1, 0, 1]);
            bytes
        };
        let original = question_wire("start.test");
        let query = Packet::request(&original, limits).unwrap();
        let active = admission.clone();
        let peer = tokio::spawn(async move {
            let mut transferred = 0;
            for (owner, alias) in [("start.test", true), ("end.test", false)] {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(
                    active.active(),
                    1,
                    "dependencies retain root request admission"
                );
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
                assert_eq!(bytes, question_wire(owner));
                transferred += bytes.len() + 2;
                bytes[2] = 0x81;
                bytes[3] = 0x80;
                bytes[7] = 1;
                bytes.extend_from_slice(&[0xc0, 12, 0, if alias { 5 } else { 1 }, 0, 1]);
                bytes.extend_from_slice(&10_u32.to_be_bytes());
                let data = if alias {
                    Name::from_ascii("end.test").unwrap().wire().to_vec()
                } else {
                    vec![192, 0, 2, 42]
                };
                bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&data);
                let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&bytes);
                transferred += frame.len();
                stream.write_all(&frame).await.unwrap();
                assert_eq!(
                    stream.read(&mut [0]).await.unwrap(),
                    0,
                    "dependency socket closes before the next query"
                );
            }
            transferred
        });
        let (_owner, cancellation) = watch::channel(false);
        let budget = QueryBudget::new(2).unwrap();
        let start = Instant::now();
        let result = transport
            .discover_addresses(
                &query,
                Request {
                    deadline: start + Duration::from_secs(2),
                    cancellation,
                },
                &budget,
                AddressDiscoveryLimits {
                    alias_hops: 1,
                    addresses: 1,
                },
            )
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(result.backend, BackendId(8));
        assert_eq!(
            result.answer.canonical_name,
            Name::from_ascii("end.test").unwrap()
        );
        assert_eq!(result.answer.addresses.len(), 1);
        assert_eq!(
            result.answer.addresses[0].ip,
            "192.0.2.42".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(result.response.question(), query.question());
        assert_eq!(connector.calls.load(Ordering::SeqCst), 2);
        assert_eq!(budget.used(), 2);
        assert_eq!(admission.active(), 0);
        (elapsed, peer.await.unwrap())
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn address_dependencies_use_the_selected_socks5_backend_without_new_root_admission() {
    controlled_address_discovery().await;
}

#[tokio::test]
#[ignore = "controlled local workload; run explicitly in release mode"]
async fn selected_address_discovery_workload() {
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut transferred = 0;
    for _ in 0..100 {
        let (elapsed, bytes) = controlled_address_discovery().await;
        latencies.push(elapsed.as_nanos());
        transferred += bytes;
    }
    latencies.sort_unstable();
    println!(
        "selected address discovery workload requests=100 attempts=200 dns_framed_bytes={transferred} elapsed_ns={} p50_ns={} p95_ns={} p99_ns={}; loopback controlled SOCKS5 peers, two fresh TCP streams per request, no induced loss",
        start.elapsed().as_nanos(),
        latencies[49],
        latencies[94],
        latencies[98]
    );
}
