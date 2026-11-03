// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Actual DNS frames through the production SOCKS5 backend and a controlled peer.

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
use warper_service::dns::{Admission, Limits, Packet, TcpTransport};

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

async fn controlled_exchange() -> (Duration, usize) {
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
        let mut query_wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query_wire.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
        let query = Packet::request(&query_wire, limits).unwrap();
        let expected = query_wire.clone();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
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
        let (response, peer_result) = tokio::join!(transport.exchange(&query, request), peer);
        peer_result.unwrap();
        let response = response.unwrap();
        assert_eq!(response.response_code(), 3);
        assert_eq!(response.question(), query.question());
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(admission.active(), 0);
        (started.elapsed(), query_wire.len() * 2 + 4)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn dns_tcp_uses_the_selected_socks5_peer_and_original_upstream() {
    controlled_exchange().await;
}

#[tokio::test]
#[ignore = "controlled release workload; run explicitly with --nocapture"]
async fn dns_tcp_workload() {
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(100);
    let mut bytes = 0;
    for _ in 0..100 {
        let (latency, transferred) = controlled_exchange().await;
        latencies.push(latency);
        bytes += transferred;
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    println!(
        "requests=100 concurrency=1 dns_frame_bytes={bytes} socks5_setup_bytes=2500 elapsed_ms={:.3} queries_per_second={:.3} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} max_ms={:.3}",
        elapsed.as_secs_f64() * 1000.0,
        100.0 / elapsed.as_secs_f64(),
        latencies[49].as_secs_f64() * 1000.0,
        latencies[94].as_secs_f64() * 1000.0,
        latencies[98].as_secs_f64() * 1000.0,
        latencies[99].as_secs_f64() * 1000.0,
    );
}
