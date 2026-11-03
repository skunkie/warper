// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Actual TCP peers exercise original destination, duplex traffic and FIN.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
    transport::{Backend, EndpointConnector, Error, OpenTcp, Request, TcpStream as BoxedTcp},
};

struct MockConnector {
    expected_endpoint: SocketAddr,
    attempts: AtomicUsize,
}
impl EndpointConnector for MockConnector {
    fn connect_tcp(&self, endpoint: SocketAddr, request: Request) -> OpenTcp<'_> {
        assert_eq!(endpoint, self.expected_endpoint);
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Box::pin(request.run(async move {
            let stream = TcpStream::connect(endpoint)
                .await
                .map_err(|e| Error::Io(e.kind()))?;
            Ok(Box::new(stream) as BoxedTcp)
        }))
    }
}
fn loopback(ipv6: bool) -> SocketAddr {
    SocketAddr::new(
        if ipv6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        },
        0,
    )
}

#[tokio::test]
async fn real_socks_peers_preserve_duplex_bytes_and_response_after_fin_in_all_address_families() {
    for inner_ipv6 in [false, true] {
        for outer_ipv6 in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), run_flow(inner_ipv6, outer_ipv6))
                .await
                .unwrap();
        }
    }
}

async fn run_flow(inner_ipv6: bool, outer_ipv6: bool) {
    let target = TcpListener::bind(loopback(inner_ipv6)).await.unwrap();
    let destination = target.local_addr().unwrap();
    let proxy = TcpListener::bind(loopback(outer_ipv6)).await.unwrap();
    let endpoint = proxy.local_addr().unwrap();
    let payload: Vec<_> = (0..65536).map(|n| (n % 251) as u8).collect();
    let expected = payload.clone();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        stream.write_all(&vec![b'g'; 16384]).await.unwrap();
        let mut actual = Vec::new();
        (&mut stream)
            .take(65537)
            .read_to_end(&mut actual)
            .await
            .unwrap();
        assert_eq!(actual, expected);
        stream.write_all(b"after-fin").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut hello = [0; 3];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [5, 1, 0, if inner_ipv6 { 4 } else { 1 }]);
        let address = if inner_ipv6 {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await.unwrap();
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            IpAddr::V4(Ipv4Addr::from(bytes))
        };
        let port = stream.read_u16().await.unwrap();
        let original = SocketAddr::new(address, port);
        assert_eq!(original, destination);
        let mut upstream = TcpStream::connect(original).await.unwrap();
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let counts = tokio::io::copy_bidirectional(&mut stream, &mut upstream)
            .await
            .unwrap();
        assert_eq!(counts, (65536, 16384 + 9));
    });
    let connector = Arc::new(MockConnector {
        expected_endpoint: endpoint,
        attempts: AtomicUsize::new(0),
    });
    let backend = Socks5::new(BackendId(11), endpoint, None, 1, connector.clone()).unwrap();
    let (_owner, cancellation) = watch::channel(false);
    let stream = backend
        .open_tcp(
            destination,
            Request {
                deadline: Instant::now() + Duration::from_secs(2),
                cancellation,
            },
        )
        .await
        .unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let mut greeting = vec![0; 16384];
    let (sent, received) = tokio::join!(write.write_all(&payload), read.read_exact(&mut greeting));
    sent.unwrap();
    received.unwrap();
    assert_eq!(greeting, vec![b'g'; 16384]);
    write.shutdown().await.unwrap();
    let mut after = Vec::new();
    read.read_to_end(&mut after).await.unwrap();
    assert_eq!(after, b"after-fin");
    drop(read);
    drop(write);
    target_task.await.unwrap();
    proxy_task.await.unwrap();
    assert_eq!(connector.attempts.load(Ordering::SeqCst), 1);
}
