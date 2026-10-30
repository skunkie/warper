// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded local packet bridge for the isolated Linux TUN fixture.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use initial_contract::transport::{self, Backend};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixDatagram},
    task::JoinSet,
};

use crate::{
    adapter::{self, AcceptedFlow, BackendId},
    packet_peer::MTU,
    runtime::Runtime,
    udp_adapter::{self, Association},
};

const TRANSFER: usize = 65536;
const RESPONSE: &[u8] = b"tun-fixture-response-after-fin";

pub async fn run(local: &str, remote: &str) -> Result<()> {
    let socket = UnixDatagram::bind(local)?;
    socket.connect(remote)?;
    let (runtime, mut channels) = Runtime::new(
        adapter::Limits::default(),
        udp_adapter::Limits::default(),
        crate::udp_probe::select_backend,
        64,
    )?;
    let first_backend = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let second_backend = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let backends = [first_backend.local_addr()?, second_backend.local_addr()?];
    ensure!(
        backends[0] != backends[1],
        "backend fixture listeners collided"
    );
    let mut runner = tokio::spawn(runtime.run());
    let mut handlers = JoinSet::new();
    handlers.spawn(serve_backend(first_backend, 0x61));
    handlers.spawn(serve_backend(second_backend, 0x62));
    let mut runner_finished = false;
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        let mut packet = [0; MTU + 1];
        loop {
            tokio::select! {
                result = &mut runner => {
                    runner_finished = true;
                    result.context("runtime task failed")??;
                    anyhow::bail!("runtime stopped before fixture shutdown");
                }
                received = socket.recv(&mut packet) => {
                    let length = received?;
                    if length == 0 { break; }
                    channels.ingress.try_inject(&packet[..length])?;
                }
                output = channels.packets.recv() => {
                    let output = output.context("runtime output closed")?;
                    ensure!(socket.send(&output).await? == output.len(), "partial packet bridge write");
                }
                accepted = channels.tcp.recv() => {
                    let flow = accepted.context("TCP acceptance closed")?;
                    validate_metadata(flow.metadata.source, flow.metadata.destination, flow.metadata.backend, false)?;
                    let backend = backend_address(flow.metadata.backend, &backends)?;
                    handlers.spawn(handle_tcp(flow, backend));
                }
                accepted = channels.udp.recv() => {
                    let association = accepted.context("UDP acceptance closed")?;
                    let metadata = association.metadata();
                    validate_metadata(metadata.source, metadata.destination, metadata.backend, true)?;
                    handlers.spawn(handle_udp(association));
                }
                result = handlers.join_next(), if !handlers.is_empty() => {
                    result.context("handler set unexpectedly empty")???;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }).await.context("TUN bridge deadline exceeded").and_then(|result| result);

    let _shutdown_delivered = channels.shutdown.send(()).is_ok();
    let mut cleanup = Vec::new();
    if !runner_finished {
        match tokio::time::timeout(Duration::from_secs(1), &mut runner).await {
            Ok(Ok(Ok(_))) => {}
            Ok(result) => cleanup.push(format!("runtime shutdown failed: {result:?}")),
            Err(_) => {
                runner.abort();
                match runner.await {
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => cleanup.push(format!("runtime abort failed: {error}")),
                    Ok(Err(error)) => cleanup.push(format!("runtime failed during abort: {error}")),
                    Ok(Ok(_)) => {}
                }
                cleanup.push("runtime shutdown deadline exceeded".into());
            }
        }
    }
    handlers.abort_all();
    while let Some(result) = handlers.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Err(error) if error.is_cancelled() => {}
            result => cleanup.push(format!("handler cleanup failed: {result:?}")),
        }
    }
    if let Err(error) = outcome {
        return Err(error.context(format!("additional cleanup failures: {cleanup:?}")));
    }
    ensure!(cleanup.is_empty(), "cleanup failures: {cleanup:?}");
    Ok(())
}

fn validate_metadata(
    source: SocketAddr,
    destination: SocketAddr,
    backend: BackendId,
    udp: bool,
) -> Result<()> {
    let expected_source: std::net::IpAddr = if destination.is_ipv6() {
        "fd66:66::2"
    } else {
        "10.66.66.2"
    }
    .parse()?;
    let (suffix, offset, expected_backend) = match destination.port() {
        9000 => (91, 1, BackendId(1)),
        9100 => (92, 2, BackendId(2)),
        _ => anyhow::bail!("unexpected destination port"),
    };
    let expected_destination: std::net::IpAddr = if destination.is_ipv6() {
        format!("fd66:66::{suffix}").parse()?
    } else {
        format!("10.66.66.{suffix}").parse()?
    };
    ensure!(
        source.ip() == expected_source
            && source.port() == if udp { 41000 + offset } else { 40000 + offset }
            && destination.ip() == expected_destination
            && backend == expected_backend,
        "TUN flow metadata or backend changed"
    );
    Ok(())
}

fn backend_address(backend: BackendId, backends: &[SocketAddr; 2]) -> Result<SocketAddr> {
    match backend {
        BackendId(1) => Ok(backends[0]),
        BackendId(2) => Ok(backends[1]),
        _ => anyhow::bail!("unknown controlled backend"),
    }
}

async fn serve_backend(listener: TcpListener, expected: u8) -> Result<()> {
    let (stream, _) = listener.accept().await?;
    transfer_tcp(stream, expected).await
}

async fn handle_tcp(flow: AcceptedFlow, backend: SocketAddr) -> Result<()> {
    let flow = flow.into_contract();
    relay_tcp(
        flow.stream,
        backend,
        flow.metadata.destination,
        flow.metadata.backend,
    )
    .await
}

// Controlled peer used to exercise the backend contract; this is not a
// SOCKS5 implementation and never participates in production configuration.
struct ControlledBackend {
    id: initial_contract::routes::BackendId,
    destination: SocketAddr,
    listener: SocketAddr,
}

impl Backend for ControlledBackend {
    fn id(&self) -> initial_contract::routes::BackendId {
        self.id
    }

    fn capabilities(&self) -> transport::Capabilities {
        transport::Capabilities {
            ipv4: self.destination.is_ipv4(),
            ipv6: self.destination.is_ipv6(),
            tcp: true,
            udp: false,
        }
    }

    fn open_tcp(
        &self,
        destination: SocketAddr,
        request: transport::Request,
    ) -> transport::OpenTcp<'_> {
        Box::pin(request.run(async move {
            if destination != self.destination {
                return Err(transport::Error::UnsupportedCapability);
            }
            let stream = TcpStream::connect(self.listener)
                .await
                .map_err(transport::Error::Io)?;
            Ok(Box::new(stream) as transport::TcpStream)
        }))
    }
}

async fn relay_tcp(
    mut downstream: impl AsyncRead + AsyncWrite + Unpin,
    listener: SocketAddr,
    destination: SocketAddr,
    id: initial_contract::routes::BackendId,
) -> Result<()> {
    let backend = ControlledBackend {
        id,
        destination,
        listener,
    };
    ensure!(
        backend.capabilities().tcp && backend.id().0 != 0,
        "invalid controlled backend"
    );
    let (_cancellation_owner, cancellation) = tokio::sync::watch::channel(false);
    let mut upstream = backend
        .open_tcp(
            destination,
            transport::Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                cancellation,
            },
        )
        .await?;
    let (request, response) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;
    ensure!(
        request == TRANSFER as u64,
        "TCP relay request length changed"
    );
    ensure!(
        response == (TRANSFER + RESPONSE.len()) as u64,
        "TCP relay response length changed"
    );
    Ok(())
}

async fn transfer_tcp(mut stream: impl AsyncRead + AsyncWrite + Unpin, expected: u8) -> Result<()> {
    let mut total = 0;
    let mut buffer = [0; 1024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        total += count;
        ensure!(
            total <= TRANSFER && buffer[..count].iter().all(|byte| *byte == expected),
            "TUN TCP request changed"
        );
        stream.write_all(&buffer[..count]).await?;
    }
    ensure!(total == TRANSFER, "TUN TCP request or half-close changed");
    stream.write_all(RESPONSE).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn handle_udp(mut association: Association) -> Result<()> {
    let max_payload = MTU
        - if association.metadata().destination.is_ipv6() {
            48
        } else {
            28
        };
    for payload in [vec![], vec![0x31], vec![0x72; 257], vec![0x53; max_payload]] {
        let datagram = association.recv().await?;
        ensure!(datagram.payload() == payload, "TUN UDP datagram changed");
        association.try_reply(datagram.payload())?;
    }
    // Retain the association until the fixture has received the final reply.
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::socket::udp;

    struct TestDirectory(std::path::PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn tcp_transfer_echoes_full_payload_and_trailer_after_fin() {
        let (mut client, server) = tokio::io::duplex(TRANSFER * 2);
        let handler = tokio::spawn(transfer_tcp(server, 0x61));
        client.write_all(&vec![0x61; TRANSFER]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        handler.await.unwrap().unwrap();
        assert_eq!(response.len(), TRANSFER + RESPONSE.len());
        assert!(response[..TRANSFER].iter().all(|byte| *byte == 0x61));
        assert_eq!(&response[TRANSFER..], RESPONSE);
    }

    #[tokio::test]
    async fn tcp_transfer_rejects_wrong_payload_premature_fin_and_excess() {
        for payload in [vec![0x62], vec![0x61; 10], vec![0x61; TRANSFER + 1]] {
            let (mut client, server) = tokio::io::duplex(TRANSFER * 2);
            let handler = tokio::spawn(transfer_tcp(server, 0x61));
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(handler.await.unwrap().is_err());
            if payload[0] == 0x61 {
                assert_eq!(response.len(), payload.len().min(TRANSFER));
                assert_eq!(response, payload[..response.len()]);
            } else {
                assert!(response.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn backend_relay_preserves_full_duplex_and_fin() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let peer = serve_backend(listener, 0x61);
        let (mut client, downstream) = tokio::io::duplex(1024);
        let relay = relay_tcp(
            downstream,
            address,
            address,
            initial_contract::routes::BackendId(1),
        );
        let application = async move {
            client.write_all(&vec![0x61; TRANSFER]).await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        };
        let (response, relay_result, peer_result) =
            tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(application, relay, peer)
            })
            .await
            .unwrap();
        let response = response.unwrap();
        relay_result.unwrap();
        peer_result.unwrap();
        assert_eq!(response.len(), TRANSFER + RESPONSE.len());
        assert!(response[..TRANSFER].iter().all(|byte| *byte == 0x61));
        assert_eq!(&response[TRANSFER..], RESPONSE);
    }

    #[tokio::test]
    async fn backend_disconnect_fails_the_relay_and_joins_the_peer() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let peer = async move {
            let (stream, _) = listener.accept().await?;
            drop(stream);
            Ok::<(), std::io::Error>(())
        };
        let (mut client, downstream) = tokio::io::duplex(1024);
        client.write_all(b"synthetic").await.unwrap();
        client.shutdown().await.unwrap();
        let (result, peer_result) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                relay_tcp(
                    downstream,
                    address,
                    address,
                    initial_contract::routes::BackendId(1)
                ),
                peer
            )
        })
        .await
        .unwrap();
        assert!(result.is_err(), "an incomplete backend exchange must fail");
        peer_result.unwrap();
    }

    #[test]
    fn backend_selection_rejects_unknown_identity() {
        let backends = [
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:10002".parse().unwrap(),
        ];
        assert_eq!(
            backend_address(BackendId(1), &backends).unwrap(),
            backends[0]
        );
        assert_eq!(
            backend_address(BackendId(2), &backends).unwrap(),
            backends[1]
        );
        assert!(backend_address(BackendId(3), &backends).is_err());
    }

    #[test]
    fn metadata_requires_the_selected_backend_and_original_tuple() {
        for (source, destination, backend, udp) in [
            ("10.66.66.2:40001", "10.66.66.91:9000", BackendId(1), false),
            (
                "[fd66:66::2]:41002",
                "[fd66:66::92]:9100",
                BackendId(2),
                true,
            ),
        ] {
            let source = source.parse().unwrap();
            let destination = destination.parse().unwrap();
            assert!(validate_metadata(source, destination, backend, udp).is_ok());
            assert!(validate_metadata(source, destination, BackendId(3), udp).is_err());
            assert!(validate_metadata(source, destination, backend, !udp).is_err());
        }
    }

    #[tokio::test]
    async fn local_packet_bridge_round_trips_udp_and_joins_on_shutdown() {
        for ipv6 in [false, true] {
            bridge_udp(ipv6).await;
        }
    }

    async fn bridge_udp(ipv6: bool) {
        let directory = TestDirectory(
            std::env::temp_dir().join(format!("warper-tun-bridge-{}-udp", std::process::id())),
        );
        std::fs::create_dir(&directory.0).unwrap();
        let local = directory.0.join("fixture.sock");
        let remote = directory.0.join("adapter.sock");
        let socket = UnixDatagram::bind(&local).unwrap();
        let local_path = local.to_str().unwrap().to_owned();
        let remote_path = remote.to_str().unwrap().to_owned();
        let mut runner = tokio::spawn(async move { run(&remote_path, &local_path).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !remote.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        socket.connect(&remote).unwrap();
        let source: SocketAddr = if ipv6 {
            "[fd66:66::2]:41001"
        } else {
            "10.66.66.2:41001"
        }
        .parse()
        .unwrap();
        let destination: SocketAddr = if ipv6 {
            "[fd66:66::91]:9000"
        } else {
            "10.66.66.91:9000"
        }
        .parse()
        .unwrap();
        let mut peer = crate::packet_peer::Peer::new(source.ip(), source.port()).unwrap();
        let start = tokio::time::Instant::now();
        for payload in [
            vec![],
            vec![0x31],
            vec![0x72; 257],
            vec![0x53; MTU - if ipv6 { 48 } else { 28 }],
        ] {
            peer.sockets
                .get_mut::<udp::Socket>(peer.udp)
                .send_slice(&payload, destination)
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    peer.poll(i64::try_from(start.elapsed().as_millis()).unwrap());
                    while let Some(packet) = peer.device.outgoing.pop_front() {
                        assert_eq!(socket.send(&packet).await.unwrap(), packet.len());
                    }
                    let udp = peer.sockets.get_mut::<udp::Socket>(peer.udp);
                    if udp.can_recv() {
                        let (actual, metadata) = udp.recv().unwrap();
                        assert_eq!(actual, payload);
                        assert_eq!(metadata.endpoint, destination.into());
                        break;
                    }
                    let mut packet = [0; MTU + 1];
                    if let Ok(result) =
                        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut packet))
                            .await
                    {
                        let length = result.unwrap();
                        peer.device.inject(packet[..length].to_vec()).unwrap();
                    }
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(socket.send(&[]).await.unwrap(), 0);
        tokio::time::timeout(Duration::from_secs(2), &mut runner)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn oversized_bridge_packet_fails_and_joins_runtime() {
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "warper-tun-bridge-{}-oversized",
            std::process::id()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let local = directory.0.join("fixture.sock");
        let remote = directory.0.join("adapter.sock");
        let socket = UnixDatagram::bind(&local).unwrap();
        let local_path = local.to_str().unwrap().to_owned();
        let remote_path = remote.to_str().unwrap().to_owned();
        let runner = tokio::spawn(async move { run(&remote_path, &local_path).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !remote.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        socket.connect(&remote).unwrap();
        assert_eq!(socket.send(&[0; MTU + 1]).await.unwrap(), MTU + 1);
        let error = tokio::time::timeout(Duration::from_secs(2), runner)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<crate::runtime::Error>(),
            Some(&crate::runtime::Error::PacketTooLarge)
        );
    }
}
