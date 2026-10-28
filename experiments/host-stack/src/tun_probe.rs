// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded local packet bridge for the isolated Linux TUN fixture.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixDatagram,
    task::JoinSet,
};

use crate::{
    adapter::{self, AcceptedFlow, BackendId},
    packet_peer::MTU,
    runtime::Runtime,
    udp_adapter::{self, Association},
};

const REQUEST: &[u8] = b"tun-fixture-request";
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
    let mut runner = tokio::spawn(runtime.run());
    let mut handlers = JoinSet::new();
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
                    handlers.spawn(handle_tcp(flow));
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

async fn handle_tcp(mut flow: AcceptedFlow) -> Result<()> {
    let mut request = Vec::new();
    (&mut flow.stream)
        .take(1024)
        .read_to_end(&mut request)
        .await?;
    ensure!(request == REQUEST, "TUN TCP request or half-close changed");
    flow.stream.write_all(RESPONSE).await?;
    flow.stream.shutdown().await?;
    Ok(())
}

async fn handle_udp(mut association: Association) -> Result<()> {
    for payload in [vec![], vec![0x31], vec![0x72; 257]] {
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
        let source: SocketAddr = "10.66.66.2:41001".parse().unwrap();
        let destination: SocketAddr = "10.66.66.91:9000".parse().unwrap();
        let mut peer = crate::packet_peer::Peer::new(source.ip(), source.port()).unwrap();
        let start = tokio::time::Instant::now();
        for payload in [vec![], vec![0x31], vec![0x72; 257]] {
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
