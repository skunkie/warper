// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Packet-level candidate checks; these do not establish kernel TUN acceptance.

mod direct;
#[path = "../../packet_peer.rs"]
mod packet_peer;

use std::{cell::Cell, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use futures::{FutureExt, SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use packet_peer::{MTU, Peer};
use smoltcp::socket::{tcp, udp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DEADLINE: Duration = Duration::from_secs(2);
const REQUEST: &[u8] = b"synthetic-request-before-fin";
const RESPONSE: &[u8] = b"synthetic-response-after-fin";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.is_empty() {
        for ipv6 in [false, true] {
            direct::run_probe(ipv6)?;
            println!(
                "PASS direct smoltcp: two destinations, empty UDP, 64 KiB TCP/FIN, IPv6={ipv6}"
            );
            direct::verify_admission_and_cancellation(ipv6)?;
            println!("PASS direct smoltcp: occupied-slot rejection and cancellation, IPv6={ipv6}");
            direct::verify_stalled_reader(ipv6)?;
            println!("PASS direct smoltcp: stalled-reader backpressure, IPv6={ipv6}");
        }
        return Ok(());
    }
    ensure!(arguments == ["--wrapper"], "usage: host-stack [--wrapper]");
    let mut failures = 0;
    for ipv6 in [false, true] {
        for empty in [false, true] {
            let name = format!("udp ipv6={ipv6} empty={empty}");
            match udp_case(ipv6, empty).await {
                Ok(()) => println!("PASS {name}"),
                Err(error) => {
                    eprintln!("FAIL {name}: {error:#}");
                    failures += 1;
                }
            }
        }
        match tcp_case(ipv6, true).await {
            Ok(()) => println!("PASS tcp-half-close ipv6={ipv6}"),
            Err(error) => {
                eprintln!("FAIL tcp-half-close ipv6={ipv6}: {error:#}");
                failures += 1;
            }
        }
    }
    ensure!(
        failures == 0,
        "{failures} candidate checks failed; stack selection remains open"
    );
    Ok(())
}

fn addresses(ipv6: bool) -> (SocketAddr, SocketAddr) {
    if ipv6 {
        (
            "[fd66:66::2]:40000".parse().expect("peer constant"),
            "[fd66:66::10]:9000".parse().expect("destination constant"),
        )
    } else {
        (
            "10.66.66.2:40000".parse().expect("peer constant"),
            "10.66.66.10:9000".parse().expect("destination constant"),
        )
    }
}

async fn udp_case(ipv6: bool, empty: bool) -> Result<()> {
    tokio::time::timeout(DEADLINE, async {
        let (source, destination) = addresses(ipv6);
        let mut peer = Peer::new(source.ip(), source.port())?;
        let (mut stack, _, udp_socket, _) = StackBuilder::default()
            .enable_udp(true)
            .stack_buffer_size(8)
            .udp_buffer_size(8)
            .mtu(MTU)
            .build()?;
        let (mut received, mut replies) = udp_socket.context("UDP socket missing")?.split();
        // Unequal consecutive messages detect concatenation and truncation.
        let payloads = [vec![0x31; if empty { 0 } else { 1 }], vec![0x72; 257]];
        for payload in &payloads {
            peer.sockets
                .get_mut::<udp::Socket>(peer.udp)
                .send_slice(payload, destination)?;
            peer.poll(0);
            while let Some(packet) = peer.device.outgoing.pop_front() {
                stack.send(packet).await?;
            }
            let (actual, actual_source, actual_destination) =
                received.next().await.context("UDP ingress ended")?;
            ensure!(actual == *payload, "UDP ingress datagram boundary changed");
            ensure!(
                actual_source == source && actual_destination == destination,
                "original UDP metadata changed"
            );
            replies.send((actual, destination, source)).await?;
            let packet = stack.next().await.context("UDP egress ended")??;
            peer.device.inject(packet)?;
            peer.poll(1);
            let (actual, metadata) = peer.sockets.get_mut::<udp::Socket>(peer.udp).recv()?;
            ensure!(
                actual == payload && metadata.endpoint == destination.into(),
                "UDP reply or source changed"
            );
        }
        Ok(())
    })
    .await
    .context("UDP round trip exceeded deadline (including empty datagram reply)")?
}

async fn tcp_case(ipv6: bool, await_shutdown: bool) -> Result<()> {
    tokio::time::timeout(DEADLINE, async {
        let (source, destination) = addresses(ipv6);
        let mut peer = Peer::new(source.ip(), source.port())?;
        peer.sockets.get_mut::<tcp::Socket>(peer.tcp).connect(
            peer.interface.context(),
            destination,
            source,
        )?;
        let (stack, runner, _, listener) = StackBuilder::default()
            .enable_tcp(true)
            .stack_buffer_size(8)
            .tcp_buffer_size(8)
            .tcp_recv_buffer_size(8192)
            .tcp_send_buffer_size(8192)
            .mtu(MTU)
            .build()?;
        let (mut packets_in, mut packets_out) = stack.split();
        let mut listener = listener.context("TCP listener missing")?;
        let handler_done = Cell::new(false);
        let handler = async {
            let (mut stream, actual_source, actual_destination) =
                listener.next().await.context("TCP listener ended")?;
            ensure!(
                actual_source == source && actual_destination == destination,
                "original TCP metadata changed"
            );
            // Limit read_to_end independently of the peer and library buffers.
            let mut request = Vec::new();
            (&mut stream).take(1024).read_to_end(&mut request).await?;
            ensure!(request == REQUEST, "request or EOF changed");
            stream.write_all(RESPONSE).await?;
            if await_shutdown {
                stream.shutdown().await?;
            }
            drop(stream);
            handler_done.set(true);
            Ok::<_, anyhow::Error>(())
        };
        let driver = async {
            let start = std::time::Instant::now();
            let mut sent = false;
            let mut response = Vec::new();
            loop {
                peer.poll(i64::try_from(start.elapsed().as_millis())?);
                while let Some(packet) = peer.device.outgoing.pop_front() {
                    packets_in.send(packet).await?;
                }
                while let Some(Some(packet)) = packets_out.next().now_or_never() {
                    peer.device.inject(packet?)?;
                }
                let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
                if !sent && socket.can_send() {
                    ensure!(
                        socket.send_slice(REQUEST)? == REQUEST.len(),
                        "partial request admission"
                    );
                    socket.close();
                    sent = true;
                }
                if socket.can_recv() {
                    socket.recv(|bytes| {
                        response.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })?;
                    ensure!(response.len() <= RESPONSE.len(), "unexpected response size");
                }
                if sent && !socket.may_recv() && handler_done.get() {
                    ensure!(response == RESPONSE, "response after FIN was lost");
                    // Flush the final ACK before the driver finishes.
                    peer.poll(i64::try_from(start.elapsed().as_millis())?);
                    while let Some(packet) = peer.device.outgoing.pop_front() {
                        packets_in.send(packet).await?;
                    }
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        let runner = runner.context("TCP runner missing")?;
        tokio::pin!(runner);
        tokio::select! {
            result = &mut runner => {
                result?;
                anyhow::bail!("TCP runner exited before scenario completion");
            }
            result = async { tokio::try_join!(handler, driver) } => {
                result?;
                // Runner is an owned future: cancellation drops it here. No task is detached.
                Ok(())
            }
        }
    })
    .await
    .context("TCP half-close/shutdown exceeded deadline")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nonempty_udp_preserves_metadata_and_boundaries() {
        for ipv6 in [false, true] {
            udp_case(ipv6, false).await.unwrap();
        }
    }

    #[tokio::test]
    async fn tcp_response_survives_client_fin_and_stream_drop() {
        for ipv6 in [false, true] {
            tcp_case(ipv6, false).await.unwrap();
        }
    }

    #[tokio::test]
    async fn tcp_shutdown_completes_while_peer_packet_driver_remains_alive() {
        for ipv6 in [false, true] {
            tcp_case(ipv6, true).await.unwrap();
        }
    }
}
