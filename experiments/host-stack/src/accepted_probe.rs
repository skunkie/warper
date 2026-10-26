// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled peers exercising the experimental accepted-stream boundary.

use std::{
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    task::Poll,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use smoltcp::{
    socket::tcp,
    wire::{Ipv4Packet, Ipv6Packet},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Receiver,
    task::JoinSet,
};

use crate::{
    adapter::{AcceptedFlow, BackendId, FlowMetadata, HostAdapter, Limits},
    packet_peer::Peer,
};

const TRANSFER_BYTES: usize = 65536;
const STEP_LIMIT: u64 = 4000;
const TRAILERS: [&[u8]; 2] = [b"accepted-backend-zero", b"accepted-backend-one"];

pub async fn run_probe(ipv6: bool, same_destination: bool) -> Result<()> {
    let (mut host, mut accepted) = HostAdapter::new(Limits::default(), select_backend)?;
    let destinations = destinations(ipv6, same_destination)?;
    let mut peers = [peer(ipv6, 2)?, peer(ipv6, 3)?];
    for (index, peer) in peers.iter_mut().enumerate() {
        peer.sockets.get_mut::<tcp::Socket>(peer.tcp).connect(
            peer.interface.context(),
            destinations[index],
            source(ipv6, 2 + index as u8)?,
        )?;
    }
    let mut tasks = JoinSet::new();
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        drive(
            &mut host,
            &mut accepted,
            &mut peers,
            destinations,
            &mut tasks,
        ),
    )
    .await
    .context("accepted-stream probe exceeded real-time deadline")
    .and_then(|result| result);
    host.cancel();
    tasks.abort_all();
    let mut cleanup_errors = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(_)) => {}
            Err(error) if error.is_cancelled() => {}
            other => cleanup_errors.push(format!("{other:?}")),
        }
    }
    match outcome {
        Err(primary) => Err(primary.context(format!(
            "additional worker failures during cleanup: {cleanup_errors:?}"
        ))),
        Ok(()) => {
            ensure!(cleanup_errors.is_empty(), "handler cleanup failed");
            Ok(())
        }
    }
}

async fn drive(
    host: &mut HostAdapter,
    accepted: &mut Receiver<AcceptedFlow>,
    peers: &mut [Peer; 2],
    destinations: [SocketAddr; 2],
    tasks: &mut JoinSet<Result<FlowMetadata>>,
) -> Result<()> {
    let mut sent = [0; 2];
    let mut received = [0; 2];
    let mut finished_handlers = 0;
    let mut metadata = [None; 2];
    for step in 0..STEP_LIMIT {
        exchange(host, peers, Duration::from_millis(step)).await?;
        while let Ok(flow) = accepted.try_recv() {
            let index = peers
                .iter()
                .position(|peer| {
                    peer.interface.ip_addrs()[0].address() == flow.metadata.source.ip().into()
                })
                .context("accepted source had no controlled peer")?;
            ensure!(
                flow.metadata.source.port() == 40000,
                "accepted source port changed"
            );
            ensure!(metadata[index].is_none(), "duplicate accepted stream");
            ensure!(
                flow.metadata.destination == destinations[index],
                "original destination changed"
            );
            ensure!(
                Some(flow.metadata.backend) == select_backend(destinations[index]),
                "backend selection changed"
            );
            metadata[index] = Some(flow.metadata);
            tasks.spawn(echo(flow, index));
        }
        while let Some(result) = tasks.try_join_next() {
            let completed = result.context("accepted handler panicked")??;
            ensure!(
                metadata.contains(&Some(completed)),
                "handler identity changed"
            );
            finished_handlers += 1;
        }
        let mut done = finished_handlers == 2;
        for (index, peer) in peers.iter_mut().enumerate() {
            let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
            if sent[index] < TRANSFER_BYTES && socket.can_send() {
                let bytes = [0x61 + index as u8; 1024];
                sent[index] +=
                    socket.send_slice(&bytes[..(TRANSFER_BYTES - sent[index]).min(bytes.len())])?;
                if sent[index] == TRANSFER_BYTES {
                    socket.close();
                }
            }
            if socket.can_recv() {
                let backend = usize::from(
                    select_backend(destinations[index])
                        .context("missing backend")?
                        .0,
                );
                let correct = socket.recv(|bytes| {
                    let correct = bytes.iter().enumerate().all(|(offset, byte)| {
                        let position = received[index] + offset;
                        if position < TRANSFER_BYTES {
                            *byte == 0x61 + index as u8
                        } else {
                            TRAILERS[backend].get(position - TRANSFER_BYTES) == Some(byte)
                        }
                    });
                    received[index] += bytes.len();
                    (bytes.len(), correct)
                })?;
                ensure!(correct, "asynchronous stream changed TCP bytes or backend");
            }
            let backend = usize::from(
                select_backend(destinations[index])
                    .context("missing backend")?
                    .0,
            );
            done &= sent[index] == TRANSFER_BYTES
                && received[index] == TRANSFER_BYTES + TRAILERS[backend].len()
                && !socket.may_recv();
        }
        if done && host.active_flows() == 0 {
            ensure!(
                metadata[0].context("first flow missing")?.id
                    != metadata[1].context("second flow missing")?.id,
                "flow identifiers were reused"
            );
            ensure!(
                host.statistics().admitted == 2
                    && host.statistics().accepted == 2
                    && host.statistics().finished == 2,
                "flow lifecycle did not finish cleanly"
            );
            ensure!(
                host.statistics().timed_out == 0 && host.statistics().reset == 0,
                "normal forwarding failed"
            );
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    anyhow::bail!("asynchronous flow exchange exceeded controlled deadline")
}

async fn echo(mut flow: AcceptedFlow, index: usize) -> Result<FlowMetadata> {
    let mut total = 0;
    let mut bytes = [0; 1024];
    loop {
        let count = flow.stream.read(&mut bytes).await?;
        if count == 0 {
            break;
        }
        total += count;
        ensure!(total <= TRANSFER_BYTES, "request exceeded probe budget");
        ensure!(
            bytes[..count]
                .iter()
                .all(|byte| *byte == 0x61 + index as u8),
            "accepted source metadata changed"
        );
        flow.stream.write_all(&bytes[..count]).await?;
    }
    ensure!(
        total == TRANSFER_BYTES,
        "request ended before all bytes arrived"
    );
    flow.stream
        .write_all(TRAILERS[usize::from(flow.metadata.backend.0)])
        .await?;
    flow.stream.flush().await?;
    flow.stream.shutdown().await?;
    Ok(flow.metadata)
}

pub fn select_backend(destination: SocketAddr) -> Option<BackendId> {
    let selected = match destination.ip() {
        IpAddr::V4(address) => address.octets()[..3] == [10, 66, 66] && address.octets()[3] < 254,
        IpAddr::V6(address) => address.segments()[..4] == [0xfd66, 0x66, 0, 0],
    };
    selected.then_some(BackendId((destination.port() % 2) as u8))
}

pub fn source(ipv6: bool, suffix: u8) -> Result<SocketAddr> {
    let address: IpAddr = if ipv6 {
        format!("fd66:66::{suffix}").parse()?
    } else {
        format!("10.66.66.{suffix}").parse()?
    };
    Ok(SocketAddr::new(address, 40000))
}

fn destinations(ipv6: bool, same: bool) -> Result<[SocketAddr; 2]> {
    let first = SocketAddr::new(source(ipv6, 91)?.ip(), 9100);
    Ok([
        first,
        if same {
            first
        } else {
            SocketAddr::new(source(ipv6, 92)?.ip(), 9101)
        },
    ])
}

pub fn peer(ipv6: bool, suffix: u8) -> Result<Peer> {
    let address = source(ipv6, suffix)?;
    Peer::new(address.ip(), address.port())
}

pub async fn exchange(host: &mut HostAdapter, peers: &mut [Peer; 2], now: Duration) -> Result<()> {
    for peer in peers.iter_mut() {
        peer.poll(i64::try_from(now.as_millis())?);
        while let Some(packet) = peer.device.outgoing.pop_front() {
            host.inject(&packet)?;
        }
    }
    poll_fn(|cx| Poll::Ready(host.poll_io(cx, now))).await?;
    while let Some(packet) = host.take_packet() {
        let destination: IpAddr = match packet.first().map(|byte| byte >> 4) {
            Some(4) => Ipv4Packet::new_checked(packet.as_slice())?
                .dst_addr()
                .into(),
            Some(6) => Ipv6Packet::new_checked(packet.as_slice())?
                .dst_addr()
                .into(),
            _ => anyhow::bail!("invalid output packet family"),
        };
        let peer = peers
            .iter_mut()
            .find(|peer| {
                peer.interface
                    .ip_addrs()
                    .iter()
                    .any(|address| address.address() == destination.into())
            })
            .context("output had no controlled peer")?;
        peer.device.inject(packet)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dynamic_destinations_and_shared_destination_preserve_async_flow_lifecycle() {
        for ipv6 in [false, true] {
            for same_destination in [false, true] {
                run_probe(ipv6, same_destination).await.unwrap();
            }
        }
    }
}
