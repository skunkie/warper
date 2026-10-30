// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Dynamic sizing through the actual owned host runner and accepted streams.

use std::{io, net::IpAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use smoltcp::{
    socket::tcp,
    wire::{Ipv4Packet, Ipv6Packet, TcpPacket},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::Instant,
};

use crate::{
    adapter::{self, AcceptedFlow},
    packet_peer::Peer,
    runtime::{Channels, Runtime},
};

const BYTES: usize = 8192;
const TRAILER: &[u8] = b"pmtu-after-fin";

pub async fn run(ipv6: bool, mtu: usize) -> Result<()> {
    let mut first = true;
    run_with_seed(
        ipv6,
        mtu,
        Box::new(move || {
            if first {
                first = false;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            // Controlled fixture seed; Linux TUN runs use OS entropy instead.
            Ok(0x9182_7364)
        }),
    )
    .await
}

async fn run_with_seed(
    ipv6: bool,
    mtu: usize,
    seed: Box<dyn FnMut() -> io::Result<u64> + Send>,
) -> Result<()> {
    let config = adapter::PmtuConfig {
        link_mtu: 1500,
        reporter: |metadata| Some(metadata.source.ip()),
        seed,
    };
    let (runner, mut channels) = Runtime::with_pmtu(
        adapter::Limits::default(),
        crate::udp_adapter::Limits::default(),
        crate::accepted_probe::select_backend,
        64,
        config,
    )?;
    let mut runner = tokio::spawn(runner.run());
    let mut handlers = JoinSet::new();
    let mut finished = false;
    let outcome = tokio::select! {
        result = &mut runner => {
            finished = true;
            match result {
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
                Ok(Ok(_)) => Err(anyhow::anyhow!("PMTU runner ended before shutdown")),
            }
        }
        result = tokio::time::timeout(Duration::from_secs(8), exchange(&mut channels, &mut handlers, ipv6, mtu)) => {
            result.context("runtime PMTU exchange deadline").and_then(|result| result)
        }
    };
    let _stop_delivered = channels.shutdown.send(()).is_ok();
    let mut cleanup = Vec::new();
    let mut report = None;
    if !finished {
        match tokio::time::timeout(Duration::from_secs(1), &mut runner).await {
            Ok(Ok(Ok(result))) => report = Some(result),
            Ok(result) => cleanup.push(format!("PMTU runner join: {result:?}")),
            Err(_) => {
                runner.abort();
                match runner.await {
                    Err(error) if error.is_cancelled() => {}
                    result => cleanup.push(format!("PMTU abort join: {result:?}")),
                }
                cleanup.push("PMTU shutdown deadline".to_owned());
            }
        }
    }
    if outcome.is_err() {
        handlers.abort_all();
    }
    while let Some(result) = handlers.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Err(error) if error.is_cancelled() && outcome.is_err() => {}
            result => cleanup.push(format!("PMTU handler: {result:?}")),
        }
    }
    if let Err(primary) = outcome {
        return Err(primary.context(format!(
            "additional cleanup: {cleanup:?}; report={report:?}"
        )));
    }
    ensure!(cleanup.is_empty(), "PMTU cleanup failed: {cleanup:?}");
    let report = report.context("missing PMTU shutdown report")?;
    ensure!(
        report.pmtu_feedback >= 2 && report.pmtu_reductions >= 1 && report.pmtu_deferred >= 1,
        "runtime did not own/retry/commit sizing: {report:?}"
    );
    ensure!(
        channels.packets.recv().await.is_none() && channels.tcp.recv().await.is_none(),
        "PMTU runner retained output"
    );
    println!(
        "PASS runtime PMTU: IPv6={ipv6}, mtu={mtu}, flows=2, single_write_bytes=16384, FIN=true, transient_seed_retry=true, joined=true"
    );
    Ok(())
}

async fn exchange(
    channels: &mut Channels,
    handlers: &mut JoinSet<Result<()>>,
    ipv6: bool,
    mtu: usize,
) -> Result<()> {
    let mut peers: [Peer; 2] = [2, 3]
        .map(|suffix| {
            Peer::with_mtu(
                crate::accepted_probe::source(ipv6, suffix)
                    .expect("fixture source")
                    .ip(),
                40000,
                1500,
            )
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("fixture peer count"))?;
    for (index, peer) in peers.iter_mut().enumerate() {
        let destination = std::net::SocketAddr::new(
            crate::accepted_probe::source(ipv6, 91 + index as u8)?.ip(),
            9100 + index as u16,
        );
        let source = crate::accepted_probe::source(ipv6, 2 + index as u8)?;
        peer.sockets.get_mut::<tcp::Socket>(peer.tcp).connect(
            peer.interface.context(),
            destination,
            source,
        )?;
    }
    let origin = Instant::now();
    let mut sent = [false; 2];
    let mut accepted = [false; 2];
    let mut feedback = [false; 2];
    let mut lost_sequence = [None; 2];
    let mut retried = [false; 2];
    let mut received = [Vec::new(), Vec::new()];
    loop {
        ensure!(
            origin.elapsed() < Duration::from_secs(7),
            "PMTU progress: sent={sent:?} accepted={accepted:?} feedback={feedback:?} retried={retried:?} received={:?} state={:?}",
            received.each_ref().map(Vec::len),
            peers
                .each_ref()
                .map(|peer| peer.sockets.get::<tcp::Socket>(peer.tcp).state())
        );
        for (index, peer) in peers.iter_mut().enumerate() {
            peer.poll(i64::try_from(origin.elapsed().as_millis())?);
            while let Some(packet) = peer.device.outgoing.pop_front() {
                channels.ingress.try_inject(&packet)?;
            }
            let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
            if !sent[index] && socket.can_send() {
                ensure!(
                    socket.send_slice(&vec![0x61 + index as u8; BYTES])? == BYTES,
                    "partial PMTU application write"
                );
                socket.close();
                sent[index] = true;
            }
            while socket.can_recv() {
                socket.recv(|bytes| {
                    received[index].extend_from_slice(bytes);
                    (bytes.len(), ())
                })?;
                ensure!(
                    received[index].len() <= BYTES + TRAILER.len(),
                    "PMTU duplicated bytes"
                );
            }
        }
        while let Ok(flow) = channels.tcp.try_recv() {
            let index = peers
                .iter()
                .position(|peer| {
                    peer.interface.ip_addrs()[0].address() == flow.metadata.source.ip().into()
                })
                .context("PMTU accepted wrong source")?;
            ensure!(!accepted[index], "duplicate accepted PMTU flow");
            ensure!(
                flow.metadata.backend == adapter::BackendId(index as u8),
                "PMTU backend changed"
            );
            accepted[index] = true;
            handlers.spawn(handle(flow, index));
        }
        for _ in 0..64 {
            let Ok(packet) = channels.packets.receiver_try_recv() else {
                break;
            };
            let (destination, payload): (IpAddr, &[u8]) = if ipv6 {
                let ip = Ipv6Packet::new_checked(&packet[..])?;
                (ip.dst_addr().into(), &packet[40..])
            } else {
                let ip = Ipv4Packet::new_checked(&packet[..])?;
                (ip.dst_addr().into(), &packet[20..])
            };
            let index = peers
                .iter()
                .position(|peer| peer.interface.ip_addrs()[0].address() == destination.into())
                .context("PMTU output wrong destination")?;
            let tcp = TcpPacket::new_checked(payload)?;
            let path_mtu = if index == 0 { 1400 } else { mtu };
            if packet.len() > path_mtu {
                let report = crate::pmtu_fixture::too_big(&packet, ipv6, path_mtu)?;
                channels.ingress.try_inject(&report)?;
                if !feedback[index] {
                    feedback[index] = true;
                    lost_sequence[index] = Some(tcp.seq_number());
                }
                continue; // Controlled network loss; the application writes once.
            }
            if !tcp.payload().is_empty() && Some(tcp.seq_number()) == lost_sequence[index] {
                retried[index] = true;
            }
            peers[index].device.inject(packet)?;
        }
        if feedback == [true, true]
            && retried == [true, true]
            && peers.iter().enumerate().all(|(index, peer)| {
                received[index].len() == BYTES + TRAILER.len()
                    && !peer.sockets.get::<tcp::Socket>(peer.tcp).may_recv()
            })
        {
            for (index, response) in received.iter().enumerate() {
                ensure!(
                    response[..BYTES]
                        .iter()
                        .all(|byte| *byte == 0x61 + index as u8)
                        && response[BYTES..] == *TRAILER,
                    "PMTU changed response bytes or FIN"
                );
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn handle(mut flow: AcceptedFlow, index: usize) -> Result<()> {
    let mut request = Vec::with_capacity(BYTES);
    (&mut flow.stream)
        .take((BYTES + 1) as u64)
        .read_to_end(&mut request)
        .await?;
    ensure!(
        request.len() == BYTES && request.iter().all(|byte| *byte == 0x61 + index as u8),
        "PMTU request changed"
    );
    let mut response = request;
    response.extend_from_slice(TRAILER);
    flow.stream.write_all(&response).await?;
    flow.stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn permanent_seed_failure_is_reported_after_runner_and_handlers_are_joined() {
        let error = super::run_with_seed(
            false,
            1280,
            Box::new(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic seed failure",
                ))
            }),
        )
        .await
        .unwrap_err();
        let failure = error
            .downcast_ref::<crate::runtime::Failure>()
            .expect("typed runner failure retained");
        assert_eq!(failure.cause, crate::runtime::Error::Pmtu);
        assert!(
            matches!(failure.pmtu, Some(crate::adapter::PmtuError::Seed(ref source)) if source.kind() == std::io::ErrorKind::PermissionDenied)
        );
    }

    #[tokio::test]
    async fn runtime_resizes_two_retained_streams_and_retries_seed_without_input() {
        for ipv6 in [false, true] {
            for mtu in [1280, 1400] {
                super::run(ipv6, mtu).await.unwrap();
            }
        }
    }
}
