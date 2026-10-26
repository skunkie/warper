// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Combined-runtime traffic experiment.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use smoltcp::socket::{tcp, udp};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::Instant,
};

use crate::{
    adapter::{self, AcceptedFlow, BackendId},
    packet_peer::Peer,
    runtime::{Channels, Runtime},
    udp_adapter::{self, Association},
};

const TRANSFER: usize = 65536;
const TRAILER: &[u8] = b"runtime-response-after-fin";

pub async fn run_probe(ipv6: bool) -> Result<()> {
    let (runtime, mut channels) = Runtime::new(
        adapter::Limits::default(),
        udp_adapter::Limits::default(),
        crate::udp_probe::select_backend,
        64,
    )?;
    let mut runner = tokio::spawn(runtime.run());
    let mut handlers = JoinSet::new();
    let mut completed = false;
    let outcome = tokio::select! {
        result = &mut runner => {
            completed = true;
            match result {
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
                Ok(Ok(_)) => Err(anyhow::anyhow!("combined runner stopped before explicit shutdown")),
            }
        }
        result = tokio::time::timeout(Duration::from_secs(5), exchange(ipv6, &mut channels, &mut handlers)) => result.context("combined runtime probe exceeded deadline").and_then(|result| result),
    };
    // A failed send means the runner has already stopped; joining below reports
    // that outcome. It is never substituted for a successful shutdown.
    let _shutdown_delivered = channels.shutdown.send(()).is_ok();
    let mut cleanup = Vec::new();
    let mut report = None;
    if !completed {
        match tokio::time::timeout(Duration::from_secs(1), &mut runner).await {
            Ok(Ok(Ok(result))) => report = Some(result),
            Ok(result) => cleanup.push(format!("runner join failed: {result:?}")),
            Err(_) => {
                runner.abort();
                match runner.await {
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => cleanup.push(format!("runner abort failed: {error}")),
                    Ok(Err(error)) => cleanup.push(format!("runner failed during abort: {error}")),
                    Ok(Ok(_)) => {}
                }
                cleanup.push("runner exceeded shutdown deadline".into());
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
    if let Err(primary) = outcome {
        return Err(primary.context(format!("additional cleanup failures: {cleanup:?}")));
    }
    ensure!(cleanup.is_empty(), "combined cleanup failures: {cleanup:?}");
    let report = report.context("missing joined runner report")?;
    ensure!(
        report.emitted_tcp > 0 && report.emitted_udp == 4 && report.rejected == 0,
        "combined packet accounting changed"
    );
    ensure!(
        channels.tcp.recv().await.is_none()
            && channels.udp.recv().await.is_none()
            && channels.packets.recv().await.is_none(),
        "combined runner retained usable output after shutdown"
    );
    Ok(())
}

async fn exchange(
    ipv6: bool,
    channels: &mut Channels,
    handlers: &mut JoinSet<Result<()>>,
) -> Result<()> {
    let source: std::net::SocketAddr = if ipv6 {
        "[fd66:66::2]:40000"
    } else {
        "10.66.66.2:40000"
    }
    .parse()?;
    let destination: std::net::SocketAddr = if ipv6 {
        "[fd66:66::91]:9000"
    } else {
        "10.66.66.91:9000"
    }
    .parse()?;
    let mut peer = Peer::new(source.ip(), source.port())?;
    peer.sockets.get_mut::<tcp::Socket>(peer.tcp).connect(
        peer.interface.context(),
        destination,
        std::net::SocketAddr::new(source.ip(), 40001),
    )?;
    let payloads = [
        vec![],
        vec![0x31],
        vec![0x72; 257],
        vec![0x53; if ipv6 { 1232 } else { 1252 }],
    ];
    for payload in &payloads {
        peer.sockets
            .get_mut::<udp::Socket>(peer.udp)
            .send_slice(payload, destination)?;
    }
    let origin = Instant::now();
    let (mut sent, mut received, mut udp_received, mut completed) = (0, 0, 0, 0);
    let (mut tcp_accepted, mut udp_accepted) = (false, false);
    let (udp_delivered, udp_delivery) = tokio::sync::oneshot::channel();
    let mut udp_delivered = Some(udp_delivered);
    let mut udp_delivery = Some(udp_delivery);
    loop {
        let elapsed = i64::try_from(origin.elapsed().as_millis())?;
        peer.poll(elapsed);
        for _ in 0..64 {
            let Some(packet) = peer.device.outgoing.pop_front() else {
                break;
            };
            channels.ingress.try_inject(&packet)?;
        }
        ensure!(
            peer.device.outgoing.is_empty(),
            "peer exceeded bounded output work"
        );
        let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
        if sent < TRANSFER && socket.can_send() {
            sent += socket.send_slice(&[0x61; 1024][..(TRANSFER - sent).min(1024)])?;
            if sent == TRANSFER {
                socket.close();
            }
        }
        read_response(socket, &mut received)?;
        let tcp_done =
            sent == TRANSFER && received == TRANSFER + TRAILER.len() && !socket.may_recv();
        let socket = peer.sockets.get_mut::<udp::Socket>(peer.udp);
        while socket.can_recv() {
            let (payload, metadata) = socket.recv()?;
            ensure!(
                payloads.get(udp_received).map(Vec::as_slice) == Some(payload)
                    && metadata.endpoint == destination.into(),
                "combined UDP payload/source changed"
            );
            udp_received += 1;
        }
        if udp_received == 4
            && let Some(delivered) = udp_delivered.take()
        {
            delivered.send(()).map_err(|_| {
                anyhow::anyhow!("UDP handler ended before delivery acknowledgement")
            })?;
        }
        if tcp_done && udp_received == 4 && completed == 2 {
            return Ok(());
        }
        let next = peer
            .interface
            .poll_at(smoltcp::time::Instant::from_millis(elapsed), &peer.sockets)
            .map(|time| origin + Duration::from_millis(time.total_millis().max(0) as u64));
        tokio::select! {
            packet = channels.packets.recv() => peer.device.inject(packet.context("combined packet output closed")?)?,
            flow = channels.tcp.recv(), if !tcp_accepted => {
                let flow = flow.context("TCP acceptance closed")?;
                ensure!(flow.metadata.source == std::net::SocketAddr::new(source.ip(), 40001) && flow.metadata.destination == destination && flow.metadata.backend == BackendId(1), "combined TCP metadata changed");
                tcp_accepted = true;
                handlers.spawn(echo_tcp(flow));
            }
            association = channels.udp.recv(), if !udp_accepted => {
                let association = association.context("UDP acceptance closed")?;
                ensure!(association.metadata().source == source && association.metadata().destination == destination && association.metadata().backend == BackendId(1), "combined UDP metadata changed");
                udp_accepted = true;
                handlers.spawn(echo_udp(association, payloads.clone(), udp_delivery.take().context("duplicate UDP handler")?));
            }
            result = handlers.join_next(), if !handlers.is_empty() => {
                result.context("handler set unexpectedly empty")???;
                completed += 1;
            }
            _ = async {
                match next { Some(next) => tokio::time::sleep_until(next).await, None => std::future::pending().await }
            } => {}
        }
    }
}

fn read_response(socket: &mut tcp::Socket<'_>, received: &mut usize) -> Result<()> {
    // A circular receive ring can expose two contiguous slices. Drain both
    // before waiting: a final slice after FIN has no new network wakeup.
    for _ in 0..2 {
        if !socket.can_recv() {
            break;
        }
        let valid = socket.recv(|bytes| {
            let valid = bytes.iter().enumerate().all(|(offset, byte)| {
                let position = *received + offset;
                if position < TRANSFER {
                    *byte == 0x61
                } else {
                    TRAILER.get(position - TRANSFER) == Some(byte)
                }
            });
            *received += bytes.len();
            (bytes.len(), valid)
        })?;
        ensure!(valid, "combined TCP bytes changed");
    }
    ensure!(
        !socket.can_recv(),
        "peer exceeded bounded contiguous TCP reads"
    );
    Ok(())
}

async fn echo_tcp(mut flow: AcceptedFlow) -> Result<()> {
    let mut total = 0;
    let mut buffer = [0; 1024];
    loop {
        let count = flow.stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        total += count;
        ensure!(
            total <= TRANSFER && buffer[..count].iter().all(|byte| *byte == 0x61),
            "combined TCP request changed"
        );
        flow.stream.write_all(&buffer[..count]).await?;
    }
    ensure!(total == TRANSFER, "combined request ended early");
    flow.stream.write_all(TRAILER).await?;
    flow.stream.shutdown().await?;
    Ok(())
}

async fn echo_udp(
    mut association: Association,
    payloads: [Vec<u8>; 4],
    delivered: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    for expected in payloads {
        let actual = association.recv().await?;
        ensure!(actual.payload() == expected, "combined UDP request changed");
        association.try_reply(actual.payload())?;
    }
    // Only the controlled peer acknowledges receipt. This is a fixture lifetime
    // barrier, not a delivery guarantee of UDP or of the adapter API.
    delivered
        .await
        .context("UDP peer ended before final delivery")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn combined_runtime_preserves_tcp_and_udp_in_both_families() {
        for ipv6 in [false, true] {
            run_probe(ipv6).await.unwrap();
        }
    }

    #[test]
    fn peer_drains_wrapped_final_receive_slice_without_another_network_wakeup() {
        let mut sender = Peer::new("10.66.66.2".parse().unwrap(), 40000).unwrap();
        let mut receiver = Peer::new("10.66.66.91".parse().unwrap(), 9000).unwrap();
        receiver
            .sockets
            .get_mut::<tcp::Socket>(receiver.tcp)
            .listen(9000)
            .unwrap();
        sender
            .sockets
            .get_mut::<tcp::Socket>(sender.tcp)
            .connect(
                sender.interface.context(),
                "10.66.66.91:9000".parse::<std::net::SocketAddr>().unwrap(),
                "10.66.66.2:40001".parse::<std::net::SocketAddr>().unwrap(),
            )
            .unwrap();
        fn exchange(sender: &mut Peer, receiver: &mut Peer, start: i64) {
            for step in start..start + 100 {
                sender.poll(step);
                receiver.poll(step);
                while let Some(packet) = sender.device.outgoing.pop_front() {
                    receiver.device.inject(packet).unwrap();
                }
                while let Some(packet) = receiver.device.outgoing.pop_front() {
                    sender.device.inject(packet).unwrap();
                }
            }
        }
        exchange(&mut sender, &mut receiver, 0);
        assert_eq!(
            sender
                .sockets
                .get_mut::<tcp::Socket>(sender.tcp)
                .send_slice(&vec![0x61; 8190])
                .unwrap(),
            8190
        );
        exchange(&mut sender, &mut receiver, 100);
        let mut received = 0;
        read_response(
            receiver.sockets.get_mut::<tcp::Socket>(receiver.tcp),
            &mut received,
        )
        .unwrap();
        assert_eq!(received, 8190);
        exchange(&mut sender, &mut receiver, 200);
        let socket = sender.sockets.get_mut::<tcp::Socket>(sender.tcp);
        assert_eq!(socket.send_slice(&[0x61; 262]).unwrap(), 262);
        socket.close();
        exchange(&mut sender, &mut receiver, 300);
        let socket = receiver.sockets.get_mut::<tcp::Socket>(receiver.tcp);
        let contiguous = socket.peek(262).unwrap().len();
        assert_eq!(
            contiguous, 2,
            "fixture must force wraparound at the receive ring boundary"
        );
        read_response(socket, &mut received).unwrap();
        assert_eq!(received, 8452);
        assert!(
            !socket.may_recv(),
            "FIN and all buffered bytes must be observed before waiting"
        );
    }
}
