// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One retained TCP connection resized by a real routed outer MTU report.

use crate::{
    Endpoint,
    outer_errors::ErrorQueue,
    outer_remote::Reservation,
    path_mtu::PathBudget,
    pmtu_probe::{drain, plain_tcp},
};
use anyhow::{Result, ensure};
use boringtun::noise::TunnResult;
use smoltcp::{phy::Device, socket::tcp, wire::TcpPacket};
use std::{
    net::UdpSocket,
    thread,
    time::{Duration, Instant},
};

pub(super) const RESPONSE: &[u8] = b"router-response-after-mtu-fin";

pub(super) fn payload() -> Vec<u8> {
    (0..8192).map(|index| (index % 251) as u8).collect()
}

pub fn run_case(ipv6: bool, outer_ipv6: bool) -> Result<()> {
    let mut client = crate::router_mtu::client(ipv6, outer_ipv6)?;
    let address = client.transport.socket.local_addr()?;
    let queue = ErrorQueue::enable_remote_probe(&client.transport.socket)?;
    let source = client.peer.interface.ip_addrs()[0].address();
    let destination: std::net::IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    let socket = client.peer.sockets.get_mut::<tcp::Socket>(client.peer.tcp);
    socket.set_ack_delay(None);
    socket.connect(
        client.peer.interface.context(),
        (destination, 9000),
        (source, 40001),
    )?;
    let result = transfer(&mut client, &queue);
    drop(queue);
    drop(client);
    let cleanup = UdpSocket::bind(address).map(drop);
    match (result, cleanup) {
        (Err(primary), cleanup) => Err(primary.context(match cleanup {
            Ok(()) => "router TCP outer socket rebound".into(),
            Err(error) => format!("router TCP cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => Ok(cleanup?),
    }
}

fn transfer(client: &mut Endpoint, queue: &ErrorQueue) -> Result<()> {
    let wall = Instant::now();
    let payload = payload();
    let mut sent = false;
    let mut resized = false;
    let mut tuple = None;
    let mut sequence = None;
    let mut retried = false;
    let mut response = Vec::with_capacity(RESPONSE.len());
    let mut completed = None;
    let limit = PathBudget::new(1400, client.transport.remote.is_ipv6())?.inner_mtu();
    let reporter = crate::router_mtu::reporter(client.transport.remote.is_ipv6())?;
    for _ in 0..6000 {
        ensure!(
            wall.elapsed() < Duration::from_secs(6),
            "routed TCP wall deadline exceeded"
        );
        let now = wall.elapsed();
        client.peer.poll(i64::try_from(now.as_millis())?);
        if sent && !resized {
            ensure!(
                queue.read()?.is_none(),
                "routed TCP queue was not initially empty"
            );
            let packet = client
                .peer
                .device
                .outgoing
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("missing oversized routed TCP segment"))?;
            let frame =
                plain_tcp(&packet)?.ok_or_else(|| anyhow::anyhow!("expected routed TCP"))?;
            let tcp = TcpPacket::new_checked(frame.payload)?;
            ensure!(
                !tcp.payload().is_empty() && packet.len() > limit,
                "kernel MSS did not exercise routed limit"
            );
            sequence = Some(tcp.seq_number());
            let buffered = client
                .peer
                .sockets
                .get::<tcp::Socket>(client.peer.tcp)
                .send_queue();
            let mut output = [0; 1536];
            let result = client.transport.tunnel.encapsulate(&packet, &mut output);
            let TunnResult::WriteToNetwork(packet) = result else {
                anyhow::bail!("routed TCP encryption was not immediately ready");
            };
            let mut reservation = Reservation::default();
            reservation.reserve(
                packet,
                queue,
                reporter,
                wall.elapsed(),
                Duration::from_secs(1),
            )?;
            // Send exactly one attempt; no remaining TCP output is encrypted
            // until its remote report has been validated and sizing committed.
            client
                .transport
                .send_result(TunnResult::WriteToNetwork(packet), &mut client.peer)?;
            loop {
                if let Some(received) = queue.receive()? {
                    ensure!(received.record.mtu == 1400, "unexpected routed TCP MTU");
                    ensure!(
                        reservation.apply_tcp(
                            queue,
                            &received,
                            &mut client.peer,
                            &mut client.transport.path_budget,
                            wall.elapsed()
                        )? > 0,
                        "routed TCP did not retire queued attempts"
                    );
                    break;
                }
                reservation.advance(wall.elapsed())?;
                thread::sleep(Duration::from_millis(1));
            }
            ensure!(
                client
                    .peer
                    .sockets
                    .get::<tcp::Socket>(client.peer.tcp)
                    .send_queue()
                    == buffered,
                "routed sizing changed unacknowledged TCP bytes"
            );
            resized = true;
        }
        if resized {
            for packet in &client.peer.device.outgoing {
                ensure!(
                    packet.len() <= limit,
                    "routed TCP retry exceeded reduced MTU"
                );
                let frame =
                    plain_tcp(packet)?.ok_or_else(|| anyhow::anyhow!("expected TCP retry"))?;
                let tcp = TcpPacket::new_checked(frame.payload)?;
                if Some(tcp.seq_number()) == sequence && !tcp.payload().is_empty() {
                    retried = true;
                }
            }
        }
        client.transport.pump(&mut client.peer, wall.elapsed())?;
        let socket = client.peer.sockets.get_mut::<tcp::Socket>(client.peer.tcp);
        if !sent && socket.state() == tcp::State::Established {
            tuple = Some((socket.local_endpoint(), socket.remote_endpoint()));
            ensure!(socket.send_slice(&payload)? == payload.len());
            socket.close();
            sent = true;
        }
        drain(&mut client.peer, &mut response, RESPONSE.len())?;
        let socket = client.peer.sockets.get::<tcp::Socket>(client.peer.tcp);
        if sent && !socket.may_recv() {
            ensure!(
                response == RESPONSE && resized && retried,
                "routed TCP response, sizing or retry missing"
            );
            ensure!(
                Some((socket.local_endpoint(), socket.remote_endpoint())) == tuple,
                "routed TCP tuple changed: state={:?}, expected={tuple:?}, actual={:?}",
                socket.state(),
                (socket.local_endpoint(), socket.remote_endpoint())
            );
            ensure!(
                client.peer.device.capabilities().max_transmission_unit == limit
                    && client.transport.path_budget.outer_mtu() == 1400
                    && client.transport.pmtu_reductions == 0
                    && client.transport.pmtu_fixture.is_none()
            );
            let completion = *completed.get_or_insert_with(Instant::now);
            if completion.elapsed() >= Duration::from_millis(100) {
                ensure!(
                    queue.read()?.is_none(),
                    "resized TCP generated another outer error"
                );
                println!(
                    "PASS remote router TCP MTU: inner_ipv6={}, outer_ipv6={}, reported_mtu=1400, inner_mtu={limit}, delivered_bytes={}, retry=true, application_writes=1",
                    client.peer.interface.ip_addrs()[0].address().version()
                        == smoltcp::wire::IpVersion::Ipv6,
                    client.transport.remote.is_ipv6(),
                    payload.len() + response.len()
                );
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("routed TCP step deadline exceeded")
}
