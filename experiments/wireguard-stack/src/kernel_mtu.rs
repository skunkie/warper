// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Retained TCP recovery from local outer MTU errors with a kernel peer.

use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use smoltcp::{phy::Device, socket::tcp, wire::TcpPacket};

use crate::{
    Endpoint, create_client, kernel_peer,
    outer_errors::ErrorQueue,
    outer_tcp_probe::apply_outer,
    packet_peer::Peer,
    path_mtu::PathBudget,
    pmtu_probe::{drain, plain_tcp},
};

const RESPONSE: &[u8] = b"kernel-response-after-mtu-fin";

pub fn run() -> Result<()> {
    let (mut netlink, port) = kernel_peer::configure()?;
    for ipv6 in [false, true] {
        for outer_ipv6 in [false, true] {
            let mut remote = crate::loopback_address(outer_ipv6);
            remote.set_port(port);
            run_case(ipv6, remote)?;
            kernel_peer::verify_handshake(&mut netlink, false)?;
        }
    }
    Ok(())
}

fn run_case(ipv6: bool, remote: SocketAddr) -> Result<()> {
    let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let destination: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    let (_, transport) = create_client(ipv6, remote)?;
    let mut client = Endpoint {
        peer: Peer::with_mtu(source, 40000, 1500)?,
        transport,
    };
    client.transport.path_budget = PathBudget::new(1600, remote.is_ipv6())?;
    let socket = client.peer.sockets.get_mut::<tcp::Socket>(client.peer.tcp);
    socket.set_ack_delay(None);
    socket.connect(
        client.peer.interface.context(),
        (destination, 9000),
        (source, 40001),
    )?;
    client.transport.socket.connect(remote)?;
    let queue = ErrorQueue::enable(&client.transport.socket)?;
    let address = client.transport.socket.local_addr()?;
    let payload: Vec<_> = (0..8192).map(|index| (index % 251) as u8).collect();
    let mut workers = kernel_peer::Workers::start_tcp(
        std::net::TcpListener::bind((destination, 9000))?,
        payload.clone(),
        RESPONSE,
    )?;
    let result = transfer(&mut client, &queue, &payload);
    let cleanup = workers.finish();
    drop(queue);
    drop(client);
    let rebind = UdpSocket::bind(address).map(drop);
    let rebind_context = match &rebind {
        Ok(()) => "outer socket rebound".into(),
        Err(error) => format!("outer socket rebind failed: {error}"),
    };
    let report = match (result, cleanup) {
        (Err(primary), cleanup) => {
            return Err(primary.context(match cleanup {
                Ok(_) => format!("kernel MTU worker joined; {rebind_context}"),
                Err(error) => {
                    format!("kernel MTU worker cleanup also failed: {error}; {rebind_context}")
                }
            }));
        }
        (Ok(()), Err(error)) => return Err(error.context(rebind_context)),
        (Ok(()), Ok(report)) => {
            rebind?;
            report
        }
    };
    ensure!(
        report.tcp == 1 && report.udp == 0 && report.bytes == payload.len() + RESPONSE.len(),
        "kernel MTU peer did not verify exact workload"
    );
    // Client ACKs are pumped before transfer completion. Rebinding also proves
    // the joined worker released its listener and accepted stream descriptors.
    drop(std::net::TcpListener::bind((destination, 9000))?);
    println!(
        "PASS independent kernel outer MTU: inner_ipv6={ipv6}, outer_ipv6={}, reported_mtu=1400, delivered_bytes={}, retry=true, worker_joined=true, socket_rebound=true",
        remote.is_ipv6(),
        report.bytes
    );
    Ok(())
}

fn transfer(client: &mut Endpoint, queue: &ErrorQueue, payload: &[u8]) -> Result<()> {
    let wall = Instant::now();
    let mut sent = false;
    let mut resized = false;
    let mut tuple = None;
    let mut sequence = None;
    let mut retried = false;
    let mut response = Vec::with_capacity(RESPONSE.len());
    let limit = PathBudget::new(1400, client.transport.remote.is_ipv6())?.inner_mtu();
    let mut completed = None;
    for step in 0..1000 {
        ensure!(
            wall.elapsed() < Duration::from_secs(6),
            "kernel MTU wall deadline exceeded"
        );
        let tick = step * 5;
        let now = Duration::from_millis(tick);
        client.peer.poll(tick as i64);
        if sent && !resized {
            ensure!(
                queue.read()?.is_none(),
                "kernel MTU queue was not empty before TCP send"
            );
            let packet = client
                .peer
                .device
                .outgoing
                .front()
                .ok_or_else(|| anyhow::anyhow!("missing oversized kernel-bound TCP"))?;
            let frame =
                plain_tcp(packet)?.ok_or_else(|| anyhow::anyhow!("kernel output was not TCP"))?;
            let tcp = TcpPacket::new_checked(frame.payload)?;
            ensure!(
                !tcp.payload().is_empty() && packet.len() > limit,
                "kernel MSS did not exercise oversized TCP"
            );
            sequence = Some(tcp.seq_number());
            let buffered = client
                .peer
                .sockets
                .get::<tcp::Socket>(client.peer.tcp)
                .send_queue();
            let error = match client.transport.pump(&mut client.peer, now) {
                Ok(()) => anyhow::bail!("kernel-bound oversized ciphertext unexpectedly sent"),
                Err(error) => error,
            };
            let report = queue.diagnose(error)?;
            ensure!(report.mtu == 1400, "unexpected kernel outer MTU");
            ensure!(
                apply_outer(
                    &mut client.peer,
                    &mut client.transport.path_budget,
                    report.mtu,
                    now
                )? > 0,
                "kernel fixture did not retire pending TCP attempts"
            );
            ensure!(
                client
                    .peer
                    .sockets
                    .get::<tcp::Socket>(client.peer.tcp)
                    .send_queue()
                    == buffered
            );
            resized = true;
        }
        if resized {
            for packet in &client.peer.device.outgoing {
                ensure!(
                    packet.len() <= limit,
                    "kernel-bound retry exceeded resized MTU"
                );
                let frame = plain_tcp(packet)?
                    .ok_or_else(|| anyhow::anyhow!("kernel retry was not TCP"))?;
                let tcp = TcpPacket::new_checked(frame.payload)?;
                if Some(tcp.seq_number()) == sequence && !tcp.payload().is_empty() {
                    retried = true;
                }
            }
        }
        client.transport.pump(&mut client.peer, now)?;
        let socket = client.peer.sockets.get_mut::<tcp::Socket>(client.peer.tcp);
        if !sent && socket.state() == tcp::State::Established {
            tuple = Some((socket.local_endpoint(), socket.remote_endpoint()));
            ensure!(socket.send_slice(payload)? == payload.len());
            socket.close();
            sent = true;
        }
        drain(&mut client.peer, &mut response, RESPONSE.len())?;
        let socket = client.peer.sockets.get::<tcp::Socket>(client.peer.tcp);
        if sent && !socket.may_recv() {
            ensure!(
                response == RESPONSE && resized && retried,
                "kernel MTU response, sizing or retry missing"
            );
            ensure!(
                Some((socket.local_endpoint(), socket.remote_endpoint())) == tuple,
                "kernel MTU tuple changed"
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
                    "kernel retries generated additional outer errors"
                );
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("kernel MTU step deadline exceeded")
}
