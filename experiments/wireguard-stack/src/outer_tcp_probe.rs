// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Local outer feedback sizing a retained experimental TCP connection.

use crate::{
    Endpoint, create_pair_with_outer,
    outer_errors::ErrorQueue,
    packet_peer::Peer,
    path_mtu::PathBudget,
    pmtu_probe::{PathFixture, drain, plain_tcp},
};
use anyhow::{Result, ensure};
use smoltcp::{phy::Device, socket::tcp, wire::TcpPacket};
use std::{
    io,
    net::{IpAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Eq, PartialEq)]
enum Error {
    InactiveSocket,
    PendingNonTcp,
    InvalidChecksum,
    ForeignFlow,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "outer TCP sizing: {self:?}")
    }
}

impl std::error::Error for Error {}

pub(super) fn apply_outer(
    peer: &mut Peer,
    budget: &mut PathBudget,
    mtu: usize,
    now: Duration,
) -> Result<usize> {
    let tick = i64::try_from(now.as_millis())?;
    let mut candidate = *budget;
    if !candidate.reduce(mtu)? {
        return Ok(0);
    }
    let limit = candidate
        .inner_mtu()
        .min(peer.device.capabilities().max_transmission_unit);
    ensure!(
        !peer.device.has_ingress(),
        io::Error::from(io::ErrorKind::WouldBlock)
    );
    let socket = peer.sockets.get::<tcp::Socket>(peer.tcp);
    ensure!(socket.is_active(), Error::InactiveSocket);
    let local = socket.local_endpoint();
    let remote = socket.remote_endpoint();
    for packet in &peer.device.outgoing {
        let frame = plain_tcp(packet)?.ok_or(Error::PendingNonTcp)?;
        let tcp = TcpPacket::new_checked(frame.payload)?;
        ensure!(
            tcp.verify_checksum(&frame.source.into(), &frame.destination.into()),
            Error::InvalidChecksum
        );
        ensure!(
            local
                .is_some_and(|endpoint| endpoint.addr == frame.source.into()
                    && endpoint.port == tcp.src_port())
                && remote.is_some_and(|endpoint| endpoint.addr == frame.destination.into()
                    && endpoint.port == tcp.dst_port()),
            Error::ForeignFlow
        );
    }
    // Validation above leaves only packet attempts backed by the retained TCP
    // send buffer. Retiring them lets TCP resegment; no application resend occurs.
    let retired = peer.device.outgoing.len();
    peer.device.outgoing.clear();
    crate::mtu_reduction::rebuild_interface(peer, limit, tick)?;
    *budget = candidate;
    Ok(retired)
}

pub fn run_case(ipv6: bool, outer_ipv6: bool) -> Result<()> {
    let (mut client, mut server) = create_pair_with_outer(ipv6, outer_ipv6)?;
    let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let destination: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    client.peer = Peer::with_mtu(source, 40000, 1500)?;
    server.peer = Peer::with_mtu(destination, 9000, 1500)?;
    for endpoint in [&mut client, &mut server] {
        endpoint.transport.path_budget = PathBudget::new(1600, outer_ipv6)?;
        endpoint
            .peer
            .sockets
            .get_mut::<tcp::Socket>(endpoint.peer.tcp)
            .set_ack_delay(None);
    }
    server.transport.pmtu_fixture = Some(PathFixture::new(1499)?);
    server
        .peer
        .sockets
        .get_mut::<tcp::Socket>(server.peer.tcp)
        .listen((destination, 9000))?;
    client
        .peer
        .sockets
        .get_mut::<tcp::Socket>(client.peer.tcp)
        .connect(
            client.peer.interface.context(),
            (destination, 9000),
            (source, 40001),
        )?;
    client.transport.socket.connect(client.transport.remote)?;
    let queue = ErrorQueue::enable(&client.transport.socket)?;
    let addresses = [
        client.transport.socket.local_addr()?,
        server.transport.socket.local_addr()?,
    ];
    let limit = PathBudget::new(1400, outer_ipv6)?.inner_mtu();
    let result = transfer(&mut client, &mut server, limit, &queue);
    drop(queue);
    drop(client);
    drop(server);
    let cleanup = (|| -> Result<()> {
        for address in addresses {
            drop(UdpSocket::bind(address)?);
        }
        Ok(())
    })();
    match (result, cleanup) {
        (Err(primary), cleanup) => Err(primary.context(match cleanup {
            Ok(()) => "outer TCP sockets released".into(),
            Err(error) => format!("outer TCP cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => cleanup,
    }
}

fn transfer(
    client: &mut Endpoint,
    server: &mut Endpoint,
    limit: usize,
    queue: &ErrorQueue,
) -> Result<()> {
    let payload: Vec<_> = (0..8192).map(|index| (index % 251) as u8).collect();
    let reply = b"encrypted-response-after-fin";
    let mut sent = false;
    let mut resized = false;
    let mut replied = false;
    let mut request = Vec::with_capacity(payload.len());
    let mut response = Vec::with_capacity(reply.len());
    let mut original_endpoints = None;
    let mut retry_sequence = None;
    let mut observed_retry = false;
    let wall = Instant::now();
    for step in 0..1000 {
        let tick = step * 5;
        ensure!(
            wall.elapsed() < Duration::from_secs(6),
            "encrypted PMTU fixture exceeded wall deadline"
        );
        let now = Duration::from_millis(tick);
        client.peer.poll(tick as i64);
        if sent && !resized {
            ensure!(
                queue.read()?.is_none(),
                "outer queue was not empty before TCP send"
            );
            let packet = client
                .peer
                .device
                .outgoing
                .front()
                .ok_or_else(|| anyhow::anyhow!("missing oversized TCP output"))?;
            let frame = plain_tcp(packet)?.ok_or_else(|| anyhow::anyhow!("expected TCP"))?;
            let tcp = TcpPacket::new_checked(frame.payload)?;
            ensure!(!tcp.payload().is_empty() && packet.len() > limit);
            retry_sequence = Some(tcp.seq_number());
            let buffered = client
                .peer
                .sockets
                .get::<tcp::Socket>(client.peer.tcp)
                .send_queue();
            let error = match client.transport.pump(&mut client.peer, now) {
                Ok(()) => anyhow::bail!("oversized TCP ciphertext unexpectedly sent"),
                Err(error) => error,
            };
            let report = queue.diagnose(error)?;
            ensure!(report.mtu == 1400);
            let retired = apply_outer(
                &mut client.peer,
                &mut client.transport.path_budget,
                report.mtu,
                now,
            )?;
            ensure!(
                retired > 0,
                "fixture did not exercise queued TCP retirement"
            );
            ensure!(
                client
                    .peer
                    .sockets
                    .get::<tcp::Socket>(client.peer.tcp)
                    .send_queue()
                    == buffered,
                "sizing changed unacknowledged TCP bytes"
            );
            resized = true;
        }
        if resized {
            for packet in &client.peer.device.outgoing {
                ensure!(
                    packet.len() <= limit,
                    "resized encrypted sender exceeded advertised MTU"
                );
                if let Some(frame) = plain_tcp(packet)? {
                    let tcp = TcpPacket::new_checked(frame.payload)?;
                    if Some(tcp.seq_number()) == retry_sequence && !tcp.payload().is_empty() {
                        observed_retry = true;
                    }
                }
            }
        }
        client.transport.pump(&mut client.peer, now)?;
        server.peer.poll(tick as i64);
        drain(&mut server.peer, &mut request, payload.len())?;
        let socket = server.peer.sockets.get_mut::<tcp::Socket>(server.peer.tcp);
        if sent && !socket.may_recv() && socket.can_send() && !replied {
            ensure!(request == payload, "encrypted PMTU request/FIN changed");
            ensure!(socket.send_slice(reply)? == reply.len());
            socket.close();
            replied = true;
        }
        server.transport.pump(&mut server.peer, now)?;
        let socket = client.peer.sockets.get_mut::<tcp::Socket>(client.peer.tcp);
        if !sent
            && socket.state() == tcp::State::Established
            && server
                .peer
                .sockets
                .get::<tcp::Socket>(server.peer.tcp)
                .state()
                == tcp::State::Established
        {
            original_endpoints = Some((socket.local_endpoint(), socket.remote_endpoint()));
            ensure!(socket.send_slice(&payload)? == payload.len());
            socket.close();
            sent = true;
        }
        drain(&mut client.peer, &mut response, reply.len())?;
        if replied
            && !client
                .peer
                .sockets
                .get::<tcp::Socket>(client.peer.tcp)
                .may_recv()
        {
            // The final ACK has crossed the tunnel in this turn. Consume it
            // before retiring the fixture so peer completion is checked too.
            server.peer.poll(tick as i64);
            ensure!(
                server
                    .peer
                    .sockets
                    .get::<tcp::Socket>(server.peer.tcp)
                    .state()
                    == tcp::State::Closed,
                "encrypted PMTU peer did not complete final ACK"
            );
            ensure!(
                response == reply && observed_retry,
                "encrypted PMTU response or lost-sequence retry missing"
            );
            let socket = client.peer.sockets.get::<tcp::Socket>(client.peer.tcp);
            ensure!(
                Some((socket.local_endpoint(), socket.remote_endpoint())) == original_endpoints,
                "encrypted PMTU changed the connection tuple"
            );
            ensure!(
                resized
                    && client.transport.path_budget.outer_mtu() == 1400
                    && client.peer.device.capabilities().max_transmission_unit == limit
            );
            ensure!(
                queue.read()?.is_none(),
                "retry generated another outer error"
            );
            let path = server
                .transport
                .pmtu_fixture
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing controlled path"))?;
            ensure!(
                path.dropped == 0 && path.feedback_sent == 0,
                "outer recovery used inner feedback"
            );
            let inner_address: IpAddr = client.peer.interface.ip_addrs()[0].address().into();
            println!(
                "local outer TCP MTU: inner_ipv6={}, outer_ipv6={}, limit={limit}, delivered_bytes={}, inner_feedback={}, reductions=1",
                inner_address.is_ipv6(),
                client.transport.remote.is_ipv6(),
                request.len() + response.len(),
                path.feedback_sent
            );
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("encrypted PMTU connection did not complete")
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::socket::udp;

    fn pending_tcp(ipv6: bool) -> Peer {
        let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
            .parse()
            .unwrap();
        let remote: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
            .parse()
            .unwrap();
        let mut peer = Peer::with_mtu(source, 40000, 1500).unwrap();
        peer.sockets
            .get_mut::<tcp::Socket>(peer.tcp)
            .connect(peer.interface.context(), (remote, 9000), (source, 40001))
            .unwrap();
        peer.poll(0);
        assert!(!peer.device.outgoing.is_empty());
        peer
    }

    #[test]
    fn resizing_retires_valid_tcp_attempts_and_never_grows_the_device() {
        for ipv6 in [false, true] {
            for outer_ipv6 in [false, true] {
                let mut peer = pending_tcp(ipv6);
                let tuple = {
                    let socket = peer.sockets.get::<tcp::Socket>(peer.tcp);
                    (
                        socket.local_endpoint(),
                        socket.remote_endpoint(),
                        socket.state(),
                    )
                };
                let mut budget = PathBudget::new(1600, outer_ipv6).unwrap();
                let queued = peer.device.outgoing.len();
                assert_eq!(
                    apply_outer(&mut peer, &mut budget, 1400, Duration::ZERO).unwrap(),
                    queued
                );
                assert!(peer.device.outgoing.is_empty());
                assert_eq!(
                    peer.device.capabilities().max_transmission_unit,
                    if outer_ipv6 { 1312 } else { 1328 }
                );
                let socket = peer.sockets.get::<tcp::Socket>(peer.tcp);
                assert_eq!(
                    (
                        socket.local_endpoint(),
                        socket.remote_endpoint(),
                        socket.state()
                    ),
                    tuple
                );
                assert_eq!(
                    apply_outer(&mut peer, &mut budget, 1500, Duration::ZERO).unwrap(),
                    0
                );
                assert_eq!(budget.outer_mtu(), 1400);
            }
        }
        let mut peer = pending_tcp(false);
        peer.device.outgoing.clear();
        peer.device.configure_mtu(1280).unwrap();
        let mut budget = PathBudget::new(1600, false).unwrap();
        apply_outer(&mut peer, &mut budget, 1400, Duration::ZERO).unwrap();
        assert_eq!(peer.device.capabilities().max_transmission_unit, 1280);
    }

    #[test]
    fn invalid_pending_traffic_or_limits_leave_all_state_unchanged() {
        for ipv6 in [false, true] {
            for scenario in 0..8 {
                let mut peer = pending_tcp(ipv6);
                let mut budget = PathBudget::new(1600, false).unwrap();
                let mut mtu = 1400;
                let mut now = Duration::ZERO;
                match scenario {
                    0 => peer.device.inject(vec![0]).unwrap(),
                    1 => {
                        mtu = 1300;
                    }
                    2 => {
                        now = Duration::MAX;
                    }
                    3 => {
                        peer.device.outgoing.front_mut().unwrap().pop();
                    }
                    4 => {
                        let packet = peer.device.outgoing.front_mut().unwrap();
                        let last = packet.len() - 1;
                        packet[last] ^= 1;
                    }
                    5 => {
                        peer.sockets.get_mut::<tcp::Socket>(peer.tcp).abort();
                    }
                    6 => {
                        let mut foreign = pending_tcp(!ipv6);
                        peer.device
                            .outgoing
                            .push_back(foreign.device.outgoing.pop_front().unwrap());
                    }
                    7 => {
                        peer.sockets
                            .get_mut::<udp::Socket>(peer.udp)
                            .send_slice(
                                b"sample",
                                std::net::SocketAddr::new(
                                    if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
                                        .parse()
                                        .unwrap(),
                                    9000,
                                ),
                            )
                            .unwrap();
                        peer.poll(1);
                    }
                    _ => unreachable!(),
                }
                let queued = peer.device.outgoing.clone();
                let ingress = peer.device.has_ingress();
                assert!(
                    apply_outer(&mut peer, &mut budget, mtu, now).is_err(),
                    "scenario {scenario}"
                );
                assert_eq!(budget.outer_mtu(), 1600, "scenario {scenario}");
                assert_eq!(peer.device.capabilities().max_transmission_unit, 1500);
                assert_eq!(peer.device.outgoing, queued, "scenario {scenario}");
                assert_eq!(peer.device.has_ingress(), ingress);
            }
        }
    }
}
