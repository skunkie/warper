// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Active smoltcp sockets through two BoringTun peers over loopback UDP.

#[path = "../../packet_peer.rs"]
mod packet_peer;

use std::{
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use packet_peer::{MTU, PACKET_CAPACITY, Peer};
use smoltcp::socket::{tcp, udp};

const REQUEST: &[u8] = b"synthetic-tunnel-request";
const RESPONSE: &[u8] = b"synthetic-tunnel-response-after-fin";
const REKEY_DURATION: Duration = Duration::from_secs(135);

struct Transport {
    tunnel: Tunn,
    socket: UdpSocket,
    remote: SocketAddr,
    allowed_source: IpAddr,
    initiations: usize,
    encrypted_packets: usize,
}

impl Transport {
    fn send_result(&mut self, result: TunnResult<'_>, peer: &mut Peer) -> Result<bool> {
        match result {
            TunnResult::Done => Ok(false),
            TunnResult::Err(error) => bail!("WireGuard operation failed: {error:?}"),
            TunnResult::WriteToNetwork(packet) => {
                if packet.first() == Some(&1) {
                    self.initiations += 1;
                }
                ensure!(
                    self.socket.send_to(packet, self.remote)? == packet.len(),
                    "partial outer datagram"
                );
                self.encrypted_packets += 1;
                Ok(true)
            }
            TunnResult::WriteToTunnelV4(packet, source) => {
                ensure!(
                    IpAddr::V4(source) == self.allowed_source,
                    "unapproved inner IPv4 source"
                );
                peer.device.inject(packet.to_vec())?;
                Ok(true)
            }
            TunnResult::WriteToTunnelV6(packet, source) => {
                ensure!(
                    IpAddr::V6(source) == self.allowed_source,
                    "unapproved inner IPv6 source"
                );
                peer.device.inject(packet.to_vec())?;
                Ok(true)
            }
        }
    }

    fn pump(&mut self, peer: &mut Peer) -> Result<()> {
        let mut output = [0; MTU + 256];
        while let Some(packet) = peer.device.outgoing.pop_front() {
            let result = self.tunnel.encapsulate(&packet, &mut output);
            self.send_result(result, peer)?;
        }
        let result = self.tunnel.update_timers(&mut output);
        self.send_result(result, peer)?;
        let mut incoming = [0; MTU + 256];
        for _ in 0..PACKET_CAPACITY {
            let (length, source) = match self.socket.recv_from(&mut incoming) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };
            ensure!(source == self.remote, "unexpected outer peer");
            let result =
                self.tunnel
                    .decapsulate(Some(source.ip()), &incoming[..length], &mut output);
            self.send_result(result, peer)?;
            // BoringTun queues plaintext while handshaking; drain every network result.
            let mut drained = false;
            for _ in 0..PACKET_CAPACITY {
                let result = self.tunnel.decapsulate(None, &[], &mut output);
                if !self.send_result(result, peer)? {
                    drained = true;
                    break;
                }
            }
            ensure!(drained, "WireGuard drain exceeded packet budget");
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        arguments.is_empty() || arguments == ["--rekey"],
        "usage: wireguard-stack [--rekey]"
    );
    for ipv6 in [false, true] {
        probe(ipv6, Duration::ZERO)?;
        println!("PASS active TCP/UDP, empty datagram, FIN, IPv6={ipv6}; loopback BoringTun peer");
    }
    if !arguments.is_empty() {
        probe(false, REKEY_DURATION)?;
        println!("PASS sustained IPv4 UDP across timer-driven rekey");
    }
    Ok(())
}

fn probe(ipv6: bool, minimum_duration: Duration) -> Result<()> {
    let client_address: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let server_address: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    let mut client = Peer::new(client_address, 40000)?;
    let mut server = Peer::new(server_address, 9000)?;
    server
        .sockets
        .get_mut::<tcp::Socket>(server.tcp)
        .listen((server_address, 9000))?;
    client.sockets.get_mut::<tcp::Socket>(client.tcp).connect(
        client.interface.context(),
        (server_address, 9000),
        (client_address, 40001),
    )?;

    let client_socket = UdpSocket::bind("127.0.0.1:0")?;
    let server_socket = UdpSocket::bind("127.0.0.1:0")?;
    client_socket.set_nonblocking(true)?;
    server_socket.set_nonblocking(true)?;
    // Published synthetic test keys. Never use them with external peers.
    let client_key = StaticSecret::from([0x11; 32]);
    let server_key = StaticSecret::from([0x22; 32]);
    let mut client_transport = Transport {
        tunnel: Tunn::new(
            client_key.clone(),
            PublicKey::from(&server_key),
            None,
            Some(1),
            1,
            None,
        ),
        remote: server_socket.local_addr()?,
        socket: client_socket,
        allowed_source: server_address,
        initiations: 0,
        encrypted_packets: 0,
    };
    let mut server_transport = Transport {
        tunnel: Tunn::new(
            server_key,
            PublicKey::from(&client_key),
            None,
            Some(1),
            2,
            None,
        ),
        remote: client_transport.socket.local_addr()?,
        socket: server_socket,
        allowed_source: client_address,
        initiations: 0,
        encrypted_packets: 0,
    };
    let payloads = [vec![], vec![0x31], vec![0x72; 257]];
    for payload in &payloads {
        client
            .sockets
            .get_mut::<udp::Socket>(client.udp)
            .send_slice(payload, (server_address, 9000))?;
    }
    let start = Instant::now();
    let deadline = minimum_duration + Duration::from_secs(5);
    let mut next_heartbeat = Duration::from_secs(1);
    let mut sent = false;
    let mut request = Vec::new();
    let mut replied = false;
    let mut response = Vec::new();
    let mut udp_received = 0;
    let mut heartbeat_pending = false;
    loop {
        ensure!(
            start.elapsed() < deadline,
            "controlled tunnel exchange exceeded deadline"
        );
        let elapsed_ms = i64::try_from(start.elapsed().as_millis())?;
        client.poll(elapsed_ms);
        server.poll(elapsed_ms);
        client_transport.pump(&mut client)?;
        server_transport.pump(&mut server)?;

        let socket = client.sockets.get_mut::<tcp::Socket>(client.tcp);
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
            ensure!(response.len() <= RESPONSE.len(), "oversized TCP response");
        }
        let tcp_done = sent && !socket.may_recv();
        let socket = server.sockets.get_mut::<tcp::Socket>(server.tcp);
        if socket.can_recv() {
            socket.recv(|bytes| {
                request.extend_from_slice(bytes);
                (bytes.len(), ())
            })?;
            ensure!(request.len() <= REQUEST.len(), "oversized TCP request");
        }
        if !replied && !socket.may_recv() && socket.can_send() {
            ensure!(request == REQUEST, "TCP request/FIN changed");
            ensure!(
                socket.send_slice(RESPONSE)? == RESPONSE.len(),
                "partial response admission"
            );
            socket.close();
            replied = true;
        }

        let socket = server.sockets.get_mut::<udp::Socket>(server.udp);
        if socket.can_recv() {
            let (payload, metadata) = socket.recv()?;
            let payload = payload.to_vec();
            ensure!(
                metadata.endpoint == SocketAddr::new(client_address, 40000).into(),
                "UDP source changed"
            );
            socket.send_slice(&payload, metadata.endpoint)?;
        }
        let socket = client.sockets.get_mut::<udp::Socket>(client.udp);
        if socket.can_recv() {
            let (actual, metadata) = socket.recv()?;
            ensure!(
                metadata.endpoint == SocketAddr::new(server_address, 9000).into(),
                "UDP reply source changed"
            );
            if udp_received < payloads.len() {
                ensure!(
                    actual == payloads[udp_received],
                    "UDP boundary or empty datagram changed"
                );
                udp_received += 1;
            } else {
                ensure!(
                    heartbeat_pending && actual == b"heartbeat",
                    "unexpected heartbeat response"
                );
                heartbeat_pending = false;
            }
        }
        if udp_received == payloads.len() && !heartbeat_pending && start.elapsed() >= next_heartbeat
        {
            socket.send_slice(b"heartbeat", (server_address, 9000))?;
            heartbeat_pending = true;
            next_heartbeat = start.elapsed() + Duration::from_secs(1);
        }
        if tcp_done
            && udp_received == payloads.len()
            && !heartbeat_pending
            && start.elapsed() >= minimum_duration
        {
            ensure!(response == RESPONSE, "TCP response after FIN changed");
            ensure!(
                client_transport.encrypted_packets > 0 && server_transport.encrypted_packets > 0,
                "no outer traffic observed"
            );
            if minimum_duration >= REKEY_DURATION {
                ensure!(
                    client_transport.initiations + server_transport.initiations >= 2,
                    "no second handshake initiation observed"
                );
                // A new session must actually complete, not merely attempt a handshake.
                ensure!(
                    client_transport
                        .tunnel
                        .stats()
                        .0
                        .context("missing completed handshake")?
                        < Duration::from_secs(30),
                    "session did not rekey"
                );
            }
            // All stacks, sockets, and tunnel state are owned locally; no background tasks.
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_sockets_exchange_ipv4_and_ipv6_through_wireguard() {
        for ipv6 in [false, true] {
            probe(ipv6, Duration::ZERO).unwrap();
        }
    }
}
