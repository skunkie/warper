// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled shared-interface TCP and UDP behavior during an MTU reduction.

use anyhow::{Result, ensure};
use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    wire::TcpPacket,
};

use crate::packet_peer::{BYTE_CAPACITY, MTU, Peer};

pub(super) fn run(ipv6: bool) -> Result<()> {
    let (mut client, mut server) = crate::mtu_probe::peers(ipv6, 1500)?;
    let source = client.interface.ip_addrs()[0].address();
    let destination = server.interface.ip_addrs()[0].address();
    let client_second = client.sockets.add(tcp_socket());
    let server_second = server.sockets.add(tcp_socket());
    server
        .sockets
        .get_mut::<tcp::Socket>(server_second)
        .listen((destination, 9001))?;
    client
        .sockets
        .get_mut::<tcp::Socket>(client_second)
        .connect(
            client.interface.context(),
            (destination, 9001),
            (source, 40002),
        )?;
    for now in 20..60 {
        crate::mtu_probe::exchange(&mut client, &mut server, now)?;
    }
    ensure!(client.sockets.get::<tcp::Socket>(client_second).state() == tcp::State::Established);
    ensure!(server.sockets.get::<tcp::Socket>(server_second).state() == tcp::State::Established);
    let client_handles = [client.tcp, client_second];
    let server_handles = [server.tcp, server_second];
    let tuples = client_handles.map(|handle| {
        let socket = client.sockets.get::<tcp::Socket>(handle);
        (socket.local_endpoint(), socket.remote_endpoint())
    });
    let payloads = [vec![0x31; 4096], vec![0x73; 4096]];
    for (handle, payload) in client_handles.into_iter().zip(&payloads) {
        let socket = client.sockets.get_mut::<tcp::Socket>(handle);
        ensure!(socket.send_slice(payload)? == payload.len());
        socket.close();
    }
    client.poll(60);
    let mut lost = [false; 2];
    let mut dropped_packets = 0;
    let header_len = if ipv6 { 40 } else { 20 };
    while let Some(packet) = client.device.outgoing.pop_front() {
        dropped_packets += 1;
        let tcp = TcpPacket::new_checked(&packet[header_len..])?;
        if !tcp.payload().is_empty() && packet.len() > MTU {
            match tcp.dst_port() {
                9000 => lost[0] = true,
                9001 => lost[1] = true,
                _ => {}
            }
        }
    }
    ensure!(
        lost == [true, true],
        "both flows must have oversized traffic in flight"
    );
    crate::mtu_reduction::rebuild_interface(&mut client, MTU, 61)?;
    client
        .sockets
        .get_mut::<udp::Socket>(client.udp)
        .send_slice(b"shared-udp", (destination, 9000))?;
    let mut received = [Vec::new(), Vec::new()];
    let mut closed = [false; 2];
    let mut datagrams = 0;
    let mut completed_at = None;
    for now in 62..5000 {
        client.poll(now);
        while let Some(packet) = client.device.outgoing.pop_front() {
            ensure!(
                packet.len() <= MTU,
                "shared interface emitted oversized traffic"
            );
            server.device.inject(packet)?;
        }
        server.poll(now);
        for index in 0..2 {
            drain(
                &mut server,
                server_handles[index],
                &mut received[index],
                payloads[index].len(),
            )?;
            let socket = server.sockets.get_mut::<tcp::Socket>(server_handles[index]);
            if !socket.may_recv() && !closed[index] {
                ensure!(
                    received[index] == payloads[index],
                    "flow changed bytes before FIN"
                );
                socket.close();
                closed[index] = true;
            }
        }
        let socket = server.sockets.get_mut::<udp::Socket>(server.udp);
        while socket.can_recv() {
            let (packet, metadata) = socket.recv()?;
            ensure!(packet == b"shared-udp" && metadata.endpoint == (source, 40000).into());
            datagrams += 1;
            ensure!(datagrams <= 1, "UDP datagram was duplicated");
        }
        while let Some(packet) = server.device.outgoing.pop_front() {
            client.device.inject(packet)?;
        }
        if closed == [true, true]
            && datagrams == 1
            && client_handles
                .iter()
                .all(|handle| !client.sockets.get::<tcp::Socket>(*handle).may_recv())
        {
            for index in 0..2 {
                let socket = client.sockets.get::<tcp::Socket>(client_handles[index]);
                ensure!((socket.local_endpoint(), socket.remote_endpoint()) == tuples[index]);
            }
            let completed = *completed_at.get_or_insert(now);
            if now - completed >= 100 {
                println!(
                    "PASS shared interface MTU reduction: IPv6={ipv6}, tcp_flows=2, udp_datagrams=1, tcp_bytes=8192, dropped_packets={dropped_packets}, controlled_ms={}",
                    now - 61
                );
                return Ok(());
            }
        }
    }
    anyhow::bail!("shared MTU workload exceeded controlled step deadline")
}

fn tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
        tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
    )
}

fn drain(peer: &mut Peer, handle: SocketHandle, output: &mut Vec<u8>, limit: usize) -> Result<()> {
    let socket = peer.sockets.get_mut::<tcp::Socket>(handle);
    for _ in 0..2 {
        if !socket.can_recv() {
            break;
        }
        let accepted = socket.recv(|bytes| {
            if bytes.len() > limit.saturating_sub(output.len()) {
                return (0, false);
            }
            output.extend_from_slice(bytes);
            (bytes.len(), true)
        })?;
        ensure!(accepted, "flow exceeded its controlled receive budget");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_interface_preserves_two_tcp_flows_and_udp_after_reduction() {
        for ipv6 in [false, true] {
            super::run(ipv6).unwrap();
        }
    }
}
