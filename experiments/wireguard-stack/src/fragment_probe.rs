// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Authenticated, encrypted fragment input through active UDP sockets.

use std::{
    net::SocketAddr,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use smoltcp::socket::udp;

use crate::{Endpoint, create_pair_with_outer, fragment_fixture::split, reassembly};

pub fn run_probe(ipv6: bool) -> Result<()> {
    for outer_ipv6 in [false, true] {
        run_with_outer(ipv6, outer_ipv6)?;
    }
    Ok(())
}

fn run_with_outer(ipv6: bool, outer_ipv6: bool) -> Result<()> {
    for order in [[0, 1], [1, 0]] {
        let (mut client, mut server) = create_pair_with_outer(ipv6, outer_ipv6)?;
        let now = warm_up(&mut client, &mut server)?;
        let payload = vec![0x53; if ipv6 { 1232 } else { 1252 }];
        exchange(&mut client, &mut server, &payload, order, now, 42)?;
        exchange(
            &mut server,
            &mut client,
            &payload,
            order,
            now + Duration::from_millis(3),
            43,
        )?;
        for endpoint in [&client, &server] {
            ensure!(endpoint.transport.reassembly.statistics().completed == 1);
            ensure!(endpoint.transport.reassembly.next_deadline().is_none());
        }
        release_pair(client, server)?;
    }
    expiry_and_overlap(ipv6, outer_ipv6)?;
    Ok(())
}

pub(super) fn warm_up(client: &mut Endpoint, server: &mut Endpoint) -> Result<Duration> {
    let destination = address(server);
    client
        .peer
        .sockets
        .get_mut::<udp::Socket>(client.peer.udp)
        .send_slice(b"prime", destination)?;
    for tick in 0..2000 {
        let now = Duration::from_millis(tick);
        for endpoint in [&mut *client, &mut *server] {
            endpoint.peer.poll(tick as i64);
            endpoint.transport.pump(&mut endpoint.peer, now)?;
        }
        server.peer.poll(tick as i64);
        let socket = server.peer.sockets.get_mut::<udp::Socket>(server.peer.udp);
        if socket.can_recv() {
            let (payload, _) = socket.recv()?;
            ensure!(payload == b"prime");
            return Ok(now + Duration::from_millis(1));
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("fragment fixture handshake deadline expired")
}

pub(super) fn address(endpoint: &Endpoint) -> SocketAddr {
    let ip = endpoint.peer.interface.ip_addrs()[0].address();
    let port = endpoint
        .peer
        .sockets
        .get::<udp::Socket>(endpoint.peer.udp)
        .endpoint()
        .port;
    SocketAddr::new(ip.into(), port)
}

pub(super) fn fragments(
    sender: &mut Endpoint,
    destination: SocketAddr,
    payload: &[u8],
    now: Duration,
    id: u32,
) -> Result<[Vec<u8>; 2]> {
    sender
        .peer
        .sockets
        .get_mut::<udp::Socket>(sender.peer.udp)
        .send_slice(payload, destination)?;
    sender.peer.poll(now.as_millis() as i64);
    let packet = sender
        .peer
        .device
        .outgoing
        .pop_front()
        .context("missing UDP fixture packet")?;
    ensure!(sender.peer.device.outgoing.is_empty());
    split(&packet, id, 8)
}

fn transmit(
    sender: &mut Endpoint,
    receiver: &mut Endpoint,
    packet: &[u8],
    now: Duration,
) -> Result<()> {
    sender.peer.device.outgoing.push_back(packet.to_vec());
    sender.transport.pump(&mut sender.peer, now)?;
    let previous_received = receiver.transport.received_inner;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        crate::wait_for_outer(&receiver.transport.socket, deadline)?;
        receiver.transport.pump(&mut receiver.peer, now)?;
        receiver.peer.poll(now.as_millis() as i64);
        if receiver.transport.received_inner != previous_received {
            return Ok(());
        }
    }
}

fn exchange(
    sender: &mut Endpoint,
    receiver: &mut Endpoint,
    payload: &[u8],
    order: [usize; 2],
    now: Duration,
    id: u32,
) -> Result<()> {
    let source = address(sender);
    let packets = fragments(sender, address(receiver), payload, now, id)?;
    transmit(sender, receiver, &packets[order[0]], now)?;
    ensure!(
        !receiver
            .peer
            .sockets
            .get::<udp::Socket>(receiver.peer.udp)
            .can_recv(),
        "incomplete encrypted datagram reached UDP"
    );
    transmit(
        sender,
        receiver,
        &packets[order[1]],
        now + Duration::from_millis(1),
    )?;
    let (actual, metadata) = receiver
        .peer
        .sockets
        .get_mut::<udp::Socket>(receiver.peer.udp)
        .recv()?;
    ensure!(
        actual == payload && metadata.endpoint == source.into(),
        "encrypted fragment tuple or payload changed"
    );
    Ok(())
}

fn expiry_and_overlap(ipv6: bool, outer_ipv6: bool) -> Result<()> {
    let (mut client, mut server) = create_pair_with_outer(ipv6, outer_ipv6)?;
    let now = warm_up(&mut client, &mut server)?;
    let packets = fragments(&mut client, address(&server), &[0x53; 200], now, 44)?;
    transmit(&mut client, &mut server, &packets[0], now)?;
    let expires = server
        .transport
        .reassembly
        .next_deadline()
        .context("missing fragment deadline")?;
    server.transport.pump(&mut server.peer, expires)?;
    ensure!(server.transport.reassembly.statistics().timed_out == 1);
    transmit(&mut client, &mut server, &packets[1], expires)?;
    ensure!(
        !server
            .peer
            .sockets
            .get::<udp::Socket>(server.peer.udp)
            .can_recv()
    );
    // A fresh authenticated ciphertext containing the same inner fragment must
    // reach overlap validation rather than WireGuard's replay filter.
    let error = transmit(&mut client, &mut server, &packets[1], expires)
        .err()
        .context("overlapping encrypted fragment was accepted")?;
    ensure!(error.downcast_ref::<reassembly::Error>() == Some(&reassembly::Error::Overlap));
    release_pair(client, server)
}

fn release_pair(client: Endpoint, server: Endpoint) -> Result<()> {
    let addresses = [
        client.transport.socket.local_addr()?,
        server.transport.socket.local_addr()?,
    ];
    drop(client);
    drop(server);
    for address in addresses {
        drop(std::net::UdpSocket::bind(address)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MTU;

    #[test]
    fn concurrent_fragments_with_shared_deadline_make_progress() {
        for ipv6 in [false, true] {
            let (mut client, mut server) = crate::create_pair(ipv6).unwrap();
            let now = warm_up(&mut client, &mut server).unwrap();
            let destination = address(&server);
            let first = fragments(&mut client, destination, &[0x31; 200], now, 45).unwrap();
            let second = fragments(&mut client, destination, &[0x52; 200], now, 46).unwrap();
            transmit(&mut client, &mut server, &first[0], now).unwrap();
            let deadline = server.transport.reassembly.next_deadline();
            transmit(&mut client, &mut server, &second[0], now).unwrap();
            assert_eq!(server.transport.reassembly.next_deadline(), deadline);
            transmit(&mut client, &mut server, &first[1], now).unwrap();
            assert_eq!(server.transport.reassembly.next_deadline(), deadline);
            transmit(&mut client, &mut server, &second[1], now).unwrap();
            let socket = server.peer.sockets.get_mut::<udp::Socket>(server.peer.udp);
            for expected in [[0x31; 200], [0x52; 200]] {
                let (payload, _) = socket.recv().unwrap();
                assert_eq!(payload, expected);
            }
            assert!(server.transport.reassembly.next_deadline().is_none());
            release_pair(client, server).unwrap();
        }
    }

    #[test]
    fn encrypted_fragment_waits_for_delayed_outer_delivery() {
        for ipv6 in [false, true] {
            let (mut client, mut server) = crate::create_pair(ipv6).unwrap();
            let now = warm_up(&mut client, &mut server).unwrap();
            let packets = fragments(&mut client, address(&server), &[0x53; 200], now, 45).unwrap();
            let relay = std::net::UdpSocket::bind(crate::loopback_address(false)).unwrap();
            relay
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let relay_address = relay.local_addr().unwrap();
            let original_client = client.transport.socket.local_addr().unwrap();
            let server_address = server.transport.socket.local_addr().unwrap();
            let mut encrypted = [0; MTU + 256];
            let result = client.transport.tunnel.encapsulate(&[], &mut encrypted);
            assert!(matches!(&result, crate::TunnResult::WriteToNetwork(_)));
            let keepalive = if let crate::TunnResult::WriteToNetwork(bytes) = result {
                bytes.to_vec()
            } else {
                return;
            };
            assert_eq!(keepalive.len(), 32);
            client.transport.remote = relay_address;
            server.transport.remote = relay_address;
            let worker = thread::spawn(move || -> std::io::Result<(usize, SocketAddr)> {
                let mut packet = [0; MTU + 256];
                let (length, source) = relay.recv_from(&mut packet)?;
                relay.send_to(&keepalive, server_address)?;
                thread::sleep(Duration::from_millis(20));
                let sent = relay.send_to(&packet[..length], server_address)?;
                Ok((sent, source))
            });
            let result = transmit(&mut client, &mut server, &packets[0], now);
            let (sent, source) = worker.join().unwrap().unwrap();
            result.unwrap();
            assert!(sent > 32);
            assert_eq!(source, original_client);
            assert!(server.transport.reassembly.next_deadline().is_some());
            release_pair(client, server).unwrap();
        }
    }

    #[test]
    fn encrypted_fragments_preserve_datagrams_and_release_partial_state() {
        for ipv6 in [false, true] {
            run_probe(ipv6).unwrap();
        }
    }

    #[test]
    fn foreign_inner_destination_cannot_reserve_fragment_state() {
        for ipv6 in [false, true] {
            let (mut client, mut server) = crate::create_pair(ipv6).unwrap();
            let now = warm_up(&mut client, &mut server).unwrap();
            let destination = if ipv6 {
                "[fd66:66::11]:9000"
            } else {
                "10.66.66.11:9000"
            }
            .parse()
            .unwrap();
            let packets = fragments(&mut client, destination, &[0x53; 200], now, 45).unwrap();
            let error = transmit(&mut client, &mut server, &packets[0], now).unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::TransportFailure>(),
                Some(&crate::TransportFailure::InnerDestination)
            );
            assert!(server.transport.reassembly.next_deadline().is_none());
            release_pair(client, server).unwrap();
        }
    }
}
