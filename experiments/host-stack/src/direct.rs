// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Direct AnyIP candidate with fixed admission slots and controlled echo handlers.

use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result, ensure};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage},
    socket::{tcp, udp},
    time::Instant,
    wire::{HardwareAddress, IpCidr, Ipv4Packet, Ipv6Packet},
};

use crate::packet_peer::{BYTE_CAPACITY, PacketDevice, Peer};

const TRANSFER_BYTES: usize = 65536;
const STEP_LIMIT: i64 = 10000;
const HANDLER_COUNT: usize = 2;
const TRAILERS: [&[u8]; HANDLER_COUNT] = [b"backend-zero", b"backend-one"];

struct Handler {
    destination: SocketAddr,
    tcp: SocketHandle,
    udp: SocketHandle,
    source: Option<SocketAddr>,
    replied_fin: bool,
    udp_datagrams: usize,
}

struct DirectHost {
    device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    handlers: [Handler; HANDLER_COUNT],
    cancelled: bool,
}

impl DirectHost {
    fn new(destinations: [SocketAddr; HANDLER_COUNT]) -> Result<Self> {
        let mut device = PacketDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 77;
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        let v4: IpAddr = "10.66.66.254".parse()?;
        let v6: IpAddr = "fd66:66::ffff".parse()?;
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(v4.into(), 32))
                .expect("fixed IPv4 address slot");
            addresses
                .push(IpCidr::new(v6.into(), 128))
                .expect("fixed IPv6 address slot");
        });
        interface
            .routes_mut()
            .add_default_ipv4_route("10.66.66.254".parse()?)?;
        interface
            .routes_mut()
            .add_default_ipv6_route("fd66:66::ffff".parse()?)?;
        interface.set_any_ip(true);
        // Fixed socket storage: no SYN or accepted-flow queue can grow it.
        let storage: Vec<_> = (0..HANDLER_COUNT * 2)
            .map(|_| SocketStorage::EMPTY)
            .collect();
        let mut sockets = SocketSet::new(storage);
        let mut create_handler = |destination| -> Result<Handler> {
            let mut tcp = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
                tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
            );
            tcp.listen(destination)?;
            let tcp = sockets.add(tcp);
            let mut udp = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; BYTE_CAPACITY]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; BYTE_CAPACITY]),
            );
            udp.bind(destination)?;
            let udp = sockets.add(udp);
            Ok(Handler {
                destination,
                tcp,
                udp,
                source: None,
                replied_fin: false,
                udp_datagrams: 0,
            })
        };
        let handlers = [
            create_handler(destinations[0])?,
            create_handler(destinations[1])?,
        ];
        Ok(Self {
            device,
            interface,
            sockets,
            handlers,
            cancelled: false,
        })
    }

    fn inject(&mut self, packet: Vec<u8>) -> io::Result<()> {
        if self.cancelled {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.device.inject(packet)
    }

    fn poll(&mut self, elapsed_ms: i64) -> Result<()> {
        if self.cancelled {
            return Ok(());
        }
        self.interface.poll(
            Instant::from_millis(elapsed_ms),
            &mut self.device,
            &mut self.sockets,
        );
        for (index, handler) in self.handlers.iter_mut().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(handler.tcp);
            if let (Some(source), Some(destination)) =
                (socket.remote_endpoint(), socket.local_endpoint())
            {
                ensure!(
                    destination == handler.destination.into(),
                    "TCP original destination changed"
                );
                let source = SocketAddr::new(source.addr.into(), source.port);
                ensure!(
                    handler.source.is_none_or(|existing| existing == source),
                    "occupied TCP slot changed owner"
                );
                handler.source = Some(source);
            }
            let available = socket.send_capacity() - socket.send_queue();
            if socket.can_recv() && socket.can_send() && available > 0 {
                let mut buffer = [0; 1024];
                let limit = available.min(buffer.len());
                let received = socket.recv_slice(&mut buffer[..limit])?;
                ensure!(
                    socket.send_slice(&buffer[..received])? == received,
                    "partial echo admission"
                );
            }
            if handler.source.is_some()
                && !handler.replied_fin
                && !socket.may_recv()
                && socket.recv_queue() == 0
                && socket.can_send()
                && socket.send_capacity() - socket.send_queue() >= TRAILERS[index].len()
            {
                ensure!(
                    socket.send_slice(TRAILERS[index])? == TRAILERS[index].len(),
                    "partial trailer admission"
                );
                socket.close();
                handler.replied_fin = true;
            }
            let socket = self.sockets.get_mut::<udp::Socket>(handler.udp);
            if socket.can_recv() && socket.can_send() {
                let (payload, metadata) = socket.recv()?;
                ensure!(
                    metadata.local_address == Some(handler.destination.ip().into()),
                    "UDP original destination changed"
                );
                // A single bounded datagram is copied so recv's borrow ends before send.
                let payload = payload.to_vec();
                socket.send_slice(&payload, metadata)?;
                handler.udp_datagrams += 1;
            }
        }
        Ok(())
    }

    fn cancel(&mut self) {
        self.cancelled = true;
        for handler in &self.handlers {
            self.sockets.get_mut::<tcp::Socket>(handler.tcp).abort();
            self.sockets.get_mut::<udp::Socket>(handler.udp).close();
        }
        // Drop queued packets, including their retained capacities.
        self.device = PacketDevice::default();
    }
}

pub fn run_probe(ipv6: bool) -> Result<()> {
    let destinations = destinations(ipv6)?;
    let mut host = DirectHost::new(destinations)?;
    let mut peers = [new_peer(ipv6, 2)?, new_peer(ipv6, 3)?];
    let payloads = [vec![], vec![0x11], vec![0x22; 257], vec![0x33; 1000]];
    for (peer, destination) in peers.iter_mut().zip(destinations) {
        let source = peer.sockets.get::<udp::Socket>(peer.udp).endpoint();
        peer.sockets.get_mut::<tcp::Socket>(peer.tcp).connect(
            peer.interface.context(),
            destination,
            source,
        )?;
        for payload in &payloads {
            peer.sockets
                .get_mut::<udp::Socket>(peer.udp)
                .send_slice(payload, destination)?;
        }
    }
    let mut sent = [0; HANDLER_COUNT];
    let mut received = [0; HANDLER_COUNT];
    let mut udp_received = [0; HANDLER_COUNT];
    for step in 0..STEP_LIMIT {
        exchange(&mut host, &mut peers, step, true)?;
        let mut done = true;
        for (index, peer) in peers.iter_mut().enumerate() {
            let socket = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
            if sent[index] < TRANSFER_BYTES && socket.can_send() {
                let payload = [0x41 + index as u8; 1024];
                sent[index] += socket
                    .send_slice(&payload[..(TRANSFER_BYTES - sent[index]).min(payload.len())])?;
                if sent[index] == TRANSFER_BYTES {
                    socket.close();
                }
            }
            if socket.can_recv() {
                let correct = socket.recv(|bytes| {
                    let correct = bytes.iter().enumerate().all(|(offset, byte)| {
                        let position = received[index] + offset;
                        if position < TRANSFER_BYTES {
                            *byte == 0x41 + index as u8
                        } else {
                            TRAILERS[index].get(position - TRANSFER_BYTES) == Some(byte)
                        }
                    });
                    received[index] += bytes.len();
                    (bytes.len(), correct)
                })?;
                ensure!(correct, "TCP response crossed backend or changed bytes");
            }
            done &= sent[index] == TRANSFER_BYTES
                && received[index] == TRANSFER_BYTES + TRAILERS[index].len()
                && !socket.may_recv();
            let socket = peer.sockets.get_mut::<udp::Socket>(peer.udp);
            if socket.can_recv() {
                let (actual, metadata) = socket.recv()?;
                ensure!(
                    payloads
                        .get(udp_received[index])
                        .is_some_and(|expected| actual == expected),
                    "UDP message boundary changed"
                );
                ensure!(
                    metadata.endpoint == destinations[index].into(),
                    "UDP reply source crossed backend"
                );
                udp_received[index] += 1;
            }
            done &= udp_received[index] == payloads.len();
        }
        if done {
            for (index, handler) in host.handlers.iter().enumerate() {
                ensure!(
                    handler.source == Some(source_address(ipv6, 2 + index as u8)?),
                    "TCP original source changed"
                );
                ensure!(
                    handler.udp_datagrams == payloads.len(),
                    "UDP selected handler count changed"
                );
            }
            host.cancel();
            return Ok(());
        }
    }
    anyhow::bail!("direct host exchange exceeded controlled deadline")
}

pub fn verify_admission_and_cancellation(ipv6: bool) -> Result<()> {
    let destination = destinations(ipv6)?[0];
    let mut host = DirectHost::new(destinations(ipv6)?)?;
    let mut peers = [new_peer(ipv6, 2)?, new_peer(ipv6, 3)?];
    peers[0]
        .sockets
        .get_mut::<tcp::Socket>(peers[0].tcp)
        .connect(
            peers[0].interface.context(),
            destination,
            source_address(ipv6, 2)?,
        )?;
    let mut second_started = false;
    let mut rejected = false;
    for step in 0..STEP_LIMIT {
        exchange(&mut host, &mut peers, step, true)?;
        if !second_started
            && peers[0].sockets.get::<tcp::Socket>(peers[0].tcp).state() == tcp::State::Established
        {
            peers[1]
                .sockets
                .get_mut::<tcp::Socket>(peers[1].tcp)
                .connect(
                    peers[1].interface.context(),
                    destination,
                    source_address(ipv6, 3)?,
                )?;
            second_started = true;
        }
        if second_started
            && peers[1].sockets.get::<tcp::Socket>(peers[1].tcp).state() == tcp::State::Closed
        {
            ensure!(
                peers[0].sockets.get::<tcp::Socket>(peers[0].tcp).state()
                    == tcp::State::Established,
                "excess flow displaced admitted flow"
            );
            rejected = true;
            break;
        }
    }
    ensure!(rejected, "occupied slot did not reject excess TCP flow");
    host.cancel();
    ensure!(
        host.inject(vec![0; 40])
            .is_err_and(|error| error.kind() == io::ErrorKind::Interrupted),
        "cancelled host accepted more packets"
    );
    host.poll(STEP_LIMIT)?;
    ensure!(
        host.device.outgoing.is_empty(),
        "cancelled host emitted queued packets"
    );
    for handler in &host.handlers {
        ensure!(
            !host.sockets.get::<tcp::Socket>(handler.tcp).is_open(),
            "cancel left TCP open"
        );
        ensure!(
            !host.sockets.get::<udp::Socket>(handler.udp).is_open(),
            "cancel left UDP open"
        );
    }
    host.cancel();
    Ok(())
}

pub fn verify_stalled_reader(ipv6: bool) -> Result<()> {
    let destination = destinations(ipv6)?[0];
    let mut host = DirectHost::new(destinations(ipv6)?)?;
    let mut peers = [new_peer(ipv6, 2)?, new_peer(ipv6, 3)?];
    peers[0]
        .sockets
        .get_mut::<tcp::Socket>(peers[0].tcp)
        .connect(
            peers[0].interface.context(),
            destination,
            source_address(ipv6, 2)?,
        )?;
    let mut sent = 0;
    for step in 0..5000 {
        // Deliberately stop application reads while still driving packets/timers.
        exchange(&mut host, &mut peers, step, false)?;
        let socket = peers[0].sockets.get_mut::<tcp::Socket>(peers[0].tcp);
        if socket.can_send() {
            sent += socket.send_slice(&[0x51; 1024])?;
        }
        ensure!(
            socket.send_queue() <= BYTE_CAPACITY,
            "stalled sender exceeded its buffer"
        );
        let socket = host.sockets.get::<tcp::Socket>(host.handlers[0].tcp);
        ensure!(
            socket.recv_queue() <= BYTE_CAPACITY,
            "stalled receiver exceeded its buffer"
        );
    }
    ensure!(
        host.sockets
            .get::<tcp::Socket>(host.handlers[0].tcp)
            .recv_queue()
            == BYTE_CAPACITY,
        "stalled reader did not fill the receive window"
    );
    ensure!(
        sent <= BYTE_CAPACITY * 2,
        "zero-window backpressure failed to bound sender admission"
    );
    host.cancel();
    Ok(())
}

fn destinations(ipv6: bool) -> Result<[SocketAddr; HANDLER_COUNT]> {
    Ok(if ipv6 {
        ["[fd66:66::10]:9000".parse()?, "[fd66:66::11]:9001".parse()?]
    } else {
        ["10.66.66.10:9000".parse()?, "10.66.66.11:9001".parse()?]
    })
}

fn source_address(ipv6: bool, suffix: u8) -> Result<SocketAddr> {
    let address: IpAddr = if ipv6 {
        format!("fd66:66::{suffix}").parse()?
    } else {
        format!("10.66.66.{suffix}").parse()?
    };
    Ok(SocketAddr::new(address, 40000))
}

fn new_peer(ipv6: bool, suffix: u8) -> Result<Peer> {
    let source = source_address(ipv6, suffix)?;
    Peer::new(source.ip(), source.port())
}

fn exchange(
    host: &mut DirectHost,
    peers: &mut [Peer; HANDLER_COUNT],
    step: i64,
    serve_handlers: bool,
) -> Result<()> {
    for peer in &mut *peers {
        peer.poll(step);
        while let Some(packet) = peer.device.outgoing.pop_front() {
            host.inject(packet)?;
        }
    }
    if serve_handlers {
        host.poll(step)?;
    } else {
        host.interface.poll(
            Instant::from_millis(step),
            &mut host.device,
            &mut host.sockets,
        );
    }
    while let Some(packet) = host.device.outgoing.pop_front() {
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

    #[test]
    fn two_handlers_preserve_empty_datagrams_large_tcp_and_half_close() {
        for ipv6 in [false, true] {
            run_probe(ipv6).unwrap();
        }
    }

    #[test]
    fn admission_rejects_excess_flow_without_displacement_and_cancel_is_idempotent() {
        for ipv6 in [false, true] {
            verify_admission_and_cancellation(ipv6).unwrap();
        }
    }

    #[test]
    fn stalled_reader_bounds_windows_and_backpressures_sender() {
        for ipv6 in [false, true] {
            verify_stalled_reader(ipv6).unwrap();
        }
    }
}
