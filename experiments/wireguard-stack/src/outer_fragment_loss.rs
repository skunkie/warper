// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled outer-fragment loss against an independent kernel peer.

use crate::{
    RESPONSE, create_client,
    kernel_peer::{self, Workers},
    loopback_address,
};
use anyhow::{Context, Result, ensure};
use smoltcp::socket::{tcp, udp};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

pub fn run() -> Result<()> {
    let (mut netlink, port) = kernel_peer::configure()?;
    for inner in [false, true] {
        for outer in [false, true] {
            let mut endpoint = loopback_address(outer);
            endpoint.set_port(port);
            exchange(inner, outer, endpoint)?;
            kernel_peer::verify_handshake(&mut netlink, false)?;
            println!("PASS fragmented outer loss: inner_ipv6={inner}, outer_ipv6={outer}");
        }
    }
    Ok(())
}

fn control(expected: u8) -> Result<()> {
    let stdin = io::stdin();
    let mut fds = [rustix::event::PollFd::new(
        &stdin,
        rustix::event::PollFlags::IN,
    )];
    let timeout = rustix::time::Timespec {
        tv_sec: 10,
        tv_nsec: 0,
    };
    ensure!(
        rustix::event::poll(&mut fds, Some(&timeout))? > 0,
        "fragment loss control deadline exceeded"
    );
    let mut byte = [0];
    stdin.lock().read_exact(&mut byte)?;
    ensure!(
        byte[0] == expected,
        "unexpected fragment loss control message"
    );
    Ok(())
}

fn exchange(inner: bool, outer: bool, endpoint: std::net::SocketAddr) -> Result<()> {
    let server: IpAddr = if inner { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    let local: IpAddr = if inner { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let request = vec![0x61; 8192];
    let (mut peer, mut transport) = create_client(inner, endpoint)?;
    let address = transport.socket.local_addr()?;
    transport.socket.connect(endpoint)?;
    let mtu = if outer {
        rustix::net::sockopt::ipv6_mtu(&transport.socket)?
    } else {
        rustix::net::sockopt::ip_mtu(&transport.socket)?
    };
    ensure!(
        mtu == 1280,
        "fragment loss fixture requires a 1280-byte loopback path"
    );
    crate::outer_fragment::configure_fragmentation(&transport.socket, outer, true)?;
    let mut workers = Workers::start_fragment_loss(server, request.clone())?;
    let result = (|| -> Result<()> {
        peer.sockets.get_mut::<tcp::Socket>(peer.tcp).connect(
            peer.interface.context(),
            (server, 9000),
            (local, 40001),
        )?;
        peer.sockets
            .get_mut::<udp::Socket>(peer.udp)
            .send_slice(&[0x31], (server, 9000))?;
        let start = Instant::now();
        let mut warm = false;
        let mut phase = 0;
        let mut loss_since = None;
        let mut sequence = None;
        let mut retried = false;
        let mut datagram_emitted = false;
        let mut heartbeat = false;
        let mut response = Vec::new();
        let mut complete_since = None;
        loop {
            ensure!(
                start.elapsed() < Duration::from_secs(30),
                "fragment loss exchange deadline exceeded"
            );
            peer.poll(i64::try_from(start.elapsed().as_millis())?);
            if phase == 1 {
                for packet in &peer.device.outgoing {
                    if is_loss_datagram(packet, inner)? {
                        datagram_emitted = true;
                    }
                    if let Some(frame) = crate::pmtu_probe::plain_tcp(packet)? {
                        let segment = smoltcp::wire::TcpPacket::new_checked(frame.payload)?;
                        if !segment.payload().is_empty() {
                            match sequence {
                                None => sequence = Some(segment.seq_number()),
                                Some(first) if first == segment.seq_number() => retried = true,
                                _ => {}
                            }
                        }
                    }
                }
            }
            transport.pump(&mut peer, start.elapsed())?;
            let tcp = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
            if tcp.can_recv() {
                tcp.recv(|bytes| {
                    response.extend_from_slice(bytes);
                    (bytes.len(), ())
                })?;
            }
            ensure!(response.len() <= RESPONSE.len(), "oversized response");
            let tcp_done = phase == 2 && !tcp.may_recv();
            let udp = peer.sockets.get_mut::<udp::Socket>(peer.udp);
            if udp.can_recv() {
                let (payload, metadata) = udp.recv()?;
                ensure!(
                    metadata.endpoint == (server, 9000).into(),
                    "UDP reply source changed"
                );
                if !warm {
                    ensure!(payload == [0x31], "warmup datagram changed");
                    warm = true;
                } else {
                    ensure!(
                        phase == 2 && payload == b"heartbeat" && !heartbeat,
                        "unexpected UDP datagram"
                    );
                    heartbeat = true;
                }
            }
            if phase == 0 && warm && peer.sockets.get::<tcp::Socket>(peer.tcp).can_send() {
                println!("READY {} {}", u8::from(inner), u8::from(outer));
                io::stdout().flush()?;
                control(b'D')?;
                let tcp = peer.sockets.get_mut::<tcp::Socket>(peer.tcp);
                ensure!(
                    tcp.send_slice(&request)? == request.len(),
                    "partial TCP request admission"
                );
                tcp.close();
                peer.sockets
                    .get_mut::<udp::Socket>(peer.udp)
                    .send_slice(&vec![0x53; if inner { 1232 } else { 1252 }], (server, 9000))?;
                loss_since = Some(Instant::now());
                phase = 1;
            } else if phase == 1
                && retried
                && datagram_emitted
                && loss_since.context("missing loss start")?.elapsed()
                    >= Duration::from_millis(1200)
            {
                println!("RELEASE {} {}", u8::from(inner), u8::from(outer));
                io::stdout().flush()?;
                control(b'R')?;
                peer.sockets
                    .get_mut::<udp::Socket>(peer.udp)
                    .send_slice(b"heartbeat", (server, 9000))?;
                phase = 2;
            } else if tcp_done && heartbeat {
                ensure!(response == RESPONSE, "TCP response changed");
                let since = complete_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_millis(100) {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    })();
    let cleanup = workers.finish();
    drop(transport);
    drop(peer);
    let rebound = UdpSocket::bind(address).map(drop);
    if let Err(primary) = result {
        let worker_status = match cleanup {
            Ok(_) => "workers joined".to_owned(),
            Err(error) => format!("worker cleanup also failed: {error:#}"),
        };
        let socket_status = match rebound {
            Ok(()) => "outer socket rebound".to_owned(),
            Err(error) => format!("socket cleanup also failed: {error}"),
        };
        return Err(primary.context(format!("{worker_status}; {socket_status}")));
    }
    let report = cleanup?;
    rebound?;
    ensure!(
        report.tcp == 1
            && report.udp == 2
            && report.bytes == request.len() + RESPONSE.len() + 2 * (1 + b"heartbeat".len()),
        "kernel peer observed unexpected traffic"
    );
    Ok(())
}

fn is_loss_datagram(packet: &[u8], ipv6: bool) -> Result<bool> {
    use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
    let (protocol, payload) = if ipv6 {
        let ip = Ipv6Packet::new_checked(packet)?;
        (ip.next_header(), ip.payload())
    } else {
        let ip = Ipv4Packet::new_checked(packet)?;
        (ip.next_header(), ip.payload())
    };
    if protocol != IpProtocol::Udp || packet.len() != 1280 {
        return Ok(false);
    }
    let udp = UdpPacket::new_checked(payload)?;
    Ok(udp.src_port() == 40000
        && udp.dst_port() == 9000
        && udp.payload().iter().all(|byte| *byte == 0x53))
}
