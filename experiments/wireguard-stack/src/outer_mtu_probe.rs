// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real local EMSGSIZE feedback for encrypted UDP in a private MTU fixture.

use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use rustix::net::sockopt as options;
use smoltcp::socket::udp;

use crate::{Endpoint, create_pair_with_outer, outer_errors::ErrorQueue};

pub fn run() -> Result<()> {
    crate::kernel_peer::require_mapped_namespace()?;
    for ipv6 in [false, true] {
        for outer_ipv6 in [false, true] {
            run_case(ipv6, outer_ipv6)?;
            crate::outer_tcp_probe::run_case(ipv6, outer_ipv6)?;
        }
    }
    Ok(())
}

fn run_case(ipv6: bool, outer_ipv6: bool) -> Result<()> {
    let (mut client, mut server) = create_pair_with_outer(ipv6, outer_ipv6)?;
    client.transport.socket.connect(client.transport.remote)?;
    let queue = ErrorQueue::enable(&client.transport.socket)?;
    let mtu = if outer_ipv6 {
        options::ipv6_mtu(&client.transport.socket)?
    } else {
        options::ip_mtu(&client.transport.socket)?
    };
    ensure!(
        mtu == 1400,
        "outer probe requires isolated loopback MTU 1400"
    );
    let addresses = [
        client.transport.socket.local_addr()?,
        server.transport.socket.local_addr()?,
    ];
    let result = exchange(ipv6, outer_ipv6, &mut client, &mut server, &queue);
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
            Ok(()) => "outer MTU sockets released".into(),
            Err(error) => format!("outer MTU cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => cleanup,
    }
}

fn exchange(
    ipv6: bool,
    outer_ipv6: bool,
    client: &mut Endpoint,
    server: &mut Endpoint,
    queue: &ErrorQueue,
) -> Result<()> {
    let mut now = crate::fragment_probe::warm_up(client, server)?;
    ensure!(
        queue.read()?.is_none(),
        "outer error queue was not empty before the operation"
    );
    let source = client.peer.interface.ip_addrs()[0].address();
    let destination = crate::fragment_probe::address(server);
    // A controlled 1400-byte inner packet passes the declared 1500 outer
    // budget, but its 1432-byte ciphertext exceeds the kernel's 1400 path.
    client.peer = crate::packet_peer::Peer::with_mtu(source.into(), 40000, 1500)?;
    client
        .peer
        .sockets
        .get_mut::<udp::Socket>(client.peer.udp)
        .send_slice(&vec![0x61; if ipv6 { 1352 } else { 1372 }], destination)?;
    client.peer.poll(now.as_millis() as i64);
    let error = match client.transport.pump(&mut client.peer, now) {
        Ok(()) => anyhow::bail!("oversized encrypted datagram unexpectedly sent"),
        Err(error) => error,
    };
    let report = queue.diagnose(error)?;
    ensure!(report.mtu == 1400, "kernel outer MTU report changed");
    ensure!(client.transport.path_budget.reduce(report.mtu)?);
    ensure!(client.transport.path_budget.outer_mtu() == 1400);
    ensure!(matches!(
        client.transport.path_budget.check_datagram(1432),
        Err(crate::path_mtu::Error::PacketTooLarge)
    ));
    // Exercise the updated transport guard with a distinct new message. It
    // must fail before send, leaving the kernel error queue empty.
    client
        .peer
        .sockets
        .get_mut::<udp::Socket>(client.peer.udp)
        .send_slice(&vec![0x62; if ipv6 { 1352 } else { 1372 }], destination)?;
    client.peer.poll(now.as_millis() as i64);
    let guard_error = match client.transport.pump(&mut client.peer, now) {
        Ok(()) => anyhow::bail!("updated outer budget allowed oversized encrypted data"),
        Err(error) => error,
    };
    ensure!(
        guard_error.downcast_ref::<crate::path_mtu::Error>()
            == Some(&crate::path_mtu::Error::PacketTooLarge)
    );
    ensure!(
        queue.read()?.is_none(),
        "budget rejection reached the kernel send path"
    );
    server.transport.pump(&mut server.peer, now)?;
    server.peer.poll(now.as_millis() as i64);
    ensure!(
        !server
            .peer
            .sockets
            .get::<udp::Socket>(server.peer.udp)
            .can_recv(),
        "failed UDP was delivered"
    );
    ensure!(
        client.transport.staged_packets == 0,
        "failed encrypted send retained staging state"
    );
    let payload = vec![0x53; if ipv6 { 1232 } else { 1252 }];
    client
        .peer
        .sockets
        .get_mut::<udp::Socket>(client.peer.udp)
        .send_slice(&payload, destination)?;
    let wall = Instant::now();
    for _ in 0..2000 {
        ensure!(
            wall.elapsed() < Duration::from_secs(3),
            "safe outer transfer exceeded deadline"
        );
        now += Duration::from_millis(1);
        client.peer.poll(now.as_millis() as i64);
        client.transport.pump(&mut client.peer, now)?;
        server.peer.poll(now.as_millis() as i64);
        server.transport.pump(&mut server.peer, now)?;
        let socket = server.peer.sockets.get_mut::<udp::Socket>(server.peer.udp);
        if socket.can_recv() {
            let (actual, metadata) = socket.recv()?;
            ensure!(
                actual == payload
                    && metadata.endpoint == SocketAddr::new(source.into(), 40000).into(),
                "safe UDP changed or failed UDP was replayed"
            );
            ensure!(
                !socket.can_recv(),
                "outer fixture delivered an extra datagram"
            );
            ensure!(queue.read()?.is_none(), "safe send left an error queued");
            println!(
                "PASS local outer MTU: inner_ipv6={ipv6}, outer_ipv6={outer_ipv6}, reported_mtu={}, safe_bytes={}, no failed-payload replay",
                report.mtu,
                payload.len()
            );
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("safe UDP did not arrive after local outer MTU reduction")
}
