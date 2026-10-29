// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Routed remote ICMP correlation for serialized encrypted UDP/TCP operations.

use crate::{
    Endpoint, create_client, kernel_peer,
    outer_errors::ErrorQueue,
    outer_owner::Owner,
    outer_remote::Reservation,
    packet_peer::Peer,
    path_mtu::{self, PathBudget},
};
use anyhow::{Result, ensure};
use boringtun::noise::TunnResult;
use smoltcp::socket::udp;
use std::{
    fs,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

pub(super) const OWNED_MESSAGE: &[u8] = b"owned-path-after-transition";

pub fn run(directory: Option<&Path>) -> Result<()> {
    kernel_peer::require_mapped_namespace()?;
    if let Some(directory) = directory {
        crate::router_path::validate_directory(directory)?;
    }
    for ipv6 in [false, true] {
        for outer_ipv6 in [false, true] {
            run_case(ipv6, outer_ipv6, directory)?;
            // Fresh synthetic sessions reuse one kernel peer identity. Space
            // initiations beyond its anti-flood window; this is fixture pacing.
            thread::sleep(Duration::from_millis(100));
            crate::router_tcp::run_case(ipv6, outer_ipv6)?;
            thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}

pub fn serve(directory: &Path) -> Result<()> {
    let (mut netlink, port) = kernel_peer::configure_with_port(9010)?;
    ensure!(port == 9010);
    let mut workers = kernel_peer::Workers::start_router(
        [
            UdpSocket::bind("10.66.66.10:9000")?,
            UdpSocket::bind("[fd66:66::10]:9000")?,
        ],
        [
            std::net::TcpListener::bind("10.66.66.10:9000")?,
            std::net::TcpListener::bind("[fd66:66::10]:9000")?,
        ],
        crate::router_tcp::payload(),
        crate::router_tcp::RESPONSE,
    )?;
    let result = (|| -> Result<()> {
        fs::write(directory.join("ready"), b"ready\n")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while !directory.join("stop").try_exists()? {
            ensure!(
                Instant::now() < deadline,
                "router peer control deadline exceeded"
            );
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    })();
    let cleanup = workers.finish();
    let report = match (result, cleanup) {
        (Err(primary), cleanup) => {
            return Err(primary.context(match cleanup {
                Ok(_) => "router peer workers joined".into(),
                Err(error) => format!("router peer worker cleanup also failed: {error}"),
            }));
        }
        (Ok(()), report) => report?,
    };
    ensure!(
        report.tcp == 4
            && report.udp == 12
            && report.bytes
                == 9944 + 8 * OWNED_MESSAGE.len() + 4 * (8192 + crate::router_tcp::RESPONSE.len()),
        "router peer did not verify exact TCP/UDP counts and bytes"
    );
    for address in ["10.66.66.10:9000", "[fd66:66::10]:9000"] {
        drop(UdpSocket::bind(address)?);
        drop(std::net::TcpListener::bind(address)?);
    }
    kernel_peer::verify_handshake(&mut netlink, false)?;
    println!(
        "PASS independent router peer: tcp={}, udp={}, application_bytes={}, workers_joined=true",
        report.tcp, report.udp, report.bytes
    );
    Ok(())
}

pub(super) fn reporter(outer_ipv6: bool) -> Result<IpAddr> {
    Ok(if outer_ipv6 {
        "fd77:1::1"
    } else {
        "198.18.0.1"
    }
    .parse()?)
}

pub(super) fn client(ipv6: bool, outer_ipv6: bool) -> Result<Endpoint> {
    let remote: SocketAddr = match (ipv6, outer_ipv6) {
        (false, false) => "198.19.0.2:9010",
        (true, false) => "198.19.0.2:9010",
        (false, true) => "[fd77:2::2]:9010",
        (true, true) => "[fd77:2::2]:9010",
    }
    .parse()?;
    let (_, transport) = create_client(ipv6, remote)?;
    let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    let mut client = Endpoint {
        peer: Peer::with_mtu(source, 40000, 1500)?,
        transport,
    };
    client.transport.socket = UdpSocket::bind(if outer_ipv6 {
        "[fd77:1::2]:0"
    } else {
        "198.18.0.2:0"
    })?;
    client.transport.socket.set_nonblocking(true)?;
    client.transport.path_budget = PathBudget::new(1600, outer_ipv6)?;
    client.transport.socket.connect(remote)?;
    Ok(client)
}

fn run_case(ipv6: bool, outer_ipv6: bool, directory: Option<&Path>) -> Result<()> {
    let mut client = client(ipv6, outer_ipv6)?;
    let reporter = reporter(outer_ipv6)?;
    let address = client.transport.socket.local_addr()?;
    let queue = ErrorQueue::enable_remote_probe(&client.transport.socket)?;
    let mut owner = Owner::new_remote_probe(
        SocketAddr::new(address.ip(), 0),
        client.transport.remote,
        1600,
    )?;
    let second_address = owner.local_addr()?;
    ensure!(
        second_address != address,
        "outer sockets must have distinct local tuples"
    );
    let result = exchange(&mut client, &queue, &mut owner, ipv6, reporter, directory);
    let final_address = owner.local_addr();
    drop(owner);
    drop(queue);
    drop(client);
    let cleanup = final_address.and_then(|final_address| {
        let mut addresses = vec![address, second_address, final_address];
        addresses.sort_unstable();
        addresses.dedup();
        addresses
            .into_iter()
            .map(UdpSocket::bind)
            .collect::<std::io::Result<Vec<_>>>()
            .map(drop)
    });
    match (result, cleanup) {
        (Err(primary), cleanup) => Err(primary.context(match cleanup {
            Ok(()) => "router MTU outer socket rebound".into(),
            Err(error) => format!("router MTU socket cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => Ok(cleanup?),
    }
}

fn exchange(
    client: &mut Endpoint,
    queue: &ErrorQueue,
    owner: &mut Owner,
    ipv6: bool,
    reporter: IpAddr,
    directory: Option<&Path>,
) -> Result<()> {
    let wall = Instant::now();
    let destination: SocketAddr = if ipv6 {
        "[fd66:66::10]:9000"
    } else {
        "10.66.66.10:9000"
    }
    .parse()?;
    send_udp(client, destination, &[0x31])?;
    receive_udp(client, destination, &[0x31], wall)?;
    overlapping_paths(client, destination, ipv6, wall)?;
    if let Some(directory) = directory {
        interrupted_path(client, destination, ipv6, wall, directory)?;
        route_change(client, destination, ipv6, wall, directory, "route")?;
        route_change(client, destination, ipv6, wall, directory, "rule")?;
        route_change(client, destination, ipv6, wall, directory, "address")?;
    }
    ensure!(
        queue.read()?.is_none(),
        "router MTU queue was not initially empty"
    );
    send_udp(
        client,
        destination,
        &vec![0x61; if ipv6 { 1352 } else { 1372 }],
    )?;
    client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
    ensure!(
        client.peer.device.outgoing.len() == 1,
        "router probe needs exactly one outgoing packet"
    );
    let packet = client
        .peer
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing router-bound packet"))?;
    ensure!(packet.len() == 1400);
    let mut encrypted = [0; 1536];
    let result = client.transport.tunnel.encapsulate(&packet, &mut encrypted);
    let TunnResult::WriteToNetwork(packet) = result else {
        anyhow::bail!("router MTU encryption was not immediately ready");
    };
    let encrypted_len = packet.len();
    let mut reservation = Reservation::default();
    reservation.reserve(
        packet,
        queue,
        reporter,
        wall.elapsed(),
        Duration::from_secs(1),
    )?;
    // The send must succeed: local EMSGSIZE is not remote-router evidence.
    client
        .transport
        .send_result(TunnResult::WriteToNetwork(packet), &mut client.peer)?;
    let stale = loop {
        if let Some(received) = queue.receive()? {
            ensure!(received.record.mtu == 1400, "unexpected remote path MTU");
            break received;
        }
        reservation.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    };
    send_udp(
        client,
        destination,
        &vec![0x63; if ipv6 { 1352 } else { 1372 }],
    )?;
    client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
    ensure!(
        client.peer.device.outgoing.len() == 1,
        "expected one later datagram"
    );
    let packet = client
        .peer
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing later router-bound packet"))?;
    ensure!(packet.len() == 1400);
    let result = client.transport.tunnel.encapsulate(&packet, &mut encrypted);
    let TunnResult::WriteToNetwork(packet) = result else {
        anyhow::bail!("later router MTU encryption was not immediately ready");
    };
    ensure!(
        packet[..16] != stale.prefix,
        "successive WireGuard headers repeated"
    );
    let old_sent_at = Instant::now();
    owner.send_reserved(packet, reporter, wall.elapsed())?;
    let mut wrong_owner = stale.clone();
    wrong_owner.prefix.copy_from_slice(&packet[..16]);
    let error = match owner.apply(&wrong_owner, wall.elapsed()) {
        Ok(_) => anyhow::bail!("wrong socket feedback matched a reservation"),
        Err(error) => error,
    };
    ensure!(
        error.downcast_ref::<crate::outer_remote::Error>()
            == Some(&crate::outer_remote::Error::Unmatched)
    );
    ensure!(
        owner.outer_mtu() == 1600,
        "wrong socket changed path budget"
    );
    let old_prefix: [u8; 16] = packet[..16].try_into()?;
    ensure!(
        owner.receive()?.is_none(),
        "old feedback arrived before retirement"
    );
    owner.cancel_reservation();
    let error = match owner.send_reserved(packet, reporter, wall.elapsed()) {
        Ok(()) => anyhow::bail!("repeated encrypted header was sent"),
        Err(error) => error,
    };
    ensure!(
        error.downcast_ref::<crate::outer_owner::Error>()
            == Some(&crate::outer_owner::Error::NonIncreasingCounter),
        "repeated encrypted header was not rejected"
    );
    send_udp(
        client,
        destination,
        &vec![0x65; if ipv6 { 1352 } else { 1372 }],
    )?;
    client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
    ensure!(
        client.peer.device.outgoing.len() == 1,
        "expected one distinct later datagram"
    );
    let later = client
        .peer
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing distinct later packet"))?;
    ensure!(later.len() == 1400);
    let result = client.transport.tunnel.encapsulate(&later, &mut encrypted);
    let TunnResult::WriteToNetwork(later) = result else {
        anyhow::bail!("distinct later encryption was not immediately ready");
    };
    ensure!(
        later[..16] != old_prefix,
        "distinct data reused the retired header"
    );
    owner.send_reserved(later, reporter, wall.elapsed())?;
    ensure!(
        owner.receive()?.is_none(),
        "retired feedback arrived before the later send completed"
    );
    let old_report = loop {
        if let Some(received) = owner.receive()? {
            ensure!(
                received.record.mtu == 1400,
                "unexpected owned remote path MTU"
            );
            ensure!(
                received.prefix == old_prefix,
                "expected delayed retired feedback first"
            );
            break received;
        }
        owner.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    };
    ensure!(
        old_sent_at.elapsed() >= Duration::from_millis(80),
        "router feedback did not experience the configured delay"
    );
    let error = match owner.apply(&old_report, wall.elapsed()) {
        Ok(_) => anyhow::bail!("retired feedback matched a later same-socket send"),
        Err(error) => error,
    };
    ensure!(
        error.downcast_ref::<crate::outer_remote::Error>()
            == Some(&crate::outer_remote::Error::Unmatched),
        "retired feedback matched a later same-socket send"
    );
    ensure!(
        owner.outer_mtu() == 1600,
        "retired feedback changed the same-socket budget"
    );
    loop {
        if let Some(received) = owner.receive()? {
            ensure!(
                received.record.mtu == 1400,
                "unexpected later remote path MTU"
            );
            ensure!(owner.apply(&received, wall.elapsed())?);
            break;
        }
        owner.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    }
    ensure!(owner.outer_mtu() == 1400, "later feedback did not commit");
    let remote = client.transport.remote;
    let mut alternate = remote;
    alternate.set_port(
        remote
            .port()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("invalid fixture peer port"))?,
    );
    owner.reconnect(alternate, 1600)?;
    owner.reconnect(remote, 1600)?;
    let error = match owner.apply(&old_report, wall.elapsed()) {
        Ok(_) => anyhow::bail!("retired feedback matched after peer transition"),
        Err(error) => error,
    };
    ensure!(
        error.downcast_ref::<crate::outer_remote::Error>()
            == Some(&crate::outer_remote::Error::MissingReservation)
    );
    send_udp(
        client,
        destination,
        &vec![0x64; if ipv6 { 1352 } else { 1372 }],
    )?;
    client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
    ensure!(
        client.peer.device.outgoing.len() == 1,
        "expected one post-transition datagram"
    );
    let packet = client
        .peer
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing post-transition packet"))?;
    ensure!(packet.len() == 1400);
    let result = client.transport.tunnel.encapsulate(&packet, &mut encrypted);
    let TunnResult::WriteToNetwork(packet) = result else {
        anyhow::bail!("post-transition encryption was not immediately ready");
    };
    let mut same_header_old_report = old_report.clone();
    same_header_old_report.prefix.copy_from_slice(&packet[..16]);
    owner.send_reserved(packet, reporter, wall.elapsed())?;
    let error = match owner.apply(&same_header_old_report, wall.elapsed()) {
        Ok(_) => anyhow::bail!("retired reader matched the new reservation"),
        Err(error) => error,
    };
    ensure!(
        error.downcast_ref::<crate::outer_remote::Error>()
            == Some(&crate::outer_remote::Error::Unmatched)
    );
    ensure!(
        owner.outer_mtu() == 1600,
        "retired reader changed the new path budget"
    );
    let error = match owner.apply(&old_report, wall.elapsed()) {
        Ok(_) => anyhow::bail!("retired feedback matched the new reservation"),
        Err(error) => error,
    };
    ensure!(
        error.downcast_ref::<crate::outer_remote::Error>()
            == Some(&crate::outer_remote::Error::Unmatched)
    );
    ensure!(
        owner.outer_mtu() == 1600,
        "retired feedback changed the new path budget"
    );
    let quoted_len = loop {
        if let Some(received) = owner.receive()? {
            ensure!(
                received.record.mtu == 1400,
                "unexpected post-transition remote path MTU"
            );
            ensure!(owner.apply(&received, wall.elapsed())?);
            break received.quoted_len;
        }
        owner.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    };
    ensure!(
        owner.outer_mtu() == 1400,
        "post-transition budget did not commit"
    );
    owned_exchange(client, owner, destination, reporter, wall)?;
    ensure!(
        reservation.apply(
            queue,
            &stale,
            &mut client.transport.path_budget,
            wall.elapsed()
        )?,
        "first socket did not commit its own report"
    );
    ensure!(client.transport.path_budget.outer_mtu() == 1400 && encrypted_len > 1400);
    send_udp(
        client,
        destination,
        &vec![0x62; if ipv6 { 1352 } else { 1372 }],
    )?;
    client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
    let error = match client.transport.pump(&mut client.peer, wall.elapsed()) {
        Ok(()) => anyhow::bail!("reduced outer budget accepted oversized operation"),
        Err(error) => error,
    };
    ensure!(error.downcast_ref::<path_mtu::Error>() == Some(&path_mtu::Error::PacketTooLarge));
    ensure!(
        queue.read()?.is_none(),
        "budget rejection reached the socket"
    );
    let safe = vec![0x53; if ipv6 { 1232 } else { 1252 }];
    send_udp(client, destination, &safe)?;
    receive_udp(client, destination, &safe, wall)?;
    ensure!(queue.read()?.is_none() && client.transport.staged_packets == 0);
    println!(
        "PASS remote router MTU: inner_ipv6={ipv6}, outer_ipv6={}, reported_mtu=1400, quoted_header_bytes={}, safe_bytes={}, same_socket_counter_rejected=true, same_socket_stale_rejected=true, retired_feedback_rejected=true, wrong_socket_rejected=true, peer_transition=true, owned_exchange=true, failed_payload_replayed=false",
        client.transport.remote.is_ipv6(),
        quoted_len.min(16),
        safe.len()
    );
    Ok(())
}

fn overlapping_paths(
    client: &mut Endpoint,
    destination: SocketAddr,
    ipv6: bool,
    wall: Instant,
) -> Result<()> {
    let outer_ipv6 = client.transport.remote.is_ipv6();
    let (first_local, second_local, first_reporter, second_reporter): (
        IpAddr,
        IpAddr,
        IpAddr,
        IpAddr,
    ) = if outer_ipv6 {
        (
            "fd77:1::2".parse()?,
            "fd77:3::2".parse()?,
            "fd77:1::1".parse()?,
            "fd77:3::1".parse()?,
        )
    } else {
        (
            "198.18.0.2".parse()?,
            "198.20.0.2".parse()?,
            "198.18.0.1".parse()?,
            "198.20.0.1".parse()?,
        )
    };
    let mut first = Owner::new_remote_probe(
        SocketAddr::new(first_local, 0),
        client.transport.remote,
        1600,
    )?;
    let mut second = Owner::new_remote_probe(
        SocketAddr::new(second_local, 0),
        client.transport.remote,
        1600,
    )?;
    let first_address = first.local_addr()?;
    let second_address = second.local_addr()?;
    for (owner, reporter, marker) in [
        (&mut first, first_reporter, 0x67),
        (&mut second, second_reporter, 0x69),
    ] {
        send_path_datagram(client, owner, destination, reporter, ipv6, marker, wall)?;
    }
    let first_report = loop {
        if let Some(report) = first.receive()? {
            break report;
        }
        first.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    };
    let second_report = loop {
        if let Some(report) = second.receive()? {
            break report;
        }
        second.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    };
    for (owner, report) in [(&mut first, &second_report), (&mut second, &first_report)] {
        let error = match owner.apply(report, wall.elapsed()) {
            Ok(_) => anyhow::bail!("another path's report was accepted"),
            Err(error) => error,
        };
        ensure!(
            error.downcast_ref::<crate::outer_remote::Error>()
                == Some(&crate::outer_remote::Error::Unmatched),
            "another path's report did not fail correlation"
        );
    }
    ensure!(
        first.outer_mtu() == 1600 && second.outer_mtu() == 1600,
        "cross-path report changed a budget"
    );
    ensure!(
        first.apply(&first_report, wall.elapsed())?,
        "first path did not reduce"
    );
    ensure!(
        first.outer_mtu() == 1400 && second.outer_mtu() == 1600,
        "first reduction changed the second path"
    );
    ensure!(
        second.apply(&second_report, wall.elapsed())?,
        "second path did not reduce"
    );
    ensure!(
        second.outer_mtu() == 1400,
        "second path did not commit its own budget"
    );
    drop((first, second));
    drop(UdpSocket::bind(first_address)?);
    drop(UdpSocket::bind(second_address)?);
    println!("PASS simultaneous routed path feedback: inner_ipv6={ipv6}, outer_ipv6={outer_ipv6}");
    Ok(())
}

fn interrupted_path(
    client: &mut Endpoint,
    destination: SocketAddr,
    ipv6: bool,
    wall: Instant,
    directory: &Path,
) -> Result<()> {
    let outer_ipv6 = client.transport.remote.is_ipv6();
    let (first_local, second_local, first_reporter, second_reporter): (
        IpAddr,
        IpAddr,
        IpAddr,
        IpAddr,
    ) = if outer_ipv6 {
        (
            "fd77:1::2".parse()?,
            "fd77:3::2".parse()?,
            "fd77:1::1".parse()?,
            "fd77:3::1".parse()?,
        )
    } else {
        (
            "198.18.0.2".parse()?,
            "198.20.0.2".parse()?,
            "198.18.0.1".parse()?,
            "198.20.0.1".parse()?,
        )
    };
    let mut first = Owner::new_remote_probe(
        SocketAddr::new(first_local, 0),
        client.transport.remote,
        1600,
    )?;
    let mut second = Owner::new_remote_probe(
        SocketAddr::new(second_local, 0),
        client.transport.remote,
        1600,
    )?;
    let monitor = crate::link_monitor::Monitor::new("client1")?;
    let first_address = first.local_addr()?;
    let second_address = second.local_addr()?;
    for (owner, reporter, marker) in [
        (&mut first, first_reporter, 0x71),
        (&mut second, second_reporter, 0x73),
    ] {
        send_path_datagram(client, owner, destination, reporter, ipv6, marker, wall)?;
    }
    let suffix = format!("{}{}", u8::from(ipv6), u8::from(outer_ipv6));
    crate::router_path::write_marker(directory, &format!("down.{suffix}.request"))?;
    wait_marker(directory, &format!("down.{suffix}.ready"))?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if crate::link_monitor::apply(&mut second, monitor.poll())? {
            break;
        }
        if Instant::now() >= deadline {
            second.invalidate_path();
            anyhow::bail!("link notification deadline exceeded");
        }
        thread::sleep(Duration::from_millis(1));
    }
    let error = match second.send_reserved(&[0; 64], second_reporter, wall.elapsed()) {
        Ok(()) => anyhow::bail!("invalidated path accepted a send"),
        Err(error) => error,
    };
    ensure!(
        error.downcast_ref::<crate::outer_owner::Error>()
            == Some(&crate::outer_owner::Error::Unavailable),
        "invalidated path did not reject the send"
    );
    let report = loop {
        if let Some(report) = first.receive()? {
            break report;
        }
        first.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    };
    ensure!(
        first.apply(&report, wall.elapsed())?,
        "unaffected path did not reduce"
    );
    ensure!(
        first.outer_mtu() == 1400 && second.outer_mtu() == 1600,
        "interruption changed the wrong budget"
    );
    crate::router_path::write_marker(directory, &format!("up.{suffix}.request"))?;
    wait_marker(directory, &format!("up.{suffix}.ready"))?;
    second.reconnect(client.transport.remote, 1600)?;
    send_path_datagram(
        client,
        &mut second,
        destination,
        second_reporter,
        ipv6,
        0x75,
        wall,
    )?;
    let report = loop {
        if let Some(report) = second.receive()? {
            break report;
        }
        second.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    };
    ensure!(
        second.apply(&report, wall.elapsed())?,
        "restored path did not reduce"
    );
    ensure!(first.outer_mtu() == 1400 && second.outer_mtu() == 1400);
    let restored_address = second.local_addr()?;
    drop((first, second));
    drop(UdpSocket::bind(first_address)?);
    drop(UdpSocket::bind(second_address)?);
    drop(UdpSocket::bind(restored_address)?);
    println!("PASS interrupted routed path: inner_ipv6={ipv6}, outer_ipv6={outer_ipv6}");
    Ok(())
}

fn route_change(
    client: &mut Endpoint,
    destination: SocketAddr,
    ipv6: bool,
    wall: Instant,
    directory: &Path,
    change: &str,
) -> Result<()> {
    let outer_ipv6 = client.transport.remote.is_ipv6();
    let (first_local, second_local, first_reporter, second_reporter): (
        IpAddr,
        IpAddr,
        IpAddr,
        IpAddr,
    ) = if outer_ipv6 {
        (
            "fd77:1::2".parse()?,
            "fd77:3::2".parse()?,
            "fd77:1::1".parse()?,
            "fd77:3::1".parse()?,
        )
    } else {
        (
            "198.18.0.2".parse()?,
            "198.20.0.2".parse()?,
            "198.18.0.1".parse()?,
            "198.20.0.1".parse()?,
        )
    };
    let mut first = Owner::new_remote_probe(
        SocketAddr::new(first_local, 0),
        client.transport.remote,
        1600,
    )?;
    let mut second = Owner::new_remote_probe(
        SocketAddr::new(second_local, 0),
        client.transport.remote,
        1600,
    )?;
    let initial = [first.local_addr()?, second.local_addr()?];
    let monitor = match change {
        "address" => crate::link_monitor::Monitor::addresses()?,
        _ => crate::link_monitor::Monitor::routes()?,
    };
    for (owner, reporter, marker) in [
        (&mut first, first_reporter, 0x77),
        (&mut second, second_reporter, 0x79),
    ] {
        send_path_datagram(client, owner, destination, reporter, ipv6, marker, wall)?;
    }
    ensure!(
        !monitor.poll()?,
        "route notification was already pending before the fixture change"
    );
    let suffix = format!("{}{}", u8::from(ipv6), u8::from(outer_ipv6));
    crate::router_path::write_marker(directory, &format!("{change}.down.{suffix}.request"))?;
    wait_marker(directory, &format!("{change}.down.{suffix}.ready"))?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let notification = monitor.poll();
        let first_result = crate::link_monitor::apply(&mut first, notification);
        let second_result = crate::link_monitor::apply(&mut second, notification);
        let first_changed = first_result?;
        let second_changed = second_result?;
        ensure!(
            first_changed == second_changed,
            "route notification was applied inconsistently"
        );
        if first_changed {
            break;
        }
        if Instant::now() >= deadline {
            first.invalidate_path();
            second.invalidate_path();
            anyhow::bail!("route notification deadline exceeded");
        }
        thread::sleep(Duration::from_millis(1));
    }
    for (owner, reporter) in [(&mut first, first_reporter), (&mut second, second_reporter)] {
        let error = match owner.send_reserved(&[0; 64], reporter, wall.elapsed()) {
            Ok(()) => anyhow::bail!("route-invalidated path accepted a send"),
            Err(error) => error,
        };
        ensure!(
            error.downcast_ref::<crate::outer_owner::Error>()
                == Some(&crate::outer_owner::Error::Unavailable)
        );
    }
    crate::router_path::write_marker(directory, &format!("{change}.up.{suffix}.request"))?;
    wait_marker(directory, &format!("{change}.up.{suffix}.ready"))?;
    first.reconnect_verified(client.transport.remote, 1600, verify_candidate_path)?;
    second.reconnect_verified(client.transport.remote, 1600, verify_candidate_path)?;
    let restored = [first.local_addr()?, second.local_addr()?];
    for (owner, reporter, marker) in [
        (&mut first, first_reporter, 0x7b),
        (&mut second, second_reporter, 0x7d),
    ] {
        send_path_datagram(client, owner, destination, reporter, ipv6, marker, wall)?;
    }
    for owner in [&mut first, &mut second] {
        let report = loop {
            if let Some(report) = owner.receive()? {
                break report;
            }
            owner.advance(wall.elapsed())?;
            thread::sleep(Duration::from_millis(1));
        };
        ensure!(
            owner.apply(&report, wall.elapsed())?,
            "restored path did not reduce"
        );
    }
    drop((first, second));
    for address in initial.into_iter().chain(restored) {
        drop(UdpSocket::bind(address)?);
    }
    println!("PASS routed {change} change: inner_ipv6={ipv6}, outer_ipv6={outer_ipv6}");
    Ok(())
}

fn verify_candidate_path(local: SocketAddr, remote: SocketAddr) -> Result<()> {
    let checker =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/verify_router_paths.py");
    let status = Command::new("timeout")
        .arg("2s")
        .arg("python3")
        .arg(checker)
        .arg("--socket")
        .arg(local.ip().to_string())
        .arg(local.port().to_string())
        .arg(remote.ip().to_string())
        .arg(remote.port().to_string())
        .status()?;
    if !status.success() {
        return Err(crate::outer_owner::Error::PathVerification.into());
    }
    Ok(())
}

fn send_path_datagram(
    client: &mut Endpoint,
    owner: &mut Owner,
    destination: SocketAddr,
    reporter: IpAddr,
    ipv6: bool,
    marker: u8,
    wall: Instant,
) -> Result<()> {
    send_udp(
        client,
        destination,
        &vec![marker; if ipv6 { 1352 } else { 1372 }],
    )?;
    client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
    ensure!(
        client.peer.device.outgoing.len() == 1,
        "expected one path-specific datagram"
    );
    let inner = client
        .peer
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing path datagram"))?;
    let mut encrypted = [0; 1536];
    let TunnResult::WriteToNetwork(packet) =
        client.transport.tunnel.encapsulate(&inner, &mut encrypted)
    else {
        anyhow::bail!("path encryption was not immediately ready");
    };
    owner.send_reserved(packet, reporter, wall.elapsed())
}

fn wait_marker(directory: &Path, name: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !directory.join(name).try_exists()? {
        ensure!(
            Instant::now() < deadline,
            "router fixture control deadline exceeded"
        );
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

fn owned_exchange(
    client: &mut Endpoint,
    owner: &mut Owner,
    destination: SocketAddr,
    reporter: IpAddr,
    wall: Instant,
) -> Result<()> {
    send_udp(client, destination, OWNED_MESSAGE)?;
    client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
    ensure!(
        client.peer.device.outgoing.len() == 1,
        "expected one owned application datagram"
    );
    let packet = client
        .peer
        .device
        .outgoing
        .pop_front()
        .ok_or_else(|| anyhow::anyhow!("missing owned application packet"))?;
    let mut encrypted = [0; 1536];
    let result = client.transport.tunnel.encapsulate(&packet, &mut encrypted);
    let TunnResult::WriteToNetwork(packet) = result else {
        anyhow::bail!("owned application encryption was not immediately ready");
    };
    owner.send_reserved(packet, reporter, wall.elapsed())?;
    let mut incoming = [0; 1536];
    loop {
        ensure!(
            wall.elapsed() < Duration::from_secs(4),
            "owned application deadline exceeded"
        );
        if let Some(length) = owner.receive_datagram(&mut incoming)? {
            let result = client.transport.tunnel.decapsulate(
                Some(client.transport.remote.ip()),
                &incoming[..length],
                &mut encrypted,
            );
            ensure!(
                matches!(
                    result,
                    TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..)
                ),
                "owned response was not a decrypted inner packet"
            );
            client.transport.receive_result(result, &mut client.peer)?;
            client.peer.poll(i64::try_from(wall.elapsed().as_millis())?);
            let socket = client.peer.sockets.get_mut::<udp::Socket>(client.peer.udp);
            ensure!(
                socket.can_recv(),
                "owned response did not reach the application"
            );
            let (payload, metadata) = socket.recv()?;
            ensure!(
                payload == OWNED_MESSAGE
                    && metadata.endpoint.addr == destination.ip().into()
                    && metadata.endpoint.port == destination.port(),
                "owned application content or tuple changed"
            );
            ensure!(!socket.can_recv(), "extra owned application datagram");
            ensure!(
                owner.receive()?.is_none(),
                "owned safe message generated outer error"
            );
            owner.cancel_reservation();
            return Ok(());
        }
        owner.advance(wall.elapsed())?;
        thread::sleep(Duration::from_millis(1));
    }
}

fn send_udp(client: &mut Endpoint, destination: SocketAddr, payload: &[u8]) -> Result<()> {
    client
        .peer
        .sockets
        .get_mut::<udp::Socket>(client.peer.udp)
        .send_slice(payload, destination)?;
    Ok(())
}

fn receive_udp(
    client: &mut Endpoint,
    destination: SocketAddr,
    expected: &[u8],
    wall: Instant,
) -> Result<()> {
    for _ in 0..2000 {
        ensure!(
            wall.elapsed() < Duration::from_secs(4),
            "routed UDP deadline exceeded"
        );
        let now = wall.elapsed();
        client.peer.poll(i64::try_from(now.as_millis())?);
        client.transport.pump(&mut client.peer, now)?;
        let socket = client.peer.sockets.get_mut::<udp::Socket>(client.peer.udp);
        if socket.can_recv() {
            let (payload, metadata) = socket.recv()?;
            ensure!(
                payload == expected
                    && metadata.endpoint.addr == destination.ip().into()
                    && metadata.endpoint.port == destination.port(),
                "router peer UDP content or tuple changed"
            );
            ensure!(!socket.can_recv(), "extra router UDP datagram");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("routed UDP step deadline exceeded")
}
