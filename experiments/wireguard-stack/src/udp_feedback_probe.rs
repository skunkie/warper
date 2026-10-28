// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real encrypted port-unreachable feedback from a closed UDP port.

use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use smoltcp::socket::udp;

use crate::{Endpoint, create_pair_with_outer, udp_feedback};

pub fn run_probe(ipv6: bool) -> Result<()> {
    for outer_ipv6 in [false, true] {
        let (client, server) = create_pair_with_outer(ipv6, outer_ipv6)?;
        run_owned(ipv6, client, Some(server), Duration::from_secs(10))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run_kernel(ipv6: bool, remote: SocketAddr) -> Result<()> {
    let (peer, transport) = crate::create_client(ipv6, remote)?;
    run_owned(
        ipv6,
        Endpoint { peer, transport },
        None,
        Duration::from_secs(10),
    )
}

fn run_owned(
    ipv6: bool,
    mut client: Endpoint,
    mut server: Option<Endpoint>,
    timeout: Duration,
) -> Result<()> {
    let client_address = client.transport.socket.local_addr()?;
    let server_address = server
        .as_ref()
        .map(|server| server.transport.socket.local_addr())
        .transpose()?;
    let result = drive(ipv6, &mut client, server.as_mut(), timeout);
    drop(client);
    drop(server);
    let cleanup = (|| -> Result<()> {
        drop(UdpSocket::bind(client_address)?);
        if let Some(address) = server_address {
            drop(UdpSocket::bind(address)?);
        }
        Ok(())
    })();
    match (result, cleanup) {
        (Err(primary), cleanup) => Err(primary.context(match cleanup {
            Ok(()) => "UDP feedback sockets released".into(),
            Err(error) => format!("UDP feedback cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => cleanup,
    }
}

fn drive(
    ipv6: bool,
    client: &mut Endpoint,
    mut server: Option<&mut Endpoint>,
    timeout: Duration,
) -> Result<()> {
    let destination: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    client
        .peer
        .sockets
        .get_mut::<udp::Socket>(client.peer.udp)
        .send_slice(&[0x53; 257], SocketAddr::new(destination, 9001))?;
    client.peer.poll(0);
    let packet = client
        .peer
        .device
        .outgoing
        .front()
        .context("no reserved UDP packet emitted")?;
    client.transport.watch_udp(packet)?;
    let start = Instant::now();
    while start.elapsed() < timeout {
        let now = start.elapsed();
        client.peer.poll(i64::try_from(now.as_millis())?);
        if let Err(error) = client.transport.pump(&mut client.peer, now) {
            if error.downcast_ref::<udp_feedback::Error>()
                == Some(&udp_feedback::Error::PortUnreachable)
            {
                ensure!(
                    client.transport.udp_feedback.is_none(),
                    "matched feedback retained reservation"
                );
                ensure!(
                    !client
                        .peer
                        .sockets
                        .get::<udp::Socket>(client.peer.udp)
                        .can_recv(),
                    "error became application payload"
                );
                return Ok(());
            }
            return Err(error);
        }
        if let Some(server) = server.as_mut() {
            server.peer.poll(i64::try_from(now.as_millis())?);
            server.transport.pump(&mut server.peer, now)?;
        }
        thread::sleep(Duration::from_millis(1));
    }
    Err(udp_feedback::Error::DeadlineExpired.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_encrypted_port_errors_propagate_for_all_inner_and_outer_families() {
        for ipv6 in [false, true] {
            run_probe(ipv6).unwrap();
        }
    }

    #[test]
    fn deadline_failure_preserves_typed_error_and_releases_reserved_sockets() {
        for ipv6 in [false, true] {
            let (client, server) = create_pair_with_outer(ipv6, ipv6).unwrap();
            let addresses = [
                client.transport.socket.local_addr().unwrap(),
                server.transport.socket.local_addr().unwrap(),
            ];
            let error = run_owned(ipv6, client, Some(server), Duration::ZERO).unwrap_err();
            assert_eq!(
                error.downcast_ref::<udp_feedback::Error>(),
                Some(&udp_feedback::Error::DeadlineExpired)
            );
            for address in addresses {
                UdpSocket::bind(address).unwrap();
            }
        }
    }
}
