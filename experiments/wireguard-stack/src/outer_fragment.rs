// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Linux-only encrypted UDP fragmentation feasibility on private loopback.

use std::{net::UdpSocket, time::Duration};

use anyhow::{Result, ensure};
use rustix::net::sockopt::{self as options, Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};

use crate::{create_pair_with_outer, run_client};

pub fn run() -> Result<()> {
    crate::kernel_peer::require_mapped_namespace()?;
    for inner_ipv6 in [false, true] {
        for outer_ipv6 in [false, true] {
            run_case(inner_ipv6, outer_ipv6, true)?;
        }
    }
    for outer_ipv6 in [false, true] {
        run_case(outer_ipv6, outer_ipv6, false)?;
    }
    Ok(())
}

fn run_case(inner_ipv6: bool, outer_ipv6: bool, fragment: bool) -> Result<()> {
    let (mut client, mut server) = create_pair_with_outer(inner_ipv6, outer_ipv6)?;
    let addresses = [
        client.transport.socket.local_addr()?,
        server.transport.socket.local_addr()?,
    ];
    let result = (|| -> Result<()> {
        for transport in [&mut client.transport, &mut server.transport] {
            transport.socket.connect(transport.remote)?;
            let mtu = if outer_ipv6 {
                options::ipv6_mtu(&transport.socket)?
            } else {
                options::ip_mtu(&transport.socket)?
            };
            ensure!(
                mtu == 1280,
                "outer fragment fixture requires a 1280-byte loopback path"
            );
            configure_fragmentation(&transport.socket, outer_ipv6, fragment)?;
        }
        let exchange = run_client(
            inner_ipv6,
            Duration::ZERO,
            &mut client.peer,
            &mut client.transport,
            Some((&mut server.peer, &mut server.transport)),
        );
        if fragment {
            exchange?;
            println!(
                "PASS encrypted outer fragmentation: inner_ipv6={inner_ipv6}, outer_ipv6={outer_ipv6}"
            );
        } else {
            let error = match exchange {
                Ok(()) => {
                    anyhow::bail!("unfragmented oversized encrypted data unexpectedly succeeded")
                }
                Err(error) => error,
            };
            ensure!(
                error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error)
                    == Some(rustix::io::Errno::MSGSIZE.raw_os_error()),
                "unfragmented negative control did not return the kernel size error: {error}"
            );
            println!("PASS outer no-fragment negative control: outer_ipv6={outer_ipv6}");
        }
        Ok(())
    })();
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
            Ok(()) => "fragment fixture sockets released".into(),
            Err(error) => format!("fragment fixture socket cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => cleanup,
    }
}

fn configure_fragmentation(socket: &UdpSocket, ipv6: bool, enabled: bool) -> Result<()> {
    if ipv6 {
        let mode = if enabled {
            Ipv6PathMtuDiscovery::DONT
        } else {
            Ipv6PathMtuDiscovery::DO
        };
        options::set_ipv6_mtu_discover(socket, mode)?;
        ensure!(options::ipv6_mtu_discover(socket)? == mode);
    } else {
        let mode = if enabled {
            Ipv4PathMtuDiscovery::DONT
        } else {
            Ipv4PathMtuDiscovery::DO
        };
        options::set_ip_mtu_discover(socket, mode)?;
        ensure!(options::ip_mtu_discover(socket)? == mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_ipv6_option_on_ipv4_socket() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(configure_fragmentation(&socket, true, true).is_err());
    }

    #[test]
    fn configures_fragmentation_on_controlled_loopback_sockets() {
        for ipv6 in [false, true] {
            let address: std::net::SocketAddr = if ipv6 {
                (Ipv6Addr::LOCALHOST, 0).into()
            } else {
                (Ipv4Addr::LOCALHOST, 0).into()
            };
            let socket = UdpSocket::bind(address).unwrap();
            for enabled in [false, true] {
                configure_fragmentation(&socket, ipv6, enabled).unwrap();
            }
        }
    }
}
