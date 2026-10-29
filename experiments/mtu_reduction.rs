// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Synchronous experimental raw-IP interface replacement retaining socket state.

use crate::packet_peer::{PacketDevice, Peer};
use anyhow::{Context, Result};
use smoltcp::{
    iface::{Config, Interface},
    phy::Device,
    time::Instant,
    wire::HardwareAddress,
};
use std::time::Duration;

pub fn apply_feedback(
    peer: &mut Peer,
    tracker: &mut crate::pmtu_feedback::Tracker,
    packet: &[u8],
    now: Duration,
    random_seed: u64,
) -> Result<bool> {
    let Some(mtu) = tracker.reduction(packet, now)? else {
        return Ok(false);
    };
    if mtu >= peer.device.capabilities().max_transmission_unit {
        return Ok(false);
    }
    rebuild_interface(peer, mtu, i64::try_from(now.as_millis())?, random_seed)?;
    tracker.commit();
    Ok(true)
}

pub fn rebuild_interface(peer: &mut Peer, mtu: usize, now: i64, random_seed: u64) -> Result<()> {
    rebuild_components(&mut peer.interface, &mut peer.device, mtu, now, random_seed)
}

/// The caller prepares the seed before entering the synchronous rebuild.
/// This experimental boundary does not validate seed quality or uniqueness.
pub fn rebuild_components(
    original: &mut Interface,
    device: &mut PacketDevice,
    mtu: usize,
    now: i64,
    random_seed: u64,
) -> Result<()> {
    let addresses = original.ip_addrs().to_vec();
    let any_ip = original.any_ip();
    let mut routes = None;
    original
        .routes_mut()
        .update(|entries| routes = Some(entries.clone()));
    let routes = routes.context("route snapshot not captured")?;
    // Device validation occurs before mutation and refuses both queue kinds.
    device.configure_mtu(mtu)?;
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = random_seed;
    let mut interface = Interface::new(config, device, Instant::from_millis(now));
    interface.update_ip_addrs(|entries| {
        for address in addresses {
            // The source and destination tables have identical fixed capacity.
            entries
                .push(address)
                .expect("previously admitted interface addresses");
        }
    });
    interface.routes_mut().update(|entries| *entries = routes);
    interface.set_any_ip(any_ip);
    *original = interface;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::{
        socket::tcp,
        wire::{Ipv4Packet, Ipv6Packet, TcpPacket},
    };
    use std::net::IpAddr;

    fn first_sequence_after_replacement(ipv6: bool, seed: Option<u64>) -> i32 {
        let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
            .parse()
            .unwrap();
        let destination: IpAddr = if ipv6 { "fd66:66::3" } else { "10.66.66.3" }
            .parse()
            .unwrap();
        let mut peer = Peer::with_mtu(source, 40000, 1500).unwrap();
        if let Some(seed) = seed {
            rebuild_components(&mut peer.interface, &mut peer.device, 1280, 0, seed).unwrap();
        } else {
            rebuild_interface(&mut peer, 1280, 0, 0x5361).unwrap();
        }
        peer.sockets
            .get_mut::<tcp::Socket>(peer.tcp)
            .connect(
                peer.interface.context(),
                (destination, 9000),
                (source, 40001),
            )
            .unwrap();
        peer.poll(1);
        let packet = peer.device.outgoing.pop_front().unwrap();
        let payload = if ipv6 {
            Ipv6Packet::new_checked(&packet).unwrap().payload()
        } else {
            Ipv4Packet::new_checked(&packet).unwrap().payload()
        };
        TcpPacket::new_checked(payload).unwrap().seq_number().0
    }

    #[test]
    fn caller_seed_changes_new_tcp_sequence_after_replacement() {
        for ipv6 in [false, true] {
            assert_ne!(
                first_sequence_after_replacement(ipv6, Some(1)),
                first_sequence_after_replacement(ipv6, Some(2)),
                "the caller's seed must reach the replacement interface"
            );
        }
    }

    #[test]
    fn fixed_replacement_seed_repeats_tcp_sequence_across_interfaces() {
        for ipv6 in [false, true] {
            assert_eq!(
                first_sequence_after_replacement(ipv6, None),
                first_sequence_after_replacement(ipv6, None),
                "fixed replacement seeds repeat the first TCP sequence"
            );
        }
    }
}
