// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Synchronous experimental raw-IP interface replacement retaining socket state.

use crate::packet_peer::Peer;
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
) -> Result<bool> {
    let Some(mtu) = tracker.reduction(packet, now)? else {
        return Ok(false);
    };
    if mtu >= peer.device.capabilities().max_transmission_unit {
        return Ok(false);
    }
    rebuild_interface(peer, mtu, i64::try_from(now.as_millis())?)?;
    tracker.commit();
    Ok(true)
}

pub fn rebuild_interface(peer: &mut Peer, mtu: usize, now: i64) -> Result<()> {
    let addresses = peer.interface.ip_addrs().to_vec();
    let any_ip = peer.interface.any_ip();
    let mut routes = None;
    peer.interface
        .routes_mut()
        .update(|entries| routes = Some(entries.clone()));
    let routes = routes.context("route snapshot not captured")?;
    // Device validation occurs before mutation and refuses both queue kinds.
    peer.device.configure_mtu(mtu)?;
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x5361;
    let mut interface = Interface::new(config, &mut peer.device, Instant::from_millis(now));
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
    peer.interface = interface;
    Ok(())
}
