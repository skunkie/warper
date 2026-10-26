// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled IP fragments through bounded input and UDP admission.

use std::{net::SocketAddr, time::Duration};

pub use crate::fragment_fixture::split;
use anyhow::{Context, Result, ensure};
use futures::FutureExt;
use smoltcp::socket::udp;

use crate::{
    packet_peer::{MTU, Peer},
    reassembly::{Limits, Outcome, Reassembler},
    udp_adapter::{self, UdpAdapter},
};

pub fn run_probe(ipv6: bool) -> Result<()> {
    let source: SocketAddr = if ipv6 {
        "[fd66:66::2]:40000"
    } else {
        "10.66.66.2:40000"
    }
    .parse()?;
    let destination: SocketAddr = if ipv6 {
        "[fd66:66::10]:9000"
    } else {
        "10.66.66.10:9000"
    }
    .parse()?;
    let mut peer = Peer::new(source.ip(), source.port())?;
    let payload = vec![0x53; if ipv6 { 1232 } else { 1252 }];
    peer.sockets
        .get_mut::<udp::Socket>(peer.udp)
        .send_slice(&payload, destination)?;
    peer.poll(0);
    let packet = peer
        .device
        .outgoing
        .pop_front()
        .context("fragment fixture emitted no packet")?;
    let fragments = split(&packet, 42, 1024)?;
    for order in [[0, 1], [1, 0]] {
        let mut input = Reassembler::new(Limits::default())?;
        let (mut host, mut accepted) = UdpAdapter::new(
            udp_adapter::Limits::default(),
            crate::udp_probe::select_backend,
        )?;
        ensure!(
            matches!(
                input.accept(&fragments[order[0]], Duration::ZERO)?,
                Outcome::Pending
            ),
            "first fragment published incomplete data"
        );
        ensure!(
            accepted.try_recv().is_err(),
            "incomplete datagram published a handler"
        );
        let Outcome::Complete(packet) =
            input.accept(&fragments[order[1]], Duration::from_millis(1))?
        else {
            anyhow::bail!("complete fragment set remained pending");
        };
        ensure!(packet.len() == MTU, "reassembled MTU boundary changed");
        host.inject(&packet)?;
        let mut association = accepted.try_recv()?;
        ensure!(
            association.metadata().source == source
                && association.metadata().destination == destination
                && Some(association.metadata().backend)
                    == crate::udp_probe::select_backend(destination),
            "fragment reassembly changed original tuple"
        );
        let actual = association
            .recv()
            .now_or_never()
            .context("queued complete datagram was not ready")??;
        ensure!(
            actual.payload() == payload,
            "fragment reassembly changed payload or boundaries"
        );
        association.try_reply(actual.payload())?;
        host.poll(Duration::from_millis(1))?;
        peer.device.inject(
            host.take_packet()
                .context("fragmented UDP produced no reply")?,
        )?;
        peer.poll(2);
        let (reply, metadata) = peer.sockets.get_mut::<udp::Socket>(peer.udp).recv()?;
        ensure!(
            reply == payload && metadata.endpoint == destination.into(),
            "fragmented UDP reply or original destination changed"
        );
        drop(actual);
        host.cancel();
        input.cancel();
        ensure!(
            matches!(
                association.recv().now_or_never(),
                Some(Err(udp_adapter::Error::Cancelled))
            ),
            "fragment handler did not observe shutdown"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_fragment_orders_preserve_maximum_udp_datagrams_and_metadata() {
        for ipv6 in [false, true] {
            run_probe(ipv6).unwrap();
        }
    }
}
