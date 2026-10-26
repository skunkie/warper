// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled active-stack traffic through the UDP association candidate.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Result, ensure};
use smoltcp::socket::udp;

use crate::{
    adapter::BackendId,
    packet_peer::{MTU, Peer},
    udp_adapter::{Association, Error, Limits, UdpAdapter},
};

pub fn select_backend(destination: SocketAddr) -> Option<BackendId> {
    match destination.port() {
        9000 => Some(BackendId(1)),
        9100 => Some(BackendId(2)),
        _ => None,
    }
}

pub async fn run_probe(ipv6: bool, shared_destination: bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let source = |suffix, port| -> Result<SocketAddr> {
            let address = if ipv6 {
                format!("[fd66:66::{suffix}]:{port}")
            } else {
                format!("10.66.66.{suffix}:{port}")
            };
            Ok(address.parse()?)
        };
        let sources = [source(2, 40000)?, source(3, 40001)?];
        let destinations = [
            source(91, 9000)?,
            source(
                if shared_destination { 91 } else { 92 },
                if shared_destination { 9000 } else { 9100 },
            )?,
        ];
        let mut peers = [
            Peer::new(sources[0].ip(), sources[0].port())?,
            Peer::new(sources[1].ip(), sources[1].port())?,
        ];
        let (mut host, mut accepted) = UdpAdapter::new(Limits::default(), select_backend)?;
        let mut associations: Vec<Association> = Vec::new();
        let payloads = [
            vec![],
            vec![0x31],
            vec![0x72; 257],
            vec![0x53; MTU - if ipv6 { 48 } else { 28 }],
        ];
        for (step, payload) in payloads.iter().enumerate() {
            let now = Duration::from_millis(step as u64);
            host.poll(now)?;
            for (index, peer) in peers.iter_mut().enumerate() {
                peer.sockets
                    .get_mut::<udp::Socket>(peer.udp)
                    .send_slice(payload, destinations[index])?;
                peer.poll(step as i64);
                let mut packets = 0;
                while let Some(packet) = peer.device.outgoing.pop_front() {
                    ensure!(packets < 4, "UDP probe exceeded controlled packet budget");
                    packets += 1;
                    let id = host.inject(&packet)?;
                    if step == 0 {
                        let association = accepted.try_recv()?;
                        let metadata = association.metadata();
                        ensure!(
                            metadata.id == id
                                && metadata.source == sources[index]
                                && metadata.destination == destinations[index]
                                && Some(metadata.backend) == select_backend(destinations[index]),
                            "UDP association metadata changed"
                        );
                        associations.push(association);
                    } else {
                        ensure!(
                            id == associations[index].metadata().id,
                            "UDP association identity changed"
                        );
                    }
                }
                ensure!(packets == 1, "UDP did not emit exactly one datagram");
                let actual = associations[index].recv().await?;
                ensure!(actual.payload() == payload, "UDP ingress boundary changed");
                associations[index].try_reply(actual.payload())?;
            }
            host.poll(now)?;
            let mut replies = 0;
            while let Some(packet) = host.take_packet() {
                ensure!(replies < 2, "UDP probe emitted unexpected output");
                replies += 1;
                // Each controlled IP stack ignores the other source's reply.
                for peer in &mut peers {
                    peer.device.inject(packet.clone())?;
                }
            }
            ensure!(replies == 2, "UDP reply count changed");
            for (index, peer) in peers.iter_mut().enumerate() {
                peer.poll(step as i64);
                let (actual, metadata) = peer.sockets.get_mut::<udp::Socket>(peer.udp).recv()?;
                ensure!(
                    actual == payload && metadata.endpoint == destinations[index].into(),
                    "UDP reply/source changed"
                );
            }
        }
        ensure!(
            associations[0].metadata().id != associations[1].metadata().id,
            "sources shared an association"
        );
        ensure!(
            host.statistics().admitted == 2
                && host.statistics().received == 8
                && host.statistics().replied == 8
                && host.statistics().rejected == 0,
            "UDP accounting changed"
        );
        ensure!(host.active_associations() == 2, "UDP ownership disappeared");
        host.cancel();
        ensure!(
            accepted.recv().await.is_none(),
            "UDP acceptance remained open"
        );
        ensure!(
            host.take_packet().is_none() && host.active_associations() == 0,
            "UDP cancellation retained driver state"
        );
        for association in &mut associations {
            ensure!(
                matches!(association.recv().await, Err(Error::Cancelled)),
                "UDP cancellation became EOF"
            );
        }
        Ok(())
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn associations_preserve_datagrams_addresses_and_backend_in_both_families() {
        for ipv6 in [false, true] {
            for shared_destination in [false, true] {
                run_probe(ipv6, shared_destination).await.unwrap();
            }
        }
    }
}
