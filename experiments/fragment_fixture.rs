// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled fragment generation; not a production fragmentation implementation.

use crate::packet_peer::MTU;
use anyhow::{Context, Result, ensure};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6FragmentHeader, Ipv6FragmentRepr, Ipv6Packet,
        Ipv6Repr,
    },
};

pub fn split(original: &[u8], identification: u32, at: usize) -> Result<[Vec<u8>; 2]> {
    ensure!(
        !original.is_empty() && original.len() <= MTU && at > 0 && at.is_multiple_of(8),
        "invalid controlled fragment input"
    );
    let checksums = ChecksumCapabilities::default();
    let ipv6 = original[0] >> 4 == 6;
    let header = if ipv6 { 40 } else { 20 };
    ensure!(
        original.len() > header + at,
        "controlled split must leave a final payload"
    );
    let mut fragments = Vec::with_capacity(2);
    for (offset, length, more) in [(0, at, true), (at, original.len() - header - at, false)] {
        if ipv6 {
            let ip = Ipv6Packet::new_checked(original)?;
            let mut repr = Ipv6Repr::parse(&ip)?;
            let protocol = repr.next_header;
            repr.next_header = IpProtocol::Ipv6Frag;
            repr.payload_len = 8 + length;
            let mut bytes = vec![0; 48 + length];
            repr.emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));
            bytes[40] = protocol.into();
            Ipv6FragmentRepr {
                frag_offset: (offset / 8) as u16,
                more_frags: more,
                ident: identification,
            }
            .emit(&mut Ipv6FragmentHeader::new_unchecked(&mut bytes[42..48]));
            bytes[48..].copy_from_slice(&ip.payload()[offset..offset + length]);
            ensure!(bytes.len() <= MTU, "controlled IPv6 fragment exceeds MTU");
            fragments.push(bytes);
        } else {
            let ip = Ipv4Packet::new_checked(original)?;
            ensure!(
                ip.header_len() == 20,
                "controlled splitter does not accept IPv4 options"
            );
            let mut repr = Ipv4Repr::parse(&ip, &checksums)?;
            repr.payload_len = length;
            let mut bytes = vec![0; 20 + length];
            let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
            repr.emit(&mut packet, &checksums);
            packet.set_dont_frag(false);
            packet.set_more_frags(more);
            packet.set_frag_offset(offset as u16);
            packet.set_ident(identification as u16);
            packet.fill_checksum();
            packet
                .payload_mut()
                .copy_from_slice(&ip.payload()[offset..offset + length]);
            fragments.push(bytes);
        }
    }
    let mut fragments = fragments.into_iter();
    Ok([
        fragments.next().context("first fragment missing")?,
        fragments.next().context("last fragment missing")?,
    ])
}
