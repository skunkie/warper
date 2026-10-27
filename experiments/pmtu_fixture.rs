// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled too-big packet construction; no live path discovery.

use crate::packet_peer::MTU;
use anyhow::{Result, ensure};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpProtocol,
        Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    },
};

pub fn too_big(quote: &[u8], ipv6: bool, mtu: usize) -> Result<Vec<u8>> {
    ensure!((MTU..=1500).contains(&mtu), "unsupported fixture MTU");
    ensure!(
        quote.len() > mtu,
        "PTB fixture requires a genuinely oversized quote"
    );
    let checksums = ChecksumCapabilities::default();
    if ipv6 {
        let ip = Ipv6Packet::new_checked(quote)?;
        let header = Ipv6Repr::parse(&ip)?;
        let repr = Icmpv6Repr::PktTooBig {
            mtu: mtu as u32,
            header,
            data: &ip.payload()[..1192],
        };
        let mut bytes = vec![0; 40 + repr.buffer_len()];
        Ipv6Repr {
            src_addr: ip.dst_addr(),
            dst_addr: ip.src_addr(),
            next_header: IpProtocol::Icmpv6,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));
        repr.emit(
            &ip.dst_addr(),
            &ip.src_addr(),
            &mut Icmpv6Packet::new_unchecked(&mut bytes[40..]),
            &checksums,
        );
        bytes[48..].copy_from_slice(&quote[..1232]);
        Icmpv6Packet::new_unchecked(&mut bytes[40..]).fill_checksum(&ip.dst_addr(), &ip.src_addr());
        let ip = Ipv6Packet::new_checked(&bytes[..])?;
        let icmp = Icmpv6Packet::new_checked(ip.payload())?;
        ensure!(
            u8::from(icmp.msg_type()) == 2
                && icmp.msg_code() == 0
                && icmp.pkt_too_big_mtu() == mtu as u32
                && icmp.payload() == &quote[..1232]
                && icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()),
            "PTB fixture checksum, MTU, or exact quote changed"
        );
        Ok(bytes)
    } else {
        let ip = Ipv4Packet::new_checked(quote)?;
        let header = Ipv4Repr::parse(&ip, &checksums)?;
        let repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::FragRequired,
            header,
            data: &ip.payload()[..8],
        };
        let mut bytes = vec![0; 20 + repr.buffer_len()];
        Ipv4Repr {
            src_addr: ip.dst_addr(),
            dst_addr: ip.src_addr(),
            next_header: IpProtocol::Icmp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..]), &checksums);
        repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut bytes[20..]),
            &checksums,
        );
        bytes[28..].copy_from_slice(&quote[..28]);
        // The pinned ICMPv4 representation omits RFC 1191's next-hop MTU.
        // Set that non-cryptographic wire field, then use the library checksum.
        bytes[26..28].copy_from_slice(&(mtu as u16).to_be_bytes());
        Icmpv4Packet::new_unchecked(&mut bytes[20..]).fill_checksum();
        let ip = Ipv4Packet::new_checked(&bytes[..])?;
        let icmp = Icmpv4Packet::new_checked(ip.payload())?;
        ensure!(
            u8::from(icmp.msg_type()) == 3
                && icmp.msg_code() == 4
                && icmp.data() == &quote[..28]
                && icmp.verify_checksum()
                && u16::from_be_bytes([bytes[26], bytes[27]]) == mtu as u16,
            "IPv4 too-big checksum, MTU, or exact quote changed"
        );
        Ok(bytes)
    }
}
