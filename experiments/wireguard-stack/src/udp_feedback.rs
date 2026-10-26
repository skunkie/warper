// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One reserved UDP operation, matched against validated ICMP error quotes.

use std::{fmt, net::IpAddr};

use smoltcp::wire::{Icmpv4Packet, Icmpv6Packet, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};

use crate::packet_peer::MTU;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidPacket,
    PortUnreachable,
    DeadlineExpired,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "reserved UDP feedback: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    source: IpAddr,
    destination: IpAddr,
    identification: Option<u16>,
    udp_header: [u8; 8],
}

struct IpPayload<'a> {
    source: IpAddr,
    destination: IpAddr,
    identification: Option<u16>,
    protocol: IpProtocol,
    payload: &'a [u8],
    payload_len: usize,
}

impl Reservation {
    pub fn new(packet: &[u8]) -> Result<Self, Error> {
        let ip = decode_ip(packet, false).ok_or(Error::InvalidPacket)?;
        let quote = Self::from_ip(&ip).ok_or(Error::InvalidPacket)?;
        let udp = UdpPacket::new_checked(ip.payload).map_err(|_| Error::InvalidPacket)?;
        if (ip.source.is_ipv6() && udp.checksum() == 0)
            || !udp.verify_checksum(&ip.source.into(), &ip.destination.into())
        {
            return Err(Error::InvalidPacket);
        }
        Ok(quote)
    }

    pub fn matches(&self, packet: &[u8]) -> bool {
        self.match_quote(packet).is_some()
    }

    fn match_quote(&self, packet: &[u8]) -> Option<()> {
        let ip = decode_ip(packet, false)?;
        if ip.source != self.destination || ip.destination != self.source {
            return None;
        }
        let quote = match ip.protocol {
            IpProtocol::Icmp if ip.source.is_ipv4() => {
                let icmp = Icmpv4Packet::new_checked(ip.payload).ok()?;
                if u8::from(icmp.msg_type()) != 3 || icmp.msg_code() != 3 || !icmp.verify_checksum()
                {
                    return None;
                }
                ip.payload.get(8..)?
            }
            IpProtocol::Icmpv6 if ip.source.is_ipv6() => {
                let icmp = Icmpv6Packet::new_checked(ip.payload).ok()?;
                let (IpAddr::V6(source), IpAddr::V6(destination)) = (ip.source, ip.destination)
                else {
                    return None;
                };
                if u8::from(icmp.msg_type()) != 1
                    || icmp.msg_code() != 4
                    || !icmp.verify_checksum(&source, &destination)
                {
                    return None;
                }
                ip.payload.get(8..)?
            }
            _ => return None,
        };
        let original = decode_ip(quote, true)?;
        (Self::from_ip(&original)? == *self).then_some(())
    }

    fn from_ip(ip: &IpPayload<'_>) -> Option<Self> {
        if ip.protocol != IpProtocol::Udp || ip.payload_len < 8 {
            return None;
        }
        let udp_header: [u8; 8] = ip.payload.get(..8)?.try_into().ok()?;
        if udp_header[..2] == [0, 0]
            || udp_header[2..4] == [0, 0]
            || usize::from(u16::from_be_bytes([udp_header[4], udp_header[5]])) != ip.payload_len
        {
            return None;
        }
        Some(Self {
            source: ip.source,
            destination: ip.destination,
            identification: ip.identification,
            udp_header,
        })
    }
}

fn decode_ip(bytes: &[u8], truncated: bool) -> Option<IpPayload<'_>> {
    if bytes.len() > MTU {
        return None;
    }
    match bytes.first()? >> 4 {
        4 => {
            // Error quotes retain the original total length even when only the
            // IP and UDP headers fit. Check storage before unchecked accessors.
            if bytes.len() < 20 {
                return None;
            }
            let ip = Ipv4Packet::new_unchecked(bytes);
            let length = usize::from(ip.total_len());
            if ip.header_len() != 20
                || !(20..=MTU).contains(&length)
                || (!truncated && length != bytes.len())
                || bytes[6] & 0x80 != 0
                || ip.frag_offset() != 0
                || ip.more_frags()
                || !ip.verify_checksum()
            {
                return None;
            }
            Some(IpPayload {
                source: ip.src_addr().into(),
                destination: ip.dst_addr().into(),
                identification: Some(ip.ident()),
                protocol: ip.next_header(),
                payload: bytes.get(20..bytes.len().min(length))?,
                payload_len: length - 20,
            })
        }
        6 => {
            if bytes.len() < 40 {
                return None;
            }
            let ip = Ipv6Packet::new_unchecked(bytes);
            let length = usize::from(ip.payload_len());
            if length + 40 > MTU || (!truncated && length + 40 != bytes.len()) {
                return None;
            }
            Some(IpPayload {
                source: ip.src_addr().into(),
                destination: ip.dst_addr().into(),
                identification: None,
                protocol: ip.next_header(),
                payload: bytes.get(40..bytes.len().min(length + 40))?,
                payload_len: length,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "udp_feedback_tests.rs"]
mod tests;
