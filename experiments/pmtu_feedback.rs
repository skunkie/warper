// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded matching of too-big feedback for one outstanding TCP segment.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use smoltcp::wire::{
    Icmpv4Packet, Icmpv6Packet, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, TcpSeqNumber,
};

use crate::packet_peer::MTU;

const MAX_PACKET: usize = 1500;
const MAX_LIFETIME: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPacket,
    InvalidReporter,
    InvalidTime,
    InvalidLifetime,
    Busy,
    Expired,
    Cancelled,
    UnsupportedMtu,
    WrongFlow,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TCP PMTU feedback candidate: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    source: IpAddr,
    destination: IpAddr,
    identification: Option<u16>,
    length: usize,
    tcp_prefix: [u8; 8],
}

struct Reservation {
    identity: Identity,
    reporter: IpAddr,
    end_sequence: TcpSeqNumber,
    expires: Duration,
}

#[derive(Default)]
pub struct Tracker {
    pending: Option<Reservation>,
    now: Duration,
    cancelled: bool,
}

struct IpPayload<'a> {
    source: IpAddr,
    destination: IpAddr,
    identification: Option<u16>,
    protocol: IpProtocol,
    length: usize,
    payload: &'a [u8],
}

impl Tracker {
    pub fn reserve(
        &mut self,
        packet: &[u8],
        reporter: IpAddr,
        now: Duration,
        lifetime: Duration,
    ) -> Result<(), Error> {
        self.advance(now)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if lifetime.is_zero() || lifetime > MAX_LIFETIME {
            return Err(Error::InvalidLifetime);
        }
        let expires = now.checked_add(lifetime).ok_or(Error::InvalidTime)?;
        if expires.as_millis() > i64::MAX as u128 {
            return Err(Error::InvalidTime);
        }
        let ip = parse_ip(packet, false).ok_or(Error::InvalidPacket)?;
        if !unicast(reporter) || reporter.is_ipv6() != ip.source.is_ipv6() {
            return Err(Error::InvalidReporter);
        }
        let identity = Identity::from_ip(&ip).ok_or(Error::InvalidPacket)?;
        let tcp = TcpPacket::new_checked(ip.payload).map_err(|_| Error::InvalidPacket)?;
        if !tcp.ack()
            || tcp.syn()
            || tcp.rst()
            || tcp.payload().is_empty()
            || !tcp.verify_checksum(&ip.source.into(), &ip.destination.into())
        {
            return Err(Error::InvalidPacket);
        }
        let end_sequence = tcp.seq_number() + tcp.payload().len() + usize::from(tcp.fin());
        self.pending = Some(Reservation {
            identity,
            reporter,
            end_sequence,
            expires,
        });
        Ok(())
    }

    pub fn reduction(&mut self, feedback: &[u8], now: Duration) -> Result<Option<usize>, Error> {
        self.advance(now)?;
        let Some(pending) = &self.pending else {
            return Ok(None);
        };
        let Some(mtu) = matched_mtu(feedback, &pending.identity, pending.reporter) else {
            return Ok(None);
        };
        if mtu >= pending.identity.length {
            return Ok(None);
        }
        if mtu < MTU {
            return Err(Error::UnsupportedMtu);
        }
        Ok(Some(mtu))
    }

    pub fn next_deadline(&self) -> Option<Duration> {
        self.pending.as_ref().map(|pending| pending.expires)
    }

    /// The flow owner supplies only ACKs already accepted by its TCP stack.
    pub fn acknowledge(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        sequence: u32,
        now: Duration,
    ) -> Result<(), Error> {
        self.advance(now)?;
        if let Some(pending) = &self.pending {
            let identity = &pending.identity;
            let source_port = u16::from_be_bytes([identity.tcp_prefix[0], identity.tcp_prefix[1]]);
            let destination_port =
                u16::from_be_bytes([identity.tcp_prefix[2], identity.tcp_prefix[3]]);
            if source != SocketAddr::new(identity.source, source_port)
                || destination != SocketAddr::new(identity.destination, destination_port)
            {
                return Err(Error::WrongFlow);
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| TcpSeqNumber(sequence as i32) >= pending.end_sequence)
        {
            self.pending = None;
        }
        Ok(())
    }

    pub fn commit(&mut self) {
        self.pending = None;
    }

    pub fn cancel(&mut self) {
        self.pending = None;
        self.cancelled = true;
    }

    fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if now < self.now || now.as_millis() > i64::MAX as u128 {
            return Err(Error::InvalidTime);
        }
        self.now = now;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.expires)
        {
            self.pending = None;
            return Err(Error::Expired);
        }
        Ok(())
    }
}

impl Identity {
    fn from_ip(ip: &IpPayload<'_>) -> Option<Self> {
        if ip.protocol != IpProtocol::Tcp || !unicast(ip.source) || !unicast(ip.destination) {
            return None;
        }
        let tcp_prefix: [u8; 8] = ip.payload.get(..8)?.try_into().ok()?;
        if tcp_prefix[..2] == [0, 0] || tcp_prefix[2..4] == [0, 0] {
            return None;
        }
        Some(Self {
            source: ip.source,
            destination: ip.destination,
            identification: ip.identification,
            length: ip.length,
            tcp_prefix,
        })
    }
}

fn matched_mtu(feedback: &[u8], identity: &Identity, reporter: IpAddr) -> Option<usize> {
    let ip = parse_ip(feedback, false)?;
    if ip.destination != identity.source || ip.source != reporter {
        return None;
    }
    let (mtu, quote) = match (ip.protocol, ip.source, ip.destination) {
        (IpProtocol::Icmp, IpAddr::V4(_), IpAddr::V4(_)) => {
            let icmp = Icmpv4Packet::new_checked(ip.payload).ok()?;
            if u8::from(icmp.msg_type()) != 3 || icmp.msg_code() != 4 || !icmp.verify_checksum() {
                return None;
            }
            let mtu = u16::from_be_bytes(ip.payload.get(6..8)?.try_into().ok()?);
            (usize::from(mtu), ip.payload.get(8..)?)
        }
        (IpProtocol::Icmpv6, IpAddr::V6(source), IpAddr::V6(destination)) => {
            let icmp = Icmpv6Packet::new_checked(ip.payload).ok()?;
            if u8::from(icmp.msg_type()) != 2
                || icmp.msg_code() != 0
                || !icmp.verify_checksum(&source, &destination)
            {
                return None;
            }
            (
                usize::try_from(icmp.pkt_too_big_mtu()).ok()?,
                ip.payload.get(8..)?,
            )
        }
        _ => return None,
    };
    let original = parse_ip(quote, true)?;
    (Identity::from_ip(&original)? == *identity).then_some(mtu)
}

fn unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
}

fn parse_ip(bytes: &[u8], truncated: bool) -> Option<IpPayload<'_>> {
    if bytes.len() > MAX_PACKET {
        return None;
    }
    match bytes.first()? >> 4 {
        4 => {
            if bytes.len() < 20 {
                return None;
            }
            let ip = Ipv4Packet::new_unchecked(bytes);
            let length = usize::from(ip.total_len());
            if ip.header_len() != 20
                || !(20..=MAX_PACKET).contains(&length)
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
                length,
                payload: bytes.get(20..bytes.len().min(length))?,
            })
        }
        6 => {
            if bytes.len() < 40 {
                return None;
            }
            let ip = Ipv6Packet::new_unchecked(bytes);
            let length = usize::from(ip.payload_len()) + 40;
            if length > MAX_PACKET || (!truncated && length != bytes.len()) {
                return None;
            }
            Some(IpPayload {
                source: ip.src_addr().into(),
                destination: ip.dst_addr().into(),
                identification: None,
                protocol: ip.next_header(),
                length,
                payload: bytes.get(40..bytes.len().min(length))?,
            })
        }
        _ => None,
    }
}
