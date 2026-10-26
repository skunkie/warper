// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded fragment normalization before transport admission.

use std::{fmt, net::IpAddr, time::Duration};

use smoltcp::{
    storage::Assembler,
    wire::{IpProtocol, Ipv4Packet, Ipv6FragmentHeader, Ipv6Packet},
};

use crate::packet_peer::MTU;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    InvalidTime,
    MalformedPacket,
    UnsupportedHeaders,
    PacketTooLarge,
    ResourceLimit,
    Overlap,
    ConflictingEnd,
    ProtocolMismatch,
    TooManyRanges,
    Discarded,
    Cancelled,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fragment input experiment: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy)]
pub struct Limits {
    pub slots: usize,
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            slots: 2,
            timeout: Duration::from_secs(1),
        }
    }
}

pub enum Outcome {
    Pass,
    Pending,
    Complete(Vec<u8>),
}

#[derive(Default)]
pub struct Statistics {
    pub completed: u64,
    pub rejected: u64,
    pub timed_out: u64,
    pub discarded: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Key {
    source: IpAddr,
    destination: IpAddr,
    identification: u32,
    protocol: u8,
}

struct Fragment<'a> {
    key: Key,
    protocol: u8,
    header: &'a [u8],
    offset: usize,
    more: bool,
    payload: &'a [u8],
    atomic: bool,
}

struct Assembly {
    key: Key,
    protocol: u8,
    header: [u8; 40],
    header_len: usize,
    data: [u8; MTU],
    ranges: Assembler,
    total: Option<usize>,
    expires: Duration,
    discarded: bool,
}

pub struct Reassembler {
    slots: Box<[Option<Assembly>]>,
    limits: Limits,
    now: Duration,
    cancelled: bool,
    statistics: Statistics,
}

impl Reassembler {
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if !(1..=4).contains(&limits.slots)
            || limits.timeout.is_zero()
            || limits.timeout > Duration::from_secs(60)
        {
            return Err(Error::InvalidLimits);
        }
        Ok(Self {
            slots: (0..limits.slots).map(|_| None).collect(),
            limits,
            now: Duration::ZERO,
            cancelled: false,
            statistics: Statistics::default(),
        })
    }

    pub fn accept(&mut self, packet: &[u8], now: Duration) -> Result<Outcome, Error> {
        let result = self.admit(packet, now);
        if result.is_err() {
            self.statistics.rejected = self.statistics.rejected.saturating_add(1);
        }
        result
    }

    pub fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if now < self.now || now.as_millis() > i64::MAX as u128 {
            return Err(Error::InvalidTime);
        }
        self.now = now;
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|assembly| now >= assembly.expires)
            {
                *slot = None;
                self.statistics.timed_out = self.statistics.timed_out.saturating_add(1);
            }
        }
        Ok(())
    }

    pub fn next_deadline(&self) -> Option<Duration> {
        self.slots
            .iter()
            .filter_map(|slot| slot.as_ref().map(|assembly| assembly.expires))
            .min()
    }

    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        for slot in &mut self.slots {
            *slot = None;
        }
    }

    fn admit(&mut self, packet: &[u8], now: Duration) -> Result<Outcome, Error> {
        self.advance(now)?;
        let Some(fragment) = parse(packet)? else {
            return Ok(Outcome::Pass);
        };
        if fragment.atomic {
            self.statistics.completed = self.statistics.completed.saturating_add(1);
            return Ok(Outcome::Complete(rebuild(
                fragment.header,
                fragment.protocol,
                fragment.payload,
            )));
        }
        let index = self
            .slots
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|assembly| assembly.key == fragment.key)
            })
            .or_else(|| self.slots.iter().position(Option::is_none))
            .ok_or(Error::ResourceLimit)?;
        let assembly = self.slots[index].get_or_insert_with(|| Assembly {
            key: fragment.key,
            protocol: fragment.protocol,
            header: [0; 40],
            header_len: fragment.header.len(),
            data: [0; MTU],
            ranges: Assembler::new(),
            total: None,
            expires: now + self.limits.timeout,
            discarded: false,
        });
        if assembly.discarded {
            return Err(Error::Discarded);
        }
        let end = fragment.offset + fragment.payload.len();
        let failure = if assembly.protocol != fragment.protocol {
            Some(Error::ProtocolMismatch)
        } else if assembly
            .ranges
            .iter_data()
            .any(|(left, right)| fragment.offset < right && end > left)
        {
            Some(Error::Overlap)
        } else if assembly.total.is_some_and(|total| {
            end > total || (fragment.more && end >= total) || (!fragment.more && end != total)
        }) || (!fragment.more
            && assembly.ranges.iter_data().any(|(_, right)| right > end))
        {
            Some(Error::ConflictingEnd)
        } else {
            None
        };
        if let Some(error) = failure {
            assembly.discarded = true;
            self.statistics.discarded = self.statistics.discarded.saturating_add(1);
            return Err(error);
        }
        let mut ranges = assembly.ranges.clone();
        if ranges.add(fragment.offset, fragment.payload.len()).is_err() {
            assembly.discarded = true;
            self.statistics.discarded = self.statistics.discarded.saturating_add(1);
            return Err(Error::TooManyRanges);
        }
        assembly.ranges = ranges;
        assembly.data[fragment.offset..end].copy_from_slice(fragment.payload);
        if fragment.offset == 0 {
            assembly.header[..fragment.header.len()].copy_from_slice(fragment.header);
        }
        if !fragment.more {
            assembly.total = Some(end);
        }
        if let Some(total) = assembly.total
            && assembly.ranges.peek_front() == total
        {
            let packet = rebuild(
                &assembly.header[..assembly.header_len],
                assembly.protocol,
                &assembly.data[..total],
            );
            self.slots[index] = None;
            self.statistics.completed = self.statistics.completed.saturating_add(1);
            return Ok(Outcome::Complete(packet));
        }
        Ok(Outcome::Pending)
    }
}

fn parse(bytes: &[u8]) -> Result<Option<Fragment<'_>>, Error> {
    if bytes.len() > MTU {
        return Err(Error::PacketTooLarge);
    }
    let malformed = |_| Error::MalformedPacket;
    let fragment = match bytes.first().map(|byte| byte >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(bytes).map_err(malformed)?;
            if !ip.more_frags() && ip.frag_offset() == 0 {
                return Ok(None);
            }
            if ip.header_len() != 20 {
                return Err(Error::UnsupportedHeaders);
            }
            if !ip.verify_checksum()
                || usize::from(ip.total_len()) != bytes.len()
                || ip.dont_frag()
                || bytes[6] & 0x80 != 0
            {
                return Err(Error::MalformedPacket);
            }
            Fragment {
                key: Key {
                    source: ip.src_addr().into(),
                    destination: ip.dst_addr().into(),
                    identification: u32::from(ip.ident()),
                    protocol: u8::from(ip.next_header()),
                },
                protocol: ip.next_header().into(),
                header: &bytes[..20],
                offset: usize::from(ip.frag_offset()),
                more: ip.more_frags(),
                payload: ip.payload(),
                atomic: false,
            }
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(bytes).map_err(malformed)?;
            if ip.next_header() != IpProtocol::Ipv6Frag {
                return Ok(None);
            }
            if usize::from(ip.payload_len()) + 40 != bytes.len() || ip.payload_len() < 8 {
                return Err(Error::MalformedPacket);
            }
            let header = Ipv6FragmentHeader::new_checked(&bytes[42..48]).map_err(malformed)?;
            if bytes[41] != 0 || bytes[43] & 0x06 != 0 {
                return Err(Error::MalformedPacket);
            }
            Fragment {
                key: Key {
                    source: ip.src_addr().into(),
                    destination: ip.dst_addr().into(),
                    identification: header.ident(),
                    protocol: 0,
                },
                protocol: bytes[40],
                header: &bytes[..40],
                offset: usize::from(header.frag_offset()) * 8,
                more: header.more_frags(),
                payload: &bytes[48..],
                atomic: header.frag_offset() == 0 && !header.more_frags(),
            }
        }
        _ => return Ok(None),
    };
    let unicast = |address: IpAddr| match address {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    };
    if !unicast(fragment.key.source)
        || !unicast(fragment.key.destination)
        || fragment.payload.is_empty()
        || (fragment.more && !fragment.payload.len().is_multiple_of(8))
    {
        return Err(Error::MalformedPacket);
    }
    if fragment.protocol != 6 && fragment.protocol != 17 {
        return Err(Error::UnsupportedHeaders);
    }
    if fragment.offset == 0
        && (fragment.payload.len() < 8
            || (fragment.protocol == 6
                && (fragment.payload.len() < 20
                    || usize::from(fragment.payload[12] >> 4) * 4 < 20
                    || usize::from(fragment.payload[12] >> 4) * 4 > fragment.payload.len())))
    {
        return Err(Error::MalformedPacket);
    }
    if fragment.header.len() + fragment.offset + fragment.payload.len() > MTU {
        return Err(Error::PacketTooLarge);
    }
    Ok(Some(fragment))
}

fn rebuild(header: &[u8], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(header.len() + payload.len());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(payload);
    if header.len() == 20 {
        let length = bytes.len() as u16;
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ip.set_total_len(length);
        ip.set_more_frags(false);
        ip.set_frag_offset(0);
        ip.set_dont_frag(false);
        ip.fill_checksum();
    } else {
        let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
        ip.set_next_header(protocol.into());
        ip.set_payload_len(payload.len() as u16);
    }
    bytes
}
