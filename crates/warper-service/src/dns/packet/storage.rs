// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Allocation-free admission for the pinned Hickory std-only decoded layout.

use super::{Error, HEADER_BYTES, Limits, Packet};
use crate::dns::memory::{Budget, Reservation};
use hickory_proto::{
    op::Query,
    rr::{
        Record, RecordType,
        rdata::{opt::EdnsOption, svcb::SvcParamValue},
    },
};
use std::mem::size_of;

pub(super) fn reserve(bytes: &[u8], limits: Limits, budget: &Budget) -> Result<Reservation, Error> {
    limits.admit(bytes)?;
    let records = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]))
        + usize::from(u16::from_be_bytes([bytes[8], bytes[9]]))
        + usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
    let mut offset = name_end(bytes, HEADER_BYTES)?;
    offset = advance(bytes, offset, 4)?;
    let mut data_bytes = 0usize;
    let mut bitmap_nodes = 0usize;
    for _ in 0..records {
        offset = name_end(bytes, offset)?;
        let end = advance(bytes, offset, 10)?;
        let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]));
        offset = advance(bytes, end, length)?;
        data_bytes += length;
        if kind == u16::from(RecordType::CSYNC) {
            // CSYNC's serial/flags precede its expanding type bitmap. Other
            // DNSSEC bitmap decoders are disabled in the pinned std-only build.
            let mut bitmap = end
                .checked_add(6)
                .filter(|start| *start <= offset)
                .ok_or(Error::Malformed)?;
            let mut types = 0usize;
            while bitmap < offset {
                if bitmap + 2 > offset {
                    return Err(Error::Malformed);
                }
                let length = usize::from(bytes[bitmap + 1]);
                if !(1..=32).contains(&length) || bitmap + 2 + length > offset {
                    return Err(Error::Malformed);
                }
                bitmap += 2;
                types += bytes[bitmap..bitmap + length]
                    .iter()
                    .map(|byte| byte.count_ones() as usize)
                    .sum::<usize>();
                bitmap += length;
            }
            // Rust's pinned B-tree has at least five keys per non-root node.
            // Include the root and transient splitting nodes before insertion.
            bitmap_nodes += types.div_ceil(5) + 3;
        }
    }
    if offset != bytes.len() {
        return Err(Error::Malformed);
    }
    let bytes = footprint(records, data_bytes, bitmap_nodes)?;
    budget.reserve(bytes).map_err(|_| Error::ResourceLimit)
}

pub(super) fn local(budget: &Budget) -> Result<Reservation, Error> {
    // A local reply copies one question and creates empty EDNS metadata; it
    // never clones the original request's opaque options or record sections.
    budget
        .reserve(footprint(0, 0, 0)?)
        .map_err(|_| Error::ResourceLimit)
}

fn footprint(records: usize, data_bytes: usize, bitmap_nodes: usize) -> Result<usize, Error> {
    // Record vectors may grow geometrically in three sections. SOA is the
    // largest name multiplicity: owner plus two RDATA names. A legal Name has
    // at most 254 data/label-end bytes combined; both TinyVec heaps can double.
    let records_bytes = (2 * records + 12) * size_of::<Record>();
    let names = (3 * records + 4) * 512;
    // Bound variable vectors, strings and boxed TXT values by their wire
    // representation. Include capacity growth and temporary EDNS cloning.
    // Parameter/option elements have at least four framing bytes each.
    let variable = 3
        * (size_of::<String>()
            + size_of::<Box<[u8]>>()
            + size_of::<(u16, SvcParamValue)>().div_ceil(4)
            + size_of::<(u16, EdnsOption)>().div_ceil(4))
        + 4;
    // A B-tree node has at most eleven keys and twelve edges. Round its
    // header/alignment/key/edge storage upward without relying on private types.
    let node = 20 * size_of::<usize>() + 16 * size_of::<RecordType>();
    size_of::<Packet>()
        .checked_add(4 * size_of::<Query>() + 2 * size_of::<usize>())
        .and_then(|bytes| bytes.checked_add(records_bytes + names))
        .and_then(|bytes| {
            data_bytes
                .checked_mul(variable)
                .and_then(|data| bytes.checked_add(data))
        })
        .and_then(|bytes| {
            bitmap_nodes
                .checked_mul(node)
                .and_then(|nodes| bytes.checked_add(nodes))
        })
        .ok_or(Error::ResourceLimit)
}

fn name_end(bytes: &[u8], mut offset: usize) -> Result<usize, Error> {
    loop {
        let length = *bytes.get(offset).ok_or(Error::Malformed)?;
        match length {
            0 => return Ok(offset + 1),
            1..=63 => offset = advance(bytes, offset, 1 + usize::from(length))?,
            192..=255 => return advance(bytes, offset, 2),
            _ => return Err(Error::Malformed),
        }
    }
}

fn advance(bytes: &[u8], offset: usize, length: usize) -> Result<usize, Error> {
    offset
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(Error::Malformed)
}
