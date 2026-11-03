// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded read-only IPv4 route inventory, never mutation or ownership authority.

pub use super::QueryError as Error;
use super::transaction::{self, Cause, Wait};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAddress, RouteAttribute, RouteMessage},
};
use std::{fmt, net::Ipv4Addr, num::NonZeroU32};
use warper_core::transport::Request;

pub const MAX_ROUTES: usize = 8192;
const MAX_MESSAGES: usize = 16384;

/// Adapter-owned metadata. Unknown selectors remain visible as `exact = false`;
/// no entry alone authorizes deletion, replacement or a physical send.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Entry {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub table: NonZeroU32,
    pub interface: Option<NonZeroU32>,
    pub metric: Option<u32>,
    pub preferred_source: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub protocol: u8,
    pub scope: u8,
    pub kind: u8,
    pub exact: bool,
}
impl fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Entry(<native route metadata>)")
    }
}

/// All returned entries belong to one completed dump. Concurrent host changes
/// can invalidate it; the caller must subscribe before inspection and recheck.
#[derive(Eq, PartialEq)]
pub struct Inventory {
    entries: Vec<Entry>,
}
impl Inventory {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn observe(&mut self, message: RouteNetlinkMessage) -> Result<(), Cause> {
        let RouteNetlinkMessage::NewRoute(message) = message else {
            return Err(Cause::Protocol);
        };
        if self.entries.len() == MAX_ROUTES {
            return Err(Cause::ResourceLimit);
        }
        self.entries.push(entry(message)?);
        Ok(())
    }
}
impl fmt::Debug for Inventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Inventory(<native route metadata>)")
    }
}

/// Run in a retained native worker. No partial result survives error, and no
/// task, subprocess or retry is created. Bound concurrent workers externally.
pub fn inspect(request: Request) -> Result<Inventory, Error> {
    let wait = Wait::new(request).map_err(transaction::query_error)?;
    let mut query = RouteMessage::default();
    query.header.address_family = AddressFamily::Inet;
    transaction::dump(
        RouteNetlinkMessage::GetRoute(query),
        &wait,
        MAX_MESSAGES,
        Inventory {
            entries: Vec::new(),
        },
        Inventory::observe,
    )
    .map_err(transaction::query_error)
}

pub(super) fn entry(message: RouteMessage) -> Result<Entry, Cause> {
    let header = message.header;
    if header.address_family != AddressFamily::Inet || header.destination_prefix_length > 32 {
        return Err(Cause::Protocol);
    }
    let mut destination = None;
    let mut table = None;
    let mut interface = None;
    let mut metric = None;
    let mut preferred_source = None;
    let mut gateway = None;
    let mut exact = header.flags.is_empty() && header.source_prefix_length == 0 && header.tos == 0;
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(value)) => {
                once(&mut destination, value)?
            }
            RouteAttribute::Table(value) => once(&mut table, value)?,
            RouteAttribute::Oif(value) => once(&mut interface, value)?,
            RouteAttribute::Priority(value) => once(&mut metric, value)?,
            RouteAttribute::PrefSource(RouteAddress::Inet(value)) => {
                once(&mut preferred_source, value)?
            }
            RouteAttribute::Gateway(RouteAddress::Inet(value)) => once(&mut gateway, value)?,
            // An unrepresentable destination cannot safely participate in conflict checks.
            RouteAttribute::Destination(_) => return Err(Cause::Protocol),
            _ => exact = false,
        }
    }
    let network = match destination {
        Some(value) => value,
        None if header.destination_prefix_length == 0 => Ipv4Addr::UNSPECIFIED,
        None => return Err(Cause::Protocol),
    };
    let mask = u32::MAX
        .checked_shl(u32::from(32 - header.destination_prefix_length))
        .unwrap_or(0);
    if u32::from(network) & mask != u32::from(network) {
        return Err(Cause::Protocol);
    }
    let table = table.unwrap_or(u32::from(header.table));
    if header.table != 0 && table != u32::from(header.table) {
        return Err(Cause::Protocol);
    }
    if interface == Some(0) {
        return Err(Cause::Protocol);
    }
    Ok(Entry {
        network,
        prefix_len: header.destination_prefix_length,
        table: NonZeroU32::new(table).ok_or(Cause::Protocol)?,
        interface: interface.and_then(NonZeroU32::new),
        metric,
        preferred_source,
        gateway,
        protocol: header.protocol.into(),
        scope: header.scope.into(),
        kind: header.kind.into(),
        exact,
    })
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Cause> {
    if slot.replace(value).is_some() {
        return Err(Cause::Protocol);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
