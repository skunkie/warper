// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Read-only admission observation for the initial ordinary IPv4 rule layout.

pub use super::QueryError as Error;
use super::transaction::{self, Cause, Wait};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use warper_core::transport::Request;

pub const MAX_RULES: usize = 64;

/// Complete dump classification, never mutation authority or a stable snapshot.
#[derive(Debug, Eq, PartialEq)]
pub struct Inventory {
    rules: usize,
    tables: u8,
    unsupported: bool,
}
impl Inventory {
    pub fn rules(&self) -> usize {
        self.rules
    }
    /// Exactly the three unconditional local/main/default rules were observed.
    pub fn is_default_layout(&self) -> bool {
        self.rules == 3 && self.tables == 7 && !self.unsupported
    }
    fn observe(&mut self, message: RouteNetlinkMessage) -> Result<(), Cause> {
        let RouteNetlinkMessage::NewRule(message) = message else {
            return Err(Cause::Protocol);
        };
        if self.rules == MAX_RULES {
            return Err(Cause::ResourceLimit);
        }
        self.rules += 1;
        match table_bit(message)? {
            Some(bit) if self.tables & bit == 0 => self.tables |= bit,
            _ => self.unsupported = true,
        }
        Ok(())
    }
}

/// Run in a retained worker, bounding concurrent calls externally. Custom policy
/// routing produces an unsupported observation without changing host rules.
pub fn inspect(request: Request) -> Result<Inventory, Error> {
    let wait = Wait::new(request).map_err(transaction::query_error)?;
    let mut query = RuleMessage::default();
    query.header.family = AddressFamily::Inet;
    transaction::dump(
        RouteNetlinkMessage::GetRule(query),
        &wait,
        MAX_RULES + 1,
        64,
        Inventory {
            rules: 0,
            tables: 0,
            unsupported: false,
        },
        Inventory::observe,
    )
    .map_err(transaction::query_error)
}

fn table_bit(message: RuleMessage) -> Result<Option<u8>, Cause> {
    let header = message.header;
    if header.family != AddressFamily::Inet || header.dst_len > 32 || header.src_len > 32 {
        return Err(Cause::Protocol);
    }
    let mut supported = header.dst_len == 0
        && header.src_len == 0
        && header.tos == 0
        && header.flags.is_empty()
        && header.action == RuleAction::ToTable;
    let mut table = None;
    let mut priority = None;
    let mut protocol = None;
    let mut suppression = None;
    for attribute in message.attributes {
        match attribute {
            RuleAttribute::Table(value) => once(&mut table, value)?,
            RuleAttribute::Priority(value) => once(&mut priority, value)?,
            RuleAttribute::Protocol(value) => once(&mut protocol, value)?,
            RuleAttribute::SuppressPrefixLen(value) => once(&mut suppression, value)?,
            _ => supported = false,
        }
    }
    let table = table.unwrap_or(u32::from(header.table));
    if header.table != 0 && table != u32::from(header.table) {
        return Err(Cause::Protocol);
    }
    supported &= suppression.is_none_or(|value| value == u32::MAX);
    Ok(if supported {
        match (priority.unwrap_or(0), table) {
            (0, 255) => Some(1),
            (32766, 254) => Some(2),
            (32767, 253) => Some(4),
            _ => None,
        }
    } else {
        None
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
