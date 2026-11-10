// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded address snapshots and exclusive initial IPv4 mutation.

use super::transaction::{self, Cause, Delivery, Failure, Wait};
use netlink_packet_core::{NLM_F_CREATE, NLM_F_EXCL};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressFlags, AddressMessage, AddressScope},
};
use std::net::{IpAddr, Ipv4Addr};

const MAX_MESSAGES: usize = 2048;

#[derive(Default, Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) matches: usize,
    pub(super) owned_exact: usize,
}

/// Reject unexpected current state before mutation; after ACK require exactly
/// one owned /32 with no connected prefix route. Retain counts, never addresses.
pub(super) fn inspect(index: u32, address: Ipv4Addr, wait: &Wait) -> Result<Snapshot, Failure> {
    let mut query = AddressMessage::default();
    query.header.family = AddressFamily::Inet;
    transaction::dump(
        RouteNetlinkMessage::GetAddress(query),
        wait,
        MAX_MESSAGES,
        64,
        Snapshot::default(),
        |snapshot, message| match message {
            RouteNetlinkMessage::NewAddress(message) => observe(snapshot, message, index, address),
            _ => Err(Cause::Protocol),
        },
    )
    .map_err(|cause| Failure {
        delivery: Delivery::NotSent,
        cause,
    })
}

pub(super) fn add(index: u32, address: Ipv4Addr, wait: &Wait) -> Result<(), Failure> {
    transaction::mutate(add_message(index, address), NLM_F_CREATE | NLM_F_EXCL, wait)
}

fn add_message(index: u32, address: Ipv4Addr) -> RouteNetlinkMessage {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.prefix_len = 32;
    message.header.index = index;
    message.attributes = vec![
        AddressAttribute::Local(IpAddr::V4(address)),
        AddressAttribute::Address(IpAddr::V4(address)),
        AddressAttribute::Flags(AddressFlags::Permanent | AddressFlags::Noprefixroute),
    ];
    RouteNetlinkMessage::NewAddress(message)
}
fn observe(
    snapshot: &mut Snapshot,
    message: AddressMessage,
    index: u32,
    address: Ipv4Addr,
) -> Result<(), Cause> {
    if message.header.family != AddressFamily::Inet
        || message.header.index == 0
        || message.header.prefix_len > 32
    {
        return Err(Cause::Protocol);
    }
    let mut local = None;
    let mut peer = None;
    let mut flags = None;
    for attribute in message.attributes {
        match attribute {
            AddressAttribute::Local(value) => once(&mut local, value)?,
            AddressAttribute::Address(value) => once(&mut peer, value)?,
            AddressAttribute::Flags(value) => once(&mut flags, value)?,
            _ => {}
        }
    }
    let target = IpAddr::V4(address);
    if local == Some(target) || peer == Some(target) {
        snapshot.matches += 1;
        if local == Some(target)
            && peer == Some(target)
            && message.header.index == index
            && message.header.prefix_len == 32
            && message.header.scope == AddressScope::Universe
            && flags == Some(AddressFlags::Noprefixroute | AddressFlags::Permanent)
        {
            snapshot.owned_exact += 1;
        }
    }
    Ok(())
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Cause> {
    if slot.replace(value).is_some() {
        return Err(Cause::Protocol);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
