// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded address snapshots and exclusive initial IPv4 mutation.

use super::transaction::{
    self, Cause, Delivery, Failure, Wait, correlate, packet, receive, send, sequence, socket,
    validate_sender,
};
use crate::linux::netlink::MAX_DATAGRAM;
use netlink_packet_core::{
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkBuffer, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressFlags, AddressMessage, AddressScope},
};
use netlink_sys::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};

const MAX_DATAGRAMS: usize = 64;
const MAX_MESSAGES: usize = 2048;

#[derive(Default, Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) matches: usize,
    pub(super) owned_exact: usize,
}

/// Reject unexpected current state before mutation; after ACK require exactly
/// one owned /32 with no connected prefix route. Retain counts, never addresses.
pub(super) fn inspect(index: u32, address: Ipv4Addr, wait: &Wait) -> Result<Snapshot, Failure> {
    let result = (|| {
        wait.check()?;
        let (socket, port) = socket()?;
        let sequence = sequence()?;
        let mut query = AddressMessage::default();
        query.header.family = AddressFamily::Inet;
        let request = packet(
            RouteNetlinkMessage::GetAddress(query),
            NLM_F_REQUEST | NLM_F_DUMP,
            sequence,
            port,
        )?;
        send(&socket, &request, wait)?;
        let mut dump = Dump {
            sequence,
            port,
            index,
            address,
            snapshot: Snapshot::default(),
            messages: 0,
        };
        for _ in 0..MAX_DATAGRAMS {
            let mut bytes = [0; MAX_DATAGRAM + 1];
            let (length, sender) = receive(&socket, &mut bytes, wait)?;
            if dump.observe(&bytes[..length], sender)? {
                return Ok(dump.snapshot);
            }
        }
        Err(Cause::ResourceLimit)
    })();
    result.map_err(|cause| Failure {
        delivery: Delivery::NotSent,
        cause,
    })
}

struct Dump {
    sequence: u32,
    port: u32,
    index: u32,
    address: Ipv4Addr,
    snapshot: Snapshot,
    messages: usize,
}
impl Dump {
    fn observe(&mut self, bytes: &[u8], sender: SocketAddr) -> Result<bool, Cause> {
        validate_sender(sender)?;
        if bytes.len() > MAX_DATAGRAM {
            return Err(Cause::Lost);
        }
        if bytes.is_empty() {
            return Err(Cause::Protocol);
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            self.messages += 1;
            if self.messages > MAX_MESSAGES {
                return Err(Cause::ResourceLimit);
            }
            let envelope = NetlinkBuffer::new_checked(remaining).map_err(|_| Cause::Protocol)?;
            let length = envelope.length() as usize;
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&remaining[..length])
                .map_err(|_| Cause::Protocol)?;
            correlate(&message, self.sequence, self.port)?;
            let aligned = (length + 3) & !3;
            remaining = remaining.get(aligned..).ok_or(Cause::Protocol)?;
            match message.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(message)) => {
                    observe(&mut self.snapshot, message, self.index, self.address)?;
                }
                NetlinkPayload::Done(done) if done.code == 0 && remaining.is_empty() => {
                    return Ok(true);
                }
                NetlinkPayload::Error(error)
                    if error.raw_code() < 0 && error.raw_code() != i32::MIN =>
                {
                    return Err(Cause::Kernel(-error.raw_code()));
                }
                NetlinkPayload::Overrun(_) => return Err(Cause::Lost),
                _ => return Err(Cause::Protocol),
            }
        }
        Ok(false)
    }
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
