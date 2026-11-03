// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Narrow activation: change only IFF_UP on an already-owned interface.

use super::transaction::{self, Cause, Delivery, Failure, Wait};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkFlags, LinkMessage},
};

pub(super) fn is_up(index: u32, wait: &Wait) -> Result<bool, Failure> {
    let mut query = LinkMessage::default();
    query.header.index = index;
    let result = transaction::query(RouteNetlinkMessage::GetLink(query), wait)?;
    observed(result, index).map_err(|cause| Failure {
        delivery: Delivery::NotSent,
        cause,
    })
}

pub(super) fn enable(index: u32, wait: &Wait) -> Result<(), Failure> {
    transaction::mutate(enable_message(index), 0, wait)
}

fn enable_message(index: u32) -> RouteNetlinkMessage {
    let mut message = LinkMessage::default();
    message.header.index = index;
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;
    RouteNetlinkMessage::NewLink(message)
}
fn observed(message: RouteNetlinkMessage, index: u32) -> Result<bool, Cause> {
    match message {
        RouteNetlinkMessage::NewLink(message) if index != 0 && message.header.index == index => {
            Ok(message.header.flags.contains(LinkFlags::Up))
        }
        _ => Err(Cause::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_link_query_observes_loopback_without_mutation() {
        use std::time::Duration;
        use warper_core::transport::Request;
        let (_owner, cancellation) = tokio::sync::watch::channel(false);
        let wait = Wait::new(Request {
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
            cancellation,
        })
        .unwrap();
        let index = nix::net::if_::if_nametoindex("lo").unwrap();
        let flags = std::fs::read_to_string("/sys/class/net/lo/flags").unwrap();
        let flags = u32::from_str_radix(flags.trim().strip_prefix("0x").unwrap(), 16).unwrap();
        assert_eq!(
            is_up(index, &wait).unwrap(),
            flags & nix::libc::IFF_UP as u32 != 0
        );
    }
    #[test]
    fn activation_changes_only_up_without_create_or_replace_attributes() {
        let RouteNetlinkMessage::NewLink(message) = enable_message(9) else {
            unreachable!()
        };
        assert_eq!(message.header.index, 9);
        assert_eq!(message.header.flags, LinkFlags::Up);
        assert_eq!(message.header.change_mask, LinkFlags::Up);
        assert!(message.attributes.is_empty());
    }
    #[test]
    fn activation_readback_requires_the_requested_index_and_link_reply() {
        let mut message = LinkMessage::default();
        message.header.index = 9;
        assert_eq!(
            observed(RouteNetlinkMessage::NewLink(message.clone()), 9),
            Ok(false)
        );
        message.header.flags = LinkFlags::Up | LinkFlags::Running;
        assert_eq!(
            observed(RouteNetlinkMessage::NewLink(message.clone()), 9),
            Ok(true)
        );
        assert_eq!(
            observed(RouteNetlinkMessage::NewLink(message.clone()), 10),
            Err(Cause::Protocol)
        );
        assert_eq!(
            observed(RouteNetlinkMessage::GetLink(message), 9),
            Err(Cause::Protocol)
        );
    }
}
