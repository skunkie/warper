// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! A bounded, caller-owned subscription; any change or uncertainty invalidates.
//! This is not an atomic route snapshot or an authorization to send traffic.

use super::netlink::{self, MAX_DATAGRAM};
use netlink_packet_core::{NetlinkBuffer, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{AsyncSocket, SocketAddr, TokioSocket};
use nix::{errno::Errno, libc};
use std::{fmt, future::poll_fn, io};
use tokio::time::sleep_until;
use warper_core::transport::Request;

const GROUPS: u32 = libc::RTMGRP_LINK as u32
    | libc::RTMGRP_IPV4_IFADDR as u32
    | libc::RTMGRP_IPV6_IFADDR as u32
    | libc::RTMGRP_IPV4_ROUTE as u32
    | libc::RTMGRP_IPV6_ROUTE as u32
    | libc::RTMGRP_IPV4_RULE as u32
    | (1 << (libc::RTNLGRP_IPV6_RULE - 1));
const MAX_MESSAGES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ResourceLimit,
    InvalidSocket,
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResourceLimit => "ResourceLimit: network monitor queue exceeds budget",
            Self::InvalidSocket => "NativeProtocol: network monitor socket is invalid",
            Self::Io(_) => "NativeIo: cannot subscribe to network changes",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Invalidation {
    NetworkChanged,
    NotificationLost,
    InvalidMessage,
    UnexpectedSender,
    Io(io::ErrorKind),
    Cancelled,
    Timeout,
}

/// Subscribe before collecting route/link/address observations. There is no
/// internal task or event history. The first event/error closes the socket and
/// permanently invalidates this monitor. Replacing it requires fresh inspection.
/// Callers must reserve 32769 receive bytes plus bounded parse storage and a
/// kernel receive queue of at most 64 KiB. No packet contents escape this type.
pub struct Monitor {
    socket: Option<TokioSocket>,
    invalidation: Option<Invalidation>,
}

impl Monitor {
    pub fn subscribe() -> Result<Self, Error> {
        let (socket, _) = netlink::socket(GROUPS).map_err(|error| match error {
            netlink::Error::Io(error) => Error::Io(error.kind()),
            netlink::Error::ResourceLimit => Error::ResourceLimit,
            netlink::Error::InvalidSocket => Error::InvalidSocket,
        })?;
        Ok(Self {
            socket: Some(socket),
            invalidation: None,
        })
    }

    /// An empty kernel queue is only a momentary observation. It cannot close
    /// the race between a route lookup and a send or replace socket binding.
    pub fn check_pending(&mut self) -> Result<(), Invalidation> {
        if let Some(reason) = self.invalidation {
            return Err(reason);
        }
        let Some(socket) = &self.socket else {
            return Err(self.invalidate(Invalidation::InvalidMessage));
        };
        let mut buffer = [0; MAX_DATAGRAM + 1];
        let mut remaining = &mut buffer[..];
        let result = socket
            .socket_ref()
            .recv_from(&mut remaining, libc::MSG_DONTWAIT);
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(self.invalidate(io_invalidation(error))),
            Ok((length, sender)) => {
                let reason = classify(&buffer[..length], sender);
                Err(self.invalidate(reason))
            }
        }
    }

    /// Retain and await this future in the service supervisor. Dropping a
    /// pending future leaves the still-owned subscription intact; no packet is
    /// consumed across a suspension point. Cancellation/deadline invalidates.
    pub async fn wait(&mut self, mut request: Request) -> Invalidation {
        if let Some(reason) = self.invalidation {
            return reason;
        }
        let Some(socket) = &self.socket else {
            return self.invalidate(Invalidation::InvalidMessage);
        };
        let mut buffer = [0; MAX_DATAGRAM + 1];
        let mut remaining = &mut buffer[..];
        let received = tokio::select! { biased;
            _ = request.cancellation.wait_for(|cancelled| *cancelled) => Err(Invalidation::Cancelled),
            () = sleep_until(request.deadline) => Err(Invalidation::Timeout),
            result = poll_fn(|context| socket.poll_recv_from(context, &mut remaining)) => result.map_err(io_invalidation),
        };
        let length = MAX_DATAGRAM + 1 - remaining.len();
        let reason = match received {
            Err(reason) => reason,
            Ok(sender) => classify(&buffer[..length], sender),
        };
        self.invalidate(reason)
    }

    pub fn invalidation(&self) -> Option<Invalidation> {
        self.invalidation
    }

    fn invalidate(&mut self, reason: Invalidation) -> Invalidation {
        self.socket.take();
        *self.invalidation.get_or_insert(reason)
    }
}

fn io_invalidation(error: io::Error) -> Invalidation {
    if error.raw_os_error() == Some(Errno::ENOBUFS as i32) {
        Invalidation::NotificationLost
    } else {
        Invalidation::Io(error.kind())
    }
}

fn classify(mut bytes: &[u8], sender: SocketAddr) -> Invalidation {
    if sender.port_number() != 0 || sender.multicast_groups() & !GROUPS != 0 {
        return Invalidation::UnexpectedSender;
    }
    if bytes.len() > MAX_DATAGRAM {
        return Invalidation::NotificationLost;
    }
    if bytes.is_empty() {
        return Invalidation::InvalidMessage;
    }
    for _ in 0..MAX_MESSAGES {
        let buffer = match NetlinkBuffer::new_checked(bytes) {
            Ok(buffer) => buffer,
            Err(_) => return Invalidation::InvalidMessage,
        };
        let length = buffer.length() as usize;
        let message = match NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes[..length]) {
            Ok(message) => message,
            Err(_) => return Invalidation::InvalidMessage,
        };
        match message.payload {
            NetlinkPayload::InnerMessage(
                RouteNetlinkMessage::NewLink(_)
                | RouteNetlinkMessage::DelLink(_)
                | RouteNetlinkMessage::NewAddress(_)
                | RouteNetlinkMessage::DelAddress(_)
                | RouteNetlinkMessage::NewRoute(_)
                | RouteNetlinkMessage::DelRoute(_)
                | RouteNetlinkMessage::NewRule(_)
                | RouteNetlinkMessage::DelRule(_),
            ) => {}
            NetlinkPayload::Overrun(_) | NetlinkPayload::Error(_) => {
                return Invalidation::NotificationLost;
            }
            _ => return Invalidation::InvalidMessage,
        }
        // Netlink messages are four-byte aligned. A short tail is uncertainty;
        // never turn malformed input into an empty-queue observation.
        let aligned = (length + 3) & !3;
        bytes = match bytes.get(aligned..) {
            Some(bytes) => bytes,
            None => return Invalidation::InvalidMessage,
        };
        if bytes.is_empty() {
            return Invalidation::NetworkChanged;
        }
    }
    Invalidation::NotificationLost
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{ErrorMessage, NetlinkHeader};
    use netlink_packet_route::{
        address::AddressMessage, link::LinkMessage, route::RouteMessage, rule::RuleMessage,
    };
    use std::time::Duration;
    use tokio::{sync::watch, time::Instant};

    fn packet(payload: NetlinkPayload<RouteNetlinkMessage>) -> Vec<u8> {
        let mut message = NetlinkMessage::new(NetlinkHeader::default(), payload);
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        bytes
    }
    fn event(message: RouteNetlinkMessage) -> Vec<u8> {
        packet(NetlinkPayload::InnerMessage(message))
    }
    fn kernel() -> SocketAddr {
        SocketAddr::new(0, libc::RTMGRP_LINK as u32)
    }

    #[test]
    fn every_subscribed_change_invalidates_without_retaining_metadata() {
        for message in [
            RouteNetlinkMessage::NewLink(LinkMessage::default()),
            RouteNetlinkMessage::DelLink(LinkMessage::default()),
            RouteNetlinkMessage::NewAddress(AddressMessage::default()),
            RouteNetlinkMessage::DelAddress(AddressMessage::default()),
            RouteNetlinkMessage::NewRoute(RouteMessage::default()),
            RouteNetlinkMessage::DelRoute(RouteMessage::default()),
            RouteNetlinkMessage::NewRule(RuleMessage::default()),
            RouteNetlinkMessage::DelRule(RuleMessage::default()),
        ] {
            assert_eq!(
                classify(&event(message), kernel()),
                Invalidation::NetworkChanged
            );
        }
        let bytes = event(RouteNetlinkMessage::NewLink(LinkMessage::default()));
        for count in [1, 2, MAX_MESSAGES] {
            assert_eq!(
                classify(&bytes.repeat(count), kernel()),
                Invalidation::NetworkChanged
            );
        }
        assert_eq!(
            classify(&bytes.repeat(MAX_MESSAGES + 1), kernel()),
            Invalidation::NotificationLost
        );
    }

    #[test]
    fn malformed_foreign_and_lost_notifications_never_report_an_empty_queue() {
        let bytes = event(RouteNetlinkMessage::NewLink(LinkMessage::default()));
        for end in 0..bytes.len() {
            assert_eq!(
                classify(&bytes[..end], kernel()),
                Invalidation::InvalidMessage,
                "short input {end}"
            );
        }
        assert_eq!(
            classify(&bytes, SocketAddr::new(1, 0)),
            Invalidation::UnexpectedSender
        );
        assert_eq!(
            classify(&bytes, SocketAddr::new(0, libc::RTMGRP_NEIGH as u32)),
            Invalidation::UnexpectedSender
        );
        assert_eq!(
            classify(&vec![0; MAX_DATAGRAM + 1], kernel()),
            Invalidation::NotificationLost
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(classify(&trailing, kernel()), Invalidation::InvalidMessage);
        for payload in [
            NetlinkPayload::Noop,
            NetlinkPayload::Done(Default::default()),
        ] {
            assert_eq!(
                classify(&packet(payload), kernel()),
                Invalidation::InvalidMessage
            );
        }
        for payload in [
            NetlinkPayload::Overrun(vec![]),
            NetlinkPayload::Error(ErrorMessage::default()),
        ] {
            assert_eq!(
                classify(&packet(payload), kernel()),
                Invalidation::NotificationLost
            );
        }
        let mut malformed = bytes;
        malformed[0..4].copy_from_slice(&15u32.to_ne_bytes());
        assert_eq!(classify(&malformed, kernel()), Invalidation::InvalidMessage);
        assert_eq!(
            io_invalidation(io::Error::from_raw_os_error(Errno::ENOBUFS as i32)),
            Invalidation::NotificationLost
        );
        assert_eq!(
            io_invalidation(io::Error::from(io::ErrorKind::PermissionDenied)),
            Invalidation::Io(io::ErrorKind::PermissionDenied)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn native_subscription_closes_on_owner_loss_and_preserves_terminal_reason() {
        let mut monitor = Monitor::subscribe().unwrap();
        let (owner, cancellation) = watch::channel(false);
        drop(owner);
        assert_eq!(
            monitor
                .wait(Request {
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancellation
                })
                .await,
            Invalidation::Cancelled
        );
        assert_eq!(monitor.invalidation(), Some(Invalidation::Cancelled));
        assert_eq!(monitor.check_pending(), Err(Invalidation::Cancelled));
        let (_owner, cancellation) = watch::channel(false);
        assert_eq!(
            monitor
                .wait(Request {
                    deadline: Instant::now(),
                    cancellation
                })
                .await,
            Invalidation::Cancelled
        );
        let mut monitor = Monitor::subscribe().unwrap();
        let (_owner, cancellation) = watch::channel(false);
        assert_eq!(
            monitor
                .wait(Request {
                    deadline: Instant::now(),
                    cancellation
                })
                .await,
            Invalidation::Timeout
        );
        assert_eq!(monitor.check_pending(), Err(Invalidation::Timeout));
    }
}
