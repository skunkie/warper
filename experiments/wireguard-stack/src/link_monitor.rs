// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded Linux link and route notification experiments.

use std::{
    fmt,
    io::IoSliceMut,
    os::fd::{AsRawFd, OwnedFd},
};

use nix::{
    errno::Errno,
    net::if_::if_nametoindex,
    sys::socket::{self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    InvalidMessage,
    Lost,
    UnexpectedSender,
    Socket(Errno),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "network notification: {self:?}")
    }
}

impl std::error::Error for Error {}

pub(super) struct Monitor {
    socket: OwnedFd,
    scope: Scope,
}

#[derive(Clone, Copy)]
enum Scope {
    Link(u32),
    Route,
}

impl Monitor {
    pub(super) fn new(name: &str) -> Result<Self, Error> {
        let socket = Self::subscribe(nix::libc::RTMGRP_LINK as u32)?;
        let interface = if_nametoindex(name).map_err(Error::Socket)?;
        Ok(Self {
            socket,
            scope: Scope::Link(interface),
        })
    }

    pub(super) fn routes() -> Result<Self, Error> {
        let groups = nix::libc::RTMGRP_IPV4_ROUTE as u32
            | nix::libc::RTMGRP_IPV6_ROUTE as u32
            | nix::libc::RTMGRP_IPV4_RULE as u32
            | (1_u32 << (nix::libc::RTNLGRP_IPV6_RULE - 1));
        let socket = Self::subscribe(groups)?;
        Ok(Self {
            socket,
            scope: Scope::Route,
        })
    }

    fn subscribe(groups: u32) -> Result<OwnedFd, Error> {
        let socket = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )
        .map_err(Error::Socket)?;
        socket::bind(socket.as_raw_fd(), &NetlinkAddr::new(0, groups)).map_err(Error::Socket)?;
        Ok(socket)
    }

    pub(super) fn poll(&self) -> Result<bool, Error> {
        let mut buffer = [0; 8192];
        let mut slices = [IoSliceMut::new(&mut buffer)];
        let received = match socket::recvmsg::<NetlinkAddr>(
            self.socket.as_raw_fd(),
            &mut slices,
            None,
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(received) => received,
            Err(Errno::EAGAIN) => return Ok(false),
            Err(Errno::ENOBUFS) => return Err(Error::Lost),
            Err(error) => return Err(Error::Socket(error)),
        };
        let length = received.bytes;
        let sender = received.address.map(|address| address.pid());
        let flags = received.flags;
        let bytes = buffer.get(..length).ok_or(Error::Lost)?;
        classify(bytes, sender, flags, self.scope)
    }
}

fn classify(
    bytes: &[u8],
    sender: Option<u32>,
    flags: MsgFlags,
    scope: Scope,
) -> Result<bool, Error> {
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err(Error::Lost);
    }
    if sender != Some(0) {
        return Err(Error::UnexpectedSender);
    }
    parse(bytes, scope)
}

pub(super) fn apply(
    owner: &mut crate::outer_owner::Owner,
    notification: Result<bool, Error>,
) -> Result<bool, Error> {
    match notification {
        Ok(false) => Ok(false),
        Ok(true) => {
            owner.invalidate_path();
            Ok(true)
        }
        Err(error) => {
            owner.invalidate_path();
            Err(error)
        }
    }
}

fn parse(bytes: &[u8], scope: Scope) -> Result<bool, Error> {
    let mut remaining = bytes;
    let mut changed = false;
    if remaining.is_empty() {
        return Err(Error::InvalidMessage);
    }
    while !remaining.is_empty() {
        let header = remaining.get(..16).ok_or(Error::InvalidMessage)?;
        let length =
            u32::from_ne_bytes(header[..4].try_into().map_err(|_| Error::InvalidMessage)?) as usize;
        let kind = u16::from_ne_bytes(header[4..6].try_into().map_err(|_| Error::InvalidMessage)?);
        if length < 16 || length > remaining.len() {
            return Err(Error::InvalidMessage);
        }
        if kind == nix::libc::NLMSG_OVERRUN as u16 || kind == nix::libc::NLMSG_ERROR as u16 {
            return Err(Error::Lost);
        }
        let body = remaining.get(16..length).ok_or(Error::InvalidMessage)?;
        match scope {
            Scope::Link(interface) => {
                if kind != nix::libc::RTM_NEWLINK && kind != nix::libc::RTM_DELLINK {
                    return Err(Error::InvalidMessage);
                }
                let index = body.get(4..8).ok_or(Error::InvalidMessage)?;
                let index =
                    i32::from_ne_bytes(index.try_into().map_err(|_| Error::InvalidMessage)?);
                if index <= 0 || body.len() < 16 {
                    return Err(Error::InvalidMessage);
                }
                changed |= index as u32 == interface;
            }
            Scope::Route => {
                if !matches!(
                    kind,
                    nix::libc::RTM_NEWROUTE
                        | nix::libc::RTM_DELROUTE
                        | nix::libc::RTM_NEWRULE
                        | nix::libc::RTM_DELRULE
                ) || body.len() < 12
                    || (body[0] != nix::libc::AF_INET as u8 && body[0] != nix::libc::AF_INET6 as u8)
                {
                    return Err(Error::InvalidMessage);
                }
                changed = true;
            }
        }
        let aligned = length.checked_add(3).ok_or(Error::InvalidMessage)? & !3;
        remaining = remaining.get(aligned..).ok_or(Error::InvalidMessage)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(index: i32) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        bytes[..4].copy_from_slice(&32_u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&nix::libc::RTM_NEWLINK.to_ne_bytes());
        bytes[20..24].copy_from_slice(&index.to_ne_bytes());
        bytes
    }

    #[test]
    fn parser_rejects_loss_and_malformed_messages_and_identifies_target() {
        let mut messages = link(2);
        messages.extend(link(3));
        assert_eq!(parse(&messages, Scope::Link(3)), Ok(true));
        assert_eq!(parse(&messages, Scope::Link(4)), Ok(false));
        assert_eq!(
            parse(&messages[..48], Scope::Link(2)),
            Err(Error::InvalidMessage)
        );
        assert_eq!(parse(&[], Scope::Link(3)), Err(Error::InvalidMessage));
        assert_eq!(parse(&[0; 8], Scope::Link(3)), Err(Error::InvalidMessage));
        assert_eq!(
            parse(&messages[..31], Scope::Link(3)),
            Err(Error::InvalidMessage)
        );
        let mut short_body = link(3);
        short_body[..4].copy_from_slice(&20_u32.to_ne_bytes());
        assert_eq!(
            parse(&short_body[..20], Scope::Link(3)),
            Err(Error::InvalidMessage)
        );
        short_body[..4].copy_from_slice(&24_u32.to_ne_bytes());
        assert_eq!(
            parse(&short_body[..24], Scope::Link(3)),
            Err(Error::InvalidMessage)
        );
        let mut missing_padding = link(3);
        missing_padding.push(0);
        missing_padding[..4].copy_from_slice(&33_u32.to_ne_bytes());
        assert_eq!(
            parse(&missing_padding, Scope::Link(3)),
            Err(Error::InvalidMessage)
        );
        let mut removed = link(3);
        removed[4..6].copy_from_slice(&nix::libc::RTM_DELLINK.to_ne_bytes());
        assert_eq!(parse(&removed, Scope::Link(3)), Ok(true));
        let mut malformed = link(0);
        assert_eq!(
            parse(&malformed, Scope::Link(3)),
            Err(Error::InvalidMessage)
        );
        malformed[4..6].copy_from_slice(&(nix::libc::NLMSG_OVERRUN as u16).to_ne_bytes());
        assert_eq!(parse(&malformed, Scope::Link(3)), Err(Error::Lost));
        malformed[4..6].copy_from_slice(&(nix::libc::NLMSG_ERROR as u16).to_ne_bytes());
        assert_eq!(parse(&malformed, Scope::Link(3)), Err(Error::Lost));
        malformed[4..6].copy_from_slice(&999_u16.to_ne_bytes());
        assert_eq!(
            parse(&malformed, Scope::Link(3)),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            classify(&messages, None, MsgFlags::empty(), Scope::Link(3)),
            Err(Error::UnexpectedSender)
        );
        assert_eq!(
            classify(&messages, Some(7), MsgFlags::empty(), Scope::Link(3)),
            Err(Error::UnexpectedSender)
        );
        assert_eq!(
            classify(&messages, Some(0), MsgFlags::MSG_TRUNC, Scope::Link(3)),
            Err(Error::Lost)
        );
        assert_eq!(
            classify(&messages, Some(0), MsgFlags::MSG_CTRUNC, Scope::Link(3)),
            Err(Error::Lost)
        );
        assert_eq!(
            classify(&messages, Some(0), MsgFlags::empty(), Scope::Link(3)),
            Ok(true)
        );
    }

    #[test]
    fn route_notifications_invalidate_conservatively_and_reject_malformed_records() {
        let mut route = vec![0; 28];
        route[..4].copy_from_slice(&28_u32.to_ne_bytes());
        route[4..6].copy_from_slice(&nix::libc::RTM_NEWROUTE.to_ne_bytes());
        route[16] = nix::libc::AF_INET as u8;
        assert_eq!(parse(&route, Scope::Route), Ok(true));
        route[4..6].copy_from_slice(&nix::libc::RTM_DELROUTE.to_ne_bytes());
        route[16] = nix::libc::AF_INET6 as u8;
        assert_eq!(parse(&route, Scope::Route), Ok(true));
        for kind in [nix::libc::RTM_NEWRULE, nix::libc::RTM_DELRULE] {
            route[4..6].copy_from_slice(&kind.to_ne_bytes());
            for family in [nix::libc::AF_INET, nix::libc::AF_INET6] {
                route[16] = family as u8;
                assert_eq!(parse(&route, Scope::Route), Ok(true));
            }
        }
        route[16] = 255;
        assert_eq!(parse(&route, Scope::Route), Err(Error::InvalidMessage));
        route[..4].copy_from_slice(&20_u32.to_ne_bytes());
        assert_eq!(
            parse(&route[..20], Scope::Route),
            Err(Error::InvalidMessage)
        );
        assert_eq!(parse(&link(3), Scope::Route), Err(Error::InvalidMessage));
    }
}
