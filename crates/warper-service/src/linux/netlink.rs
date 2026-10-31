// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Private bounded socket construction shared by Linux read-only adapters.

use netlink_sys::{AsyncSocket, TokioSocket, protocols::NETLINK_ROUTE};
use std::io;

pub(super) const MAX_DATAGRAM: usize = 32768;

pub(super) enum Error {
    Io(io::Error),
    ResourceLimit,
    InvalidSocket,
}

pub(super) fn socket(groups: u32) -> Result<(TokioSocket, u32), Error> {
    let mut socket = TokioSocket::new(NETLINK_ROUTE).map_err(Error::Io)?;
    socket
        .socket_ref()
        .set_rx_buf_sz(MAX_DATAGRAM as i32)
        .map_err(Error::Io)?;
    if socket.socket_ref().get_rx_buf_sz().map_err(Error::Io)? > 2 * MAX_DATAGRAM {
        return Err(Error::ResourceLimit);
    }
    // Never suppress loss notifications on a monitoring or query socket.
    socket
        .socket_ref()
        .set_no_enobufs(false)
        .map_err(Error::Io)?;
    if socket.socket_ref().get_no_enobufs().map_err(Error::Io)? {
        return Err(Error::InvalidSocket);
    }
    socket
        .socket_ref()
        .set_netlink_get_strict_chk(true)
        .map_err(Error::Io)?;
    let address = netlink_sys::SocketAddr::new(0, groups);
    socket.socket_mut().bind(&address).map_err(Error::Io)?;
    let mut address = address;
    socket
        .socket_ref()
        .get_address(&mut address)
        .map_err(Error::Io)?;
    if address.port_number() == 0 || address.multicast_groups() != groups {
        return Err(Error::InvalidSocket);
    }
    Ok((socket, address.port_number()))
}
