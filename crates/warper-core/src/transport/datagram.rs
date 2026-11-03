// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Connected datagrams with explicit truncation and no hidden receive queue.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use super::{Error, Request};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Received {
    /// Initialized bytes copied, at most the caller's buffer length.
    pub length: usize,
    /// A truncated datagram must be discarded, never delivered as a full packet.
    pub truncated: bool,
}

/// One fixed remote peer per socket. One successful send is an entire datagram;
/// receive preserves boundaries, including zero-length datagrams. The caller
/// owns buffers, bounds waits and retains the socket through cancellation.
pub trait DatagramIo: Send + Unpin {
    fn poll_send(&mut self, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<()>>;
    fn poll_recv(
        &mut self,
        context: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<Received>>;
}

pub type Socket = Box<dyn DatagramIo>;
pub type OpenDatagram<'a> = Pin<Box<dyn Future<Output = Result<Socket, Error>> + Send + 'a>>;

/// Service-supplied verified physical path. No implementation may substitute an
/// unbound socket after a selected path fails. Opening owns no detached task.
pub trait DatagramConnector: Send + Sync {
    fn connect_udp(&self, endpoint: SocketAddr, request: Request) -> OpenDatagram<'_>;
}
