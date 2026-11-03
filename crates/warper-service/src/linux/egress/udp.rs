// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Source/device-bound connected UDP with retained native path invalidation.

use std::{
    io,
    io::IoSliceMut,
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU32,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SocketFlags, SocketType, ipproto,
    recvmsg, sockopt,
};
use tokio::{
    io::Interest,
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use warper_core::transport::{
    Request,
    datagram::{DatagramConnector, DatagramIo, OpenDatagram, Received, Socket},
};

use super::{
    Error, Monitor, PathInvalidated, Preparation as TcpPreparation, Wakes, bounded, context,
    io_error, route_lookup, transport_error, verify_link, verify_route,
};

pub const MAX_ASSOCIATIONS: usize = super::MAX_STREAMS;
pub const KERNEL_QUEUE_BYTES_PER_ASSOCIATION: usize = 3 * 65536;
const SOCKET_BUFFER: usize = 32768;
const MAX_PAYLOAD: usize = 65507;

/// Construct in a retained native worker; capture identity comes from its owner.
pub struct Preparation(TcpPreparation);

impl Preparation {
    pub fn new(
        context: Arc<context::Context>,
        endpoints: &[SocketAddr],
        excluded: NonZeroU32,
        limit: usize,
    ) -> Result<Self, Error> {
        let mut preparation = TcpPreparation::new(context, endpoints, excluded, limit)?;
        preparation.protocol = route_lookup::Protocol::Udp;
        Ok(Self(preparation))
    }

    pub async fn prepare(self, request: Request) -> Result<Connector, Error> {
        let super::Connector {
            paths,
            slots,
            context,
        } = self.0.prepare(request).await?;
        Ok(Connector {
            paths,
            slots,
            context,
        })
    }
}

pub struct Connector {
    paths: Box<[super::Path]>,
    slots: Arc<Semaphore>,
    context: Arc<context::Context>,
}

impl Connector {
    pub async fn connect(&self, endpoint: SocketAddr, request: Request) -> Result<Datagram, Error> {
        let SocketAddr::V4(endpoint) = endpoint else {
            return Err(Error::UnsupportedPath);
        };
        let path = self
            .paths
            .iter()
            .find(|path| path.endpoint == endpoint && path.protocol == route_lookup::Protocol::Udp)
            .ok_or(Error::InvalidInput)?;
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        bounded(request.clone(), async {
            let mut monitor = path.subscribe_changes().map_err(Error::Monitor)?;
            verify_link(path, request.clone()).await?;
            // Bound queue capacity before a local port can receive anything.
            let descriptor = rustix::net::socket_with(
                AddressFamily::INET,
                SocketType::DGRAM,
                SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
                Some(ipproto::UDP),
            )
            .map_err(|error| Error::Io(error.kind()))?;
            let socket =
                UdpSocket::from_std(std::net::UdpSocket::from(descriptor)).map_err(io_error)?;
            sockopt::set_socket_recv_buffer_size(&socket, SOCKET_BUFFER)
                .map_err(|error| Error::Io(error.kind()))?;
            sockopt::set_socket_send_buffer_size(&socket, SOCKET_BUFFER)
                .map_err(|error| Error::Io(error.kind()))?;
            if sockopt::socket_recv_buffer_size(&socket).map_err(|error| Error::Io(error.kind()))?
                > 2 * SOCKET_BUFFER
                || sockopt::socket_send_buffer_size(&socket)
                    .map_err(|error| Error::Io(error.kind()))?
                    > 2 * SOCKET_BUFFER
            {
                return Err(Error::ResourceLimit);
            }
            socket
                .bind_device(Some(path.link.name.as_bytes()))
                .map_err(io_error)?;
            if socket.device().map_err(io_error)?.as_deref() != Some(path.link.name.as_bytes()) {
                return Err(Error::PathMismatch);
            }
            rustix::net::bind(&socket, &SocketAddrV4::new(path.route.source, 0))
                .map_err(|error| Error::Io(error.kind()))?;
            let SocketAddr::V4(source) = socket.local_addr().map_err(io_error)? else {
                return Err(Error::PathMismatch);
            };
            if source.ip() != &path.route.source || source.port() == 0 {
                return Err(Error::PathMismatch);
            }
            verify_route(path, source, request.clone()).await?;
            monitor.check_pending().map_err(Error::Changed)?;
            socket
                .connect(SocketAddr::V4(endpoint))
                .await
                .map_err(io_error)?;
            if socket.local_addr().map_err(io_error)? != SocketAddr::V4(source)
                || socket.peer_addr().map_err(io_error)? != SocketAddr::V4(endpoint)
            {
                return Err(Error::PathMismatch);
            }
            verify_route(path, source, request.clone()).await?;
            verify_link(path, request).await?;
            monitor.check_pending().map_err(Error::Changed)?;
            let wakes = Arc::new(Wakes::default());
            Ok(Datagram {
                socket: Some(socket),
                monitor,
                monitor_waker: Waker::from(wakes.clone()),
                wakes,
                source,
                endpoint,
                _slot: slot,
                _context: self.context.clone(),
            })
        })
        .await
    }
}

impl DatagramConnector for Connector {
    fn connect_udp(&self, endpoint: SocketAddr, request: Request) -> OpenDatagram<'_> {
        Box::pin(async move {
            self.connect(endpoint, request)
                .await
                .map(|socket| Box::new(socket) as Socket)
                .map_err(transport_error)
        })
    }
}

/// Socket and monitor drop before admission and the protected native context.
pub struct Datagram {
    socket: Option<UdpSocket>,
    monitor: Monitor,
    monitor_waker: Waker,
    wakes: Arc<Wakes>,
    source: SocketAddrV4,
    endpoint: SocketAddrV4,
    _slot: OwnedSemaphorePermit,
    _context: Arc<context::Context>,
}

impl Datagram {
    pub fn source(&self) -> SocketAddrV4 {
        self.source
    }
    pub fn endpoint(&self) -> SocketAddrV4 {
        self.endpoint
    }

    fn healthy(&mut self, context: &Context<'_>, direction: usize) -> io::Result<()> {
        if self.wakes.register(context.waker(), direction).is_err() {
            self.socket.take();
            return Err(io::ErrorKind::Other.into());
        }
        let mut context = Context::from_waker(&self.monitor_waker);
        if let Poll::Ready(reason) = self.monitor.poll_invalidation(&mut context) {
            self.socket.take();
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                PathInvalidated(reason),
            ));
        }
        if self.socket.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        Ok(())
    }
}

impl DatagramIo for Datagram {
    fn poll_send(&mut self, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<()>> {
        self.healthy(context, 1)?;
        if bytes.len() > MAX_PAYLOAD {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let socket = self.socket.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        match socket.poll_send(context, bytes) {
            Poll::Ready(Ok(length)) if length == bytes.len() => Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_recv(
        &mut self,
        context: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<Received>> {
        self.healthy(context, 0)?;
        let socket = self.socket.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        loop {
            match socket.poll_recv_ready(context) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            match socket.try_io(Interest::READABLE, || {
                receive(socket, bytes, self.endpoint.into())
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
}

fn receive(socket: &UdpSocket, bytes: &mut [u8], peer: SocketAddr) -> io::Result<Received> {
    let capacity = bytes.len();
    let mut slices = [IoSliceMut::new(bytes)];
    let mut ancillary = RecvAncillaryBuffer::new(&mut []);
    let received =
        recvmsg(socket, &mut slices, &mut ancillary, RecvFlags::TRUNC).map_err(io::Error::from)?;
    // A datagram queued between bind and connect must not bypass peer checks.
    if received
        .address
        .and_then(|address| SocketAddr::try_from(address).ok())
        != Some(peer)
        || received.flags.contains(ReturnFlags::CTRUNC)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Received {
        length: received.bytes.min(capacity),
        truncated: received.flags.contains(ReturnFlags::TRUNC) || received.bytes > capacity,
    })
}

#[cfg(test)]
mod tests;
