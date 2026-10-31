// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Source/device-bound IPv4 TCP with current tuple proof and per-stream changes.
//! Preparation is selection evidence; every dial verifies a fresh generation.

use super::{
    QueryError,
    change_monitor::{self, Invalidation, Monitor},
    context, link_lookup, route_lookup,
};
use std::{
    fmt,
    future::Future,
    io,
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::sleep_until,
};
use warper_core::transport::{self, EndpointConnector, OpenTcp, Request};

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_STREAMS: usize = 16;
pub const KERNEL_QUEUE_BYTES_PER_STREAM: usize = 3 * 65536;
const SOCKET_BUFFER: u32 = 32768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInput,
    ResourceLimit,
    Context(context::Error),
    Query(QueryError),
    Monitor(change_monitor::Error),
    Changed(Invalidation),
    UnsupportedPath,
    PathMismatch,
    Cancelled,
    Deadline,
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "InvalidConfig: invalid protected TCP preparation",
            Self::ResourceLimit => {
                "ResourceLimit: protected TCP admission or queue budget exceeded"
            }
            Self::Context(_) => "Authentication: protected TCP native context failed",
            Self::Query(_) | Self::UnsupportedPath => {
                "UnsupportedIntegration: protected TCP path is unavailable"
            }
            Self::Monitor(_) | Self::Changed(_) | Self::PathMismatch => {
                "NativeUncertain: protected TCP path changed or cannot be verified"
            }
            Self::Cancelled => "Cancelled: protected TCP setup cancelled",
            Self::Deadline => "Timeout: protected TCP setup deadline expired",
            Self::Io(_) => "NativeIo: protected TCP socket failed",
        })
    }
}
impl std::error::Error for Error {}

/// Construct this in a retained native worker. The capture index comes from
/// the currently retained TUN owner, never a stored or caller-provided identity.
pub struct Preparation {
    endpoints: Box<[SocketAddrV4]>,
    excluded: NonZeroU32,
    limit: usize,
    context: Arc<context::Context>,
}
impl Preparation {
    pub fn new(
        context: Arc<context::Context>,
        endpoints: &[SocketAddr],
        excluded: NonZeroU32,
        limit: usize,
    ) -> Result<Self, Error> {
        if endpoints.is_empty()
            || endpoints.len() > MAX_ENDPOINTS
            || !(1..=MAX_STREAMS).contains(&limit)
            || excluded.get() > i32::MAX as u32
        {
            return Err(Error::InvalidInput);
        }
        let mut values = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let SocketAddr::V4(endpoint) = endpoint else {
                return Err(Error::UnsupportedPath);
            };
            if endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast()
                || endpoint.ip().is_broadcast()
            {
                return Err(Error::InvalidInput);
            }
            values.push(*endpoint);
        }
        values.sort_unstable();
        values.dedup();
        context.revalidate().map_err(Error::Context)?;
        Ok(Self {
            endpoints: values.into_boxed_slice(),
            excluded,
            limit,
            context,
        })
    }
    pub async fn prepare(self, request: Request) -> Result<Connector, Error> {
        bounded(request.clone(), async {
            let mut monitor = Monitor::subscribe().map_err(Error::Monitor)?;
            let mut paths = Vec::with_capacity(self.endpoints.len());
            for endpoint in self.endpoints {
                let route = route_lookup::lookup(
                    route_lookup::Query {
                        destination: endpoint,
                        source: None,
                        interface: None,
                    },
                    request.clone(),
                )
                .await
                .map_err(Error::Query)?;
                let link = link_lookup::lookup(
                    link_lookup::Query::Index(route.interface),
                    request.clone(),
                )
                .await
                .map_err(Error::Query)?;
                if !supported(endpoint, route, &link, self.excluded) {
                    return Err(Error::UnsupportedPath);
                }
                monitor.check_pending().map_err(Error::Changed)?;
                paths.push(Path {
                    endpoint,
                    route,
                    link,
                });
            }
            monitor.check_pending().map_err(Error::Changed)?;
            Ok(Connector {
                paths: paths.into_boxed_slice(),
                slots: Arc::new(Semaphore::new(self.limit)),
                context: self.context,
            })
        })
        .await
    }
}

struct Path {
    endpoint: SocketAddrV4,
    route: route_lookup::Observation,
    link: link_lookup::Observation,
}

/// Immutable deterministic path selection, with no default or alternate dial.
/// Every stream/result retains admission and native context until full drop.
pub struct Connector {
    paths: Box<[Path]>,
    slots: Arc<Semaphore>,
    context: Arc<context::Context>,
}
impl Connector {
    pub async fn connect(&self, endpoint: SocketAddr, request: Request) -> Result<Stream, Error> {
        let SocketAddr::V4(endpoint) = endpoint else {
            return Err(Error::UnsupportedPath);
        };
        let path = self
            .paths
            .iter()
            .find(|path| path.endpoint == endpoint)
            .ok_or(Error::InvalidInput)?;
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        bounded(request.clone(), async {
            let mut monitor = Monitor::subscribe().map_err(Error::Monitor)?;
            verify_link(path, request.clone()).await?;
            let socket = TcpSocket::new_v4().map_err(io_error)?;
            socket
                .set_recv_buffer_size(SOCKET_BUFFER)
                .map_err(io_error)?;
            socket
                .set_send_buffer_size(SOCKET_BUFFER)
                .map_err(io_error)?;
            if socket.recv_buffer_size().map_err(io_error)? > 2 * SOCKET_BUFFER
                || socket.send_buffer_size().map_err(io_error)? > 2 * SOCKET_BUFFER
            {
                return Err(Error::ResourceLimit);
            }
            socket
                .bind_device(Some(path.link.name.as_bytes()))
                .map_err(io_error)?;
            socket
                .bind(SocketAddrV4::new(path.route.source, 0).into())
                .map_err(io_error)?;
            if socket.device().map_err(io_error)?.as_deref() != Some(path.link.name.as_bytes()) {
                return Err(Error::PathMismatch);
            }
            let SocketAddr::V4(source) = socket.local_addr().map_err(io_error)? else {
                return Err(Error::PathMismatch);
            };
            if source.ip() != &path.route.source || source.port() == 0 {
                return Err(Error::PathMismatch);
            }
            verify_route(path, source, request.clone()).await?;
            monitor.check_pending().map_err(Error::Changed)?;
            let stream = tokio::select! { biased;
                reason=monitor.wait(request.clone())=>return Err(Error::Changed(reason)),
                result=socket.connect(endpoint.into())=>result.map_err(io_error)?,
            };
            if stream.local_addr().map_err(io_error)? != SocketAddr::V4(source)
                || stream.peer_addr().map_err(io_error)? != SocketAddr::V4(endpoint)
            {
                return Err(Error::PathMismatch);
            }
            verify_route(path, source, request.clone()).await?;
            verify_link(path, request).await?;
            monitor.check_pending().map_err(Error::Changed)?;
            let wakes = Arc::new(Wakes::default());
            Ok(Stream {
                socket: Some(stream),
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
impl EndpointConnector for Connector {
    fn connect_tcp(&self, endpoint: SocketAddr, request: Request) -> OpenTcp<'_> {
        Box::pin(async move {
            self.connect(endpoint, request)
                .await
                .map(|stream| Box::new(stream) as transport::TcpStream)
                .map_err(transport_error)
        })
    }
}
impl fmt::Debug for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedTcpConnector(<redacted>)")
    }
}

/// Original tuple is observable, but no raw socket, monitor or reconfiguration
/// escapes. Half-close does not release its permit or remaining read side.
pub struct Stream {
    socket: Option<TcpStream>,
    monitor: Monitor,
    monitor_waker: Waker,
    wakes: Arc<Wakes>,
    source: SocketAddrV4,
    endpoint: SocketAddrV4,
    _slot: OwnedSemaphorePermit,
    _context: Arc<context::Context>,
}
impl Stream {
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
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.healthy(context, 0)?;
        Pin::new(this.socket.as_mut().ok_or(io::ErrorKind::NotConnected)?)
            .poll_read(context, buffer)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.healthy(context, 1)?;
        Pin::new(this.socket.as_mut().ok_or(io::ErrorKind::NotConnected)?)
            .poll_write(context, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.healthy(context, 1)?;
        Pin::new(this.socket.as_mut().ok_or(io::ErrorKind::NotConnected)?).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.healthy(context, 1)?;
        Pin::new(this.socket.as_mut().ok_or(io::ErrorKind::NotConnected)?).poll_shutdown(context)
    }
}
impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedTcpStream(<redacted>)")
    }
}

#[derive(Debug)]
pub struct PathInvalidated(pub Invalidation);
impl fmt::Display for PathInvalidated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("verified TCP path invalidated")
    }
}
impl std::error::Error for PathInvalidated {}

#[derive(Default)]
struct Wakes(Mutex<[Option<Waker>; 2]>);
impl Wakes {
    fn register(&self, waker: &Waker, direction: usize) -> Result<(), ()> {
        let mut slots = self.0.lock().map_err(|_| ())?;
        if !slots[direction]
            .as_ref()
            .is_some_and(|stored| stored.will_wake(waker))
        {
            slots[direction] = Some(waker.clone());
        }
        Ok(())
    }
}
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        // A poisoned waker table is never used to continue I/O: registration
        // fails closed. Still wake both old waiters so they can surface it.
        let slots = match self.0.lock() {
            Ok(slots) => slots.clone(),
            Err(error) => error.into_inner().clone(),
        };
        for waker in slots.into_iter().flatten() {
            waker.wake();
        }
    }
}

fn supported(
    endpoint: SocketAddrV4,
    route: route_lookup::Observation,
    link: &link_lookup::Observation,
    excluded: NonZeroU32,
) -> bool {
    if link.index != route.interface
        || link.index == excluded
        || link.flags & nix::libc::IFF_UP as u32 == 0
    {
        return false;
    }
    match (route.kind, link.kind) {
        (route_lookup::Kind::Unicast, link_lookup::Kind::Ethernet | link_lookup::Kind::Veth) => {
            !endpoint.ip().is_loopback() && !route.source.is_loopback()
        }
        (route_lookup::Kind::Local, link_lookup::Kind::Loopback) => {
            endpoint.ip().is_loopback() && route.source.is_loopback() && route.gateway.is_none()
        }
        _ => false,
    }
}
async fn verify_link(path: &Path, request: Request) -> Result<(), Error> {
    let current = link_lookup::lookup(link_lookup::Query::Index(path.link.index), request)
        .await
        .map_err(Error::Query)?;
    if current != path.link {
        return Err(Error::PathMismatch);
    }
    Ok(())
}
async fn verify_route(path: &Path, source: SocketAddrV4, request: Request) -> Result<(), Error> {
    let current = route_lookup::lookup(
        route_lookup::Query {
            destination: path.endpoint,
            source: Some(source),
            interface: Some(path.link.index),
        },
        request,
    )
    .await
    .map_err(Error::Query)?;
    if current != path.route {
        return Err(Error::PathMismatch);
    }
    Ok(())
}
async fn bounded<T>(
    mut request: Request,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    tokio::select! { biased;
        _=request.cancellation.wait_for(|cancelled|*cancelled)=>Err(Error::Cancelled),
        ()=sleep_until(request.deadline)=>Err(Error::Deadline),
        result=operation=>result,
    }
}
fn io_error(error: io::Error) -> Error {
    Error::Io(error.kind())
}
fn transport_error(error: Error) -> transport::Error {
    match error {
        Error::InvalidInput => transport::Error::InvalidDestination,
        Error::ResourceLimit
        | Error::Query(QueryError::ResourceLimit)
        | Error::Monitor(change_monitor::Error::ResourceLimit) => transport::Error::ResourceLimit,
        Error::Cancelled
        | Error::Query(QueryError::Cancelled)
        | Error::Changed(Invalidation::Cancelled) => transport::Error::Cancelled,
        Error::Deadline
        | Error::Query(QueryError::Timeout)
        | Error::Changed(Invalidation::Timeout) => transport::Error::Timeout,
        Error::UnsupportedPath
        | Error::Query(QueryError::UnsupportedRoute | QueryError::UnsupportedLink) => {
            transport::Error::UnsupportedIntegration
        }
        Error::Context(_) => transport::Error::Authentication,
        Error::Io(kind) => transport::Error::Io(kind),
        _ => transport::Error::Io(io::ErrorKind::NetworkUnreachable),
    }
}

#[cfg(test)]
mod tests;
