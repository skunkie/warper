// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Experimental bounded TCP admission and asynchronous accepted streams.

use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::task::AtomicWaker;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage},
    phy::{ChecksumCapabilities, Device},
    socket::tcp,
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
        TcpControl, TcpPacket, TcpRepr,
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{
        OwnedSemaphorePermit, Semaphore,
        mpsc::{self, OwnedPermit, Receiver, Sender},
    },
};

use crate::packet_peer::{BYTE_CAPACITY, MTU, PacketDevice};

const MAX_FLOW_SLOTS: usize = 16;
const IO_CHUNK_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendId(pub u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowMetadata {
    pub id: FlowId,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub backend: BackendId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    InvalidLimits,
    InvalidMtu,
    MalformedPacket,
    UnsupportedProtocol,
    UnselectedDestination,
    UnknownFlow,
    ResourceLimit,
    AcceptQueueFull,
    ConsumerClosed,
    Cancelled,
    InvalidTime,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TCP experiment: {self:?}")
    }
}

impl std::error::Error for AdmissionError {}

#[derive(Clone, Copy)]
pub struct Limits {
    pub flows: usize,
    pub accepted: usize,
    pub setup_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_age: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            flows: 2,
            accepted: 2,
            setup_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            max_age: Duration::from_secs(86400),
        }
    }
}

#[derive(Default, Debug)]
pub struct Statistics {
    pub admitted: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub finished: u64,
    pub timed_out: u64,
    pub reset: u64,
    pub application_closed: u64,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Termination {
    Running = 0,
    Finished = 1,
    Cancelled = 2,
    Timeout = 3,
    Reset = 4,
    ApplicationClosed = 5,
}

struct FlowLifetime {
    termination: AtomicU8,
    wake: Arc<AtomicWaker>,
    _permit: OwnedSemaphorePermit,
}

pub struct AcceptedStream {
    inner: DuplexStream,
    lifetime: Arc<FlowLifetime>,
}

impl AcceptedStream {
    fn error(&self) -> Option<io::Error> {
        match self.lifetime.termination.load(Ordering::Acquire) {
            0 | 1 => None,
            2 => Some(io::ErrorKind::Interrupted.into()),
            3 => Some(io::ErrorKind::TimedOut.into()),
            4 => Some(io::ErrorKind::ConnectionReset.into()),
            _ => Some(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

impl Drop for AcceptedStream {
    fn drop(&mut self) {
        // Do not overwrite a driver's terminal error or normal completion.
        let _ = self.lifetime.termination.compare_exchange(
            Termination::Running as u8,
            Termination::ApplicationClosed as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.lifetime.wake.wake();
    }
}

impl AsyncRead for AcceptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for AcceptedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct AcceptedFlow {
    pub metadata: FlowMetadata,
    pub stream: AcceptedStream,
}

struct PendingFlow {
    stream: AcceptedStream,
    permit: OwnedPermit<AcceptedFlow>,
}

struct FlowState {
    metadata: FlowMetadata,
    stream: DuplexStream,
    lifetime: Arc<FlowLifetime>,
    pending: Option<PendingFlow>,
    created: Duration,
    progress: Duration,
    previous_state: tcp::State,
    application_eof: bool,
    network_eof: bool,
}

struct Slot {
    socket: SocketHandle,
    flow: Option<FlowState>,
}

pub struct HostAdapter {
    device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    slots: Box<[Slot]>,
    accepted: Option<Sender<AcceptedFlow>>,
    lifetimes: Arc<Semaphore>,
    wake: Arc<AtomicWaker>,
    select_backend: fn(SocketAddr) -> Option<BackendId>,
    limits: Limits,
    next_id: u64,
    now: Duration,
    cancelled: bool,
    statistics: Statistics,
}

impl HostAdapter {
    pub fn new(
        limits: Limits,
        select_backend: fn(SocketAddr) -> Option<BackendId>,
    ) -> Result<(Self, Receiver<AcceptedFlow>), AdmissionError> {
        Self::with_mtu(limits, select_backend, MTU)
    }

    pub fn with_mtu(
        limits: Limits,
        select_backend: fn(SocketAddr) -> Option<BackendId>,
        mtu: usize,
    ) -> Result<(Self, Receiver<AcceptedFlow>), AdmissionError> {
        if limits.flows == 0
            || limits.flows > MAX_FLOW_SLOTS
            || limits.accepted == 0
            || limits.accepted > limits.flows
            || limits.setup_timeout.is_zero()
            || limits.idle_timeout.is_zero()
            || limits.max_age.is_zero()
            || [limits.setup_timeout, limits.idle_timeout, limits.max_age]
                .iter()
                .any(|duration| duration.as_millis() > crate::MAX_CLOCK_MILLIS)
        {
            return Err(AdmissionError::InvalidLimits);
        }
        let mut device = PacketDevice::with_mtu(mtu).map_err(|_| AdmissionError::InvalidMtu)?;
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 91;
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        // Fixed constants, independent of destination policy and admitted flows.
        let v4 = std::net::Ipv4Addr::new(10, 66, 66, 254);
        let v6 = std::net::Ipv6Addr::new(0xfd66, 0x66, 0, 0, 0, 0, 0, 0xffff);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(v4.into(), 32))
                .expect("fixed IPv4 slot");
            addresses
                .push(IpCidr::new(v6.into(), 128))
                .expect("fixed IPv6 slot");
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(v4)
            .map_err(|_| AdmissionError::ResourceLimit)?;
        interface
            .routes_mut()
            .add_default_ipv6_route(v6)
            .map_err(|_| AdmissionError::ResourceLimit)?;
        interface.set_any_ip(true);
        let storage: Vec<_> = (0..limits.flows).map(|_| SocketStorage::EMPTY).collect();
        let mut sockets = SocketSet::new(storage);
        let slots: Box<[_]> = (0..limits.flows)
            .map(|_| Slot {
                socket: sockets.add(tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
                    tcp::SocketBuffer::new(vec![0; BYTE_CAPACITY]),
                )),
                flow: None,
            })
            .collect();
        let (accepted, receiver) = mpsc::channel(limits.accepted);
        Ok((
            Self {
                device,
                interface,
                sockets,
                slots,
                accepted: Some(accepted),
                lifetimes: Arc::new(Semaphore::new(limits.flows)),
                wake: Arc::new(AtomicWaker::new()),
                select_backend,
                limits,
                next_id: 1,
                now: Duration::ZERO,
                cancelled: false,
                statistics: Statistics::default(),
            },
            receiver,
        ))
    }

    pub fn inject(&mut self, packet: &[u8]) -> Result<FlowId, AdmissionError> {
        let result = self.admit(packet);
        if result.is_err() {
            self.statistics.rejected = self.statistics.rejected.saturating_add(1);
        }
        result
    }

    pub fn poll_io(&mut self, cx: &mut Context<'_>, now: Duration) -> Result<(), AdmissionError> {
        self.wake.register(cx.waker());
        if self.cancelled {
            return Err(AdmissionError::Cancelled);
        }
        if now < self.now || now.as_millis() > crate::MAX_CLOCK_MILLIS {
            return Err(AdmissionError::InvalidTime);
        }
        let timestamp = i64::try_from(now.as_millis()).map_err(|_| AdmissionError::InvalidTime)?;
        self.now = now;
        self.interface.poll(
            Instant::from_millis(timestamp),
            &mut self.device,
            &mut self.sockets,
        );
        for slot in &mut self.slots {
            let Some(flow) = &mut slot.flow else { continue };
            let socket = self.sockets.get_mut::<tcp::Socket>(slot.socket);
            let reason = if now - flow.created >= self.limits.max_age
                || (flow.pending.is_some() && now - flow.created >= self.limits.setup_timeout)
                || (flow.pending.is_none() && now - flow.progress >= self.limits.idle_timeout)
            {
                Some(Termination::Timeout)
            } else if socket.state() == tcp::State::Closed {
                Some(if flow.application_eof && flow.network_eof {
                    Termination::Finished
                } else {
                    Termination::Reset
                })
            } else {
                if flow.previous_state != socket.state() {
                    flow.previous_state = socket.state();
                    flow.progress = now;
                }
                if !matches!(socket.state(), tcp::State::Listen | tcp::State::SynReceived)
                    && let Some(pending) = flow.pending.take()
                {
                    pending.permit.send(AcceptedFlow {
                        metadata: flow.metadata,
                        stream: pending.stream,
                    });
                    self.statistics.accepted = self.statistics.accepted.saturating_add(1);
                }
                bridge(flow, socket, cx, now)
            };
            if let Some(reason) = reason {
                flow.lifetime
                    .termination
                    .store(reason as u8, Ordering::Release);
                socket.abort();
                match reason {
                    Termination::Timeout => {
                        self.statistics.timed_out = self.statistics.timed_out.saturating_add(1)
                    }
                    Termination::Reset => {
                        self.statistics.reset = self.statistics.reset.saturating_add(1)
                    }
                    Termination::ApplicationClosed => {
                        self.statistics.application_closed =
                            self.statistics.application_closed.saturating_add(1)
                    }
                    _ => self.statistics.finished = self.statistics.finished.saturating_add(1),
                }
                slot.flow = None;
            }
        }
        self.interface.poll(
            Instant::from_millis(timestamp),
            &mut self.device,
            &mut self.sockets,
        );
        Ok(())
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.device.outgoing.pop_front()
    }

    pub fn has_packet(&self) -> bool {
        !self.device.outgoing.is_empty()
    }

    pub fn next_deadline(&mut self, transport_ready: bool) -> Option<Duration> {
        if self.cancelled {
            return None;
        }
        let lifecycle = self
            .slots
            .iter()
            .filter_map(|slot| {
                slot.flow.as_ref().map(|flow| {
                    if self.sockets.get::<tcp::Socket>(slot.socket).state() != flow.previous_state
                        || (!flow.network_eof
                            && flow.lifetime.termination.load(Ordering::Acquire)
                                == Termination::ApplicationClosed as u8)
                    {
                        return self.now;
                    }
                    (flow.created + self.limits.max_age).min(if flow.pending.is_some() {
                        flow.created + self.limits.setup_timeout
                    } else {
                        flow.progress + self.limits.idle_timeout
                    })
                })
            })
            .min();
        let transport = if transport_ready {
            self.interface
                .poll_at(
                    Instant::from_millis(self.now.as_millis() as i64),
                    &self.sockets,
                )
                .map(|time| Duration::from_millis(time.total_millis().max(0) as u64).max(self.now))
        } else {
            None
        };
        lifecycle.into_iter().chain(transport).min()
    }

    pub fn active_flows(&self) -> usize {
        self.slots.iter().filter(|slot| slot.flow.is_some()).count()
    }

    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.accepted = None;
        for slot in &mut self.slots {
            if let Some(flow) = slot.flow.take() {
                flow.lifetime
                    .termination
                    .store(Termination::Cancelled as u8, Ordering::Release);
            }
            self.sockets.get_mut::<tcp::Socket>(slot.socket).abort();
        }
        self.device = PacketDevice::default();
    }

    fn admit(&mut self, packet: &[u8]) -> Result<FlowId, AdmissionError> {
        if self.cancelled {
            return Err(AdmissionError::Cancelled);
        }
        if packet.len() > self.device.capabilities().max_transmission_unit {
            return Err(AdmissionError::ResourceLimit);
        }
        let (source, destination, syn) = tcp_metadata(packet)?;
        if let Some(flow) = self
            .slots
            .iter()
            .filter_map(|slot| slot.flow.as_ref())
            .find(|flow| flow.metadata.source == source && flow.metadata.destination == destination)
        {
            let id = flow.metadata.id;
            self.device
                .inject(packet.to_vec())
                .map_err(|_| AdmissionError::ResourceLimit)?;
            return Ok(id);
        }
        if !syn {
            return Err(AdmissionError::UnknownFlow);
        }
        if self
            .now
            .checked_add(self.limits.max_age)
            .is_none_or(|deadline| deadline.as_millis() > crate::MAX_CLOCK_MILLIS)
        {
            return Err(AdmissionError::InvalidTime);
        }
        let backend =
            (self.select_backend)(destination).ok_or(AdmissionError::UnselectedDestination)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.flow.is_none())
            .ok_or(AdmissionError::ResourceLimit)?;
        // Retired streams still own buffers: charge until both driver and
        // application handles drop, independently of reusable socket slots.
        let lifetime_permit = self
            .lifetimes
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionError::ResourceLimit)?;
        let permit = self
            .accepted
            .as_ref()
            .ok_or(AdmissionError::Cancelled)?
            .clone()
            .try_reserve_owned()
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AdmissionError::AcceptQueueFull,
                mpsc::error::TrySendError::Closed(_) => AdmissionError::ConsumerClosed,
            })?;
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(AdmissionError::ResourceLimit)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(slot.socket);
        socket
            .listen(destination)
            .map_err(|_| AdmissionError::ResourceLimit)?;
        if self.device.inject(packet.to_vec()).is_err() {
            socket.abort();
            return Err(AdmissionError::ResourceLimit);
        }
        let (driver, application) = tokio::io::duplex(BYTE_CAPACITY);
        let lifetime = Arc::new(FlowLifetime {
            termination: AtomicU8::new(Termination::Running as u8),
            wake: self.wake.clone(),
            _permit: lifetime_permit,
        });
        let metadata = FlowMetadata {
            id: FlowId(self.next_id),
            source,
            destination,
            backend,
        };
        slot.flow = Some(FlowState {
            metadata,
            stream: driver,
            lifetime: lifetime.clone(),
            pending: Some(PendingFlow {
                stream: AcceptedStream {
                    inner: application,
                    lifetime,
                },
                permit,
            }),
            created: self.now,
            progress: self.now,
            previous_state: tcp::State::Listen,
            application_eof: false,
            network_eof: false,
        });
        self.next_id = next_id;
        self.statistics.admitted = self.statistics.admitted.saturating_add(1);
        Ok(metadata.id)
    }
}

impl Drop for HostAdapter {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn bridge(
    flow: &mut FlowState,
    socket: &mut tcp::Socket<'_>,
    cx: &mut Context<'_>,
    now: Duration,
) -> Option<Termination> {
    if flow.pending.is_some() {
        return None;
    }
    if flow.lifetime.termination.load(Ordering::Acquire) == Termination::ApplicationClosed as u8
        && !flow.network_eof
    {
        return Some(Termination::ApplicationClosed);
    }
    if socket.can_recv() {
        let result = socket.recv(|bytes| {
            match Pin::new(&mut flow.stream)
                .poll_write(cx, &bytes[..bytes.len().min(IO_CHUNK_BYTES)])
            {
                Poll::Ready(Ok(count)) => (count, Ok(count)),
                Poll::Ready(Err(error)) => (0, Err(error)),
                Poll::Pending => (0, Ok(0)),
            }
        });
        match result {
            Ok(Ok(count)) if count > 0 => {
                flow.progress = now;
                cx.waker().wake_by_ref();
            }
            Ok(Err(_)) | Err(_) => return Some(Termination::ApplicationClosed),
            _ => {}
        }
    }
    if !socket.may_recv() && socket.recv_queue() == 0 && !flow.network_eof {
        match Pin::new(&mut flow.stream).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => flow.network_eof = true,
            Poll::Ready(Err(_)) => return Some(Termination::ApplicationClosed),
            Poll::Pending => {}
        }
    }
    let available = socket.send_capacity() - socket.send_queue();
    if socket.can_send() && available > 0 && !flow.application_eof {
        let mut bytes = [0; IO_CHUNK_BYTES];
        let limit = available.min(bytes.len());
        let mut buffer = ReadBuf::new(&mut bytes[..limit]);
        match Pin::new(&mut flow.stream).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                socket.close();
                flow.application_eof = true;
            }
            Poll::Ready(Ok(())) => {
                match socket.send_slice(buffer.filled()) {
                    Ok(count) if count == buffer.filled().len() => {
                        flow.progress = now;
                        cx.waker().wake_by_ref();
                    }
                    // Never retry bytes after an unexpected partial admission.
                    _ => return Some(Termination::Reset),
                }
            }
            Poll::Ready(Err(_)) => return Some(Termination::ApplicationClosed),
            Poll::Pending => {}
        }
    }
    None
}

fn tcp_metadata(bytes: &[u8]) -> Result<(SocketAddr, SocketAddr, bool), AdmissionError> {
    let malformed = |_| AdmissionError::MalformedPacket;
    let checksums = ChecksumCapabilities::default();
    let (source, destination, protocol, payload): (IpAddress, IpAddress, _, _) =
        match bytes.first().map(|byte| byte >> 4) {
            Some(4) => {
                let packet = Ipv4Packet::new_checked(bytes).map_err(malformed)?;
                let representation = Ipv4Repr::parse(&packet, &checksums).map_err(malformed)?;
                (
                    representation.src_addr.into(),
                    representation.dst_addr.into(),
                    representation.next_header,
                    &bytes[usize::from(packet.header_len())..usize::from(packet.total_len())],
                )
            }
            Some(6) => {
                let packet = Ipv6Packet::new_checked(bytes).map_err(malformed)?;
                let representation = Ipv6Repr::parse(&packet).map_err(malformed)?;
                (
                    representation.src_addr.into(),
                    representation.dst_addr.into(),
                    representation.next_header,
                    &bytes[40..40 + usize::from(packet.payload_len())],
                )
            }
            _ => return Err(AdmissionError::MalformedPacket),
        };
    if protocol != IpProtocol::Tcp {
        return Err(AdmissionError::UnsupportedProtocol);
    }
    let packet = TcpPacket::new_checked(payload).map_err(malformed)?;
    let representation =
        TcpRepr::parse(&packet, &source, &destination, &checksums).map_err(malformed)?;
    let syn = representation.control == TcpControl::Syn && representation.ack_number.is_none();
    Ok((
        SocketAddr::new(source.into(), representation.src_port),
        SocketAddr::new(destination.into(), representation.dst_port),
        syn,
    ))
}

#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;
