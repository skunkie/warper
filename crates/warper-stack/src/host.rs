// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded host TCP admission and asynchronous accepted streams at MTU 1280.

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

use crate::{
    Seed,
    device::{BYTE_CAPACITY, PacketDevice},
};
use warper_core::{
    routing::Policy,
    transport::{CapturedTcp, Metadata},
};

pub use crate::device::MTU;

pub const MAX_FLOW_SLOTS: usize = 16;
const MAX_CLOCK_MILLIS: u128 = i64::MAX as u128 / 2000;
const IO_CHUNK_BYTES: usize = 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Quiescing,
    InvalidLimits,
    PacketTooLarge,
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
        write!(formatter, "host TCP: {self:?}")
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

impl Limits {
    pub fn validate(self) -> Result<(), AdmissionError> {
        if self.flows == 0
            || self.flows > MAX_FLOW_SLOTS
            || self.accepted == 0
            || self.accepted > self.flows
            || self.setup_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.max_age.is_zero()
            || [self.setup_timeout, self.idle_timeout, self.max_age]
                .iter()
                .any(|duration| duration.as_millis() > MAX_CLOCK_MILLIS)
        {
            return Err(AdmissionError::InvalidLimits);
        }
        Ok(())
    }
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

#[derive(Clone, Copy, Default, Debug)]
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
    pub metadata: Metadata,
    pub stream: AcceptedStream,
}

impl AcceptedFlow {
    pub fn into_core(self) -> CapturedTcp {
        CapturedTcp {
            metadata: self.metadata,
            stream: Box::new(self.stream),
        }
    }
}

struct PendingFlow {
    stream: AcceptedStream,
    permit: OwnedPermit<AcceptedFlow>,
}

struct FlowState {
    metadata: Metadata,
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
    policy: Arc<Policy>,
    limits: Limits,
    next_id: u64,
    now: Duration,
    quiescing: bool,
    cancelled: bool,
    statistics: Statistics,
}

impl HostAdapter {
    pub fn new(
        limits: Limits,
        policy: Arc<Policy>,
        seed: Seed,
    ) -> Result<(Self, Receiver<AcceptedFlow>), AdmissionError> {
        limits.validate()?;
        let mut device = PacketDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed.into_raw();
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
                policy,
                limits,
                next_id: 1,
                now: Duration::ZERO,
                quiescing: false,
                cancelled: false,
                statistics: Statistics::default(),
            },
            receiver,
        ))
    }

    pub fn inject(&mut self, packet: &[u8]) -> Result<u64, AdmissionError> {
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
        if now < self.now || now.as_millis() > MAX_CLOCK_MILLIS {
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
                // Transport backpressure may leave old packets unprocessed.
                // They must not reach a later listener reusing this slot.
                let metadata = flow.metadata;
                self.device.incoming.retain(|packet| {
                    tcp_metadata(packet).is_ok_and(|(source, destination, _)| {
                        source != metadata.source || destination != metadata.destination
                    })
                });
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

    /// Includes retired streams whose application handles still own buffers.
    pub fn retained_flows(&self) -> usize {
        self.limits.flows - self.lifetimes.available_permits()
    }

    /// Payload-buffer reservation; packet I/O channels and relay buffers are
    /// separately charged by the service. Allocator/socket metadata is additional.
    pub(crate) fn lifetime_pool(&self) -> Arc<Semaphore> {
        self.lifetimes.clone()
    }

    pub fn buffer_capacity(&self) -> usize {
        self.limits.flows * BYTE_CAPACITY * 4 + crate::device::PACKET_CAPACITY * MTU * 2
    }

    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    /// Stop new acceptance while retaining packet processing and accepted flows.
    /// Pending handshakes abort before they can publish an application stream.
    pub fn quiesce(&mut self) -> Result<(), AdmissionError> {
        if self.cancelled {
            return Err(AdmissionError::Cancelled);
        }
        self.quiescing = true;
        for slot in &mut self.slots {
            if slot
                .flow
                .as_ref()
                .is_some_and(|flow| flow.pending.is_some())
            {
                if let Some(flow) = slot.flow.take() {
                    flow.lifetime
                        .termination
                        .store(Termination::Cancelled as u8, Ordering::Release);
                }
                self.sockets.get_mut::<tcp::Socket>(slot.socket).abort();
            }
        }
        Ok(())
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

    pub(crate) fn accept_sender(&self) -> Option<Sender<AcceptedFlow>> {
        self.accepted.clone()
    }

    fn admit(&mut self, packet: &[u8]) -> Result<u64, AdmissionError> {
        if self.cancelled {
            return Err(AdmissionError::Cancelled);
        }
        let mtu = self.device.capabilities().max_transmission_unit;
        if packet.len() > mtu {
            return Err(AdmissionError::PacketTooLarge);
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
        if self.quiescing {
            self.policy
                .select(destination.ip())
                .ok_or(AdmissionError::UnselectedDestination)?;
            // No listener is created. The live interface can return a TCP RST
            // while route ownership and existing streams are still retained.
            self.device
                .inject(packet.to_vec())
                .map_err(|_| AdmissionError::ResourceLimit)?;
            return Err(AdmissionError::Quiescing);
        }
        if self
            .now
            .checked_add(self.limits.max_age)
            .is_none_or(|deadline| deadline.as_millis() > MAX_CLOCK_MILLIS)
        {
            return Err(AdmissionError::InvalidTime);
        }
        let backend = self
            .policy
            .select(destination.ip())
            .ok_or(AdmissionError::UnselectedDestination)?;
        let metadata = Metadata {
            id: self.next_id,
            source,
            destination,
            backend,
        };
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
                if packet.header_len() != 20 || packet.more_frags() || packet.frag_offset() != 0 {
                    return Err(AdmissionError::UnsupportedProtocol);
                }
                if usize::from(packet.total_len()) != bytes.len() {
                    return Err(AdmissionError::MalformedPacket);
                }
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
                if 40 + usize::from(packet.payload_len()) != bytes.len() {
                    return Err(AdmissionError::MalformedPacket);
                }
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
    if representation.src_port == 0 || representation.dst_port == 0 {
        return Err(AdmissionError::MalformedPacket);
    }
    let syn = representation.control == TcpControl::Syn && representation.ack_number.is_none();
    Ok((
        SocketAddr::new(source.into(), representation.src_port),
        SocketAddr::new(destination.into(), representation.dst_port),
        syn,
    ))
}

#[cfg(test)]
mod tests;
