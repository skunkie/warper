// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Experimental tuple-based UDP admission with retained-payload accounting.

use std::{
    collections::VecDeque,
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::Context,
    time::Duration,
};

use futures::task::AtomicWaker;
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr},
};
use tokio::sync::{
    OwnedSemaphorePermit, Semaphore,
    mpsc::{self, Receiver, Sender},
};

use crate::{
    adapter::{BackendId, FlowId, FlowMetadata},
    packet_peer::{MTU, PACKET_CAPACITY},
};

const MAX_ASSOCIATIONS: usize = 16;
const MAX_QUEUE: usize = 64;
const MAX_DATAGRAMS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    InvalidTime,
    MalformedPacket,
    UnsupportedProtocol,
    UnselectedDestination,
    DatagramTooLarge,
    ResourceLimit,
    QueueFull,
    ConsumerClosed,
    Cancelled,
    TimedOut,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "UDP experiment: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy)]
pub struct Limits {
    pub associations: usize,
    pub accepted: usize,
    pub queue: usize,
    pub datagrams: usize,
    pub idle_timeout: Duration,
    pub max_age: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            associations: 2,
            accepted: 2,
            queue: 4,
            datagrams: 16,
            idle_timeout: Duration::from_secs(30),
            max_age: Duration::from_secs(300),
        }
    }
}

#[derive(Default, Debug)]
pub struct Statistics {
    pub admitted: u64,
    pub received: u64,
    pub replied: u64,
    pub rejected: u64,
    pub timed_out: u64,
    pub application_closed: u64,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Termination {
    Running = 0,
    Cancelled = 1,
    TimedOut = 2,
}

struct Lifetime {
    termination: AtomicU8,
    _permit: OwnedSemaphorePermit,
}

impl Lifetime {
    fn check(&self) -> Result<(), Error> {
        match self.termination.load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(Error::Cancelled),
            _ => Err(Error::TimedOut),
        }
    }
}

// No Clone or owned-payload extraction: retained payloads retain their charge.
pub struct Datagram {
    bytes: Vec<u8>,
    permit: OwnedSemaphorePermit,
}

impl Datagram {
    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct Association {
    metadata: FlowMetadata,
    incoming: Receiver<Datagram>,
    replies: Sender<Datagram>,
    lifetime: Arc<Lifetime>,
    datagrams: Arc<Semaphore>,
    wake: Arc<AtomicWaker>,
}

impl Association {
    pub fn metadata(&self) -> FlowMetadata {
        self.metadata
    }

    pub async fn recv(&mut self) -> Result<Datagram, Error> {
        self.lifetime.check()?;
        let datagram = self.incoming.recv().await;
        // Publish terminal reason before closing the driver sender to wake us.
        self.lifetime.check()?;
        datagram.ok_or(Error::ConsumerClosed)
    }

    pub fn try_reply(&self, payload: &[u8]) -> Result<(), Error> {
        self.lifetime.check()?;
        if payload.len() > max_payload(self.metadata.destination) {
            return Err(Error::DatagramTooLarge);
        }
        let queue = self.replies.try_reserve().map_err(queue_error)?;
        let permit = reserve(&self.datagrams)?;
        queue.send(Datagram {
            bytes: payload.to_vec(),
            permit,
        });
        self.wake.wake();
        Ok(())
    }
}

impl Drop for Association {
    fn drop(&mut self) {
        self.incoming.close();
        self.wake.wake();
    }
}

struct State {
    metadata: FlowMetadata,
    incoming: Sender<Datagram>,
    replies: Receiver<Datagram>,
    lifetime: Arc<Lifetime>,
    created: Duration,
    progress: Duration,
}

struct Output {
    id: FlowId,
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

pub struct UdpAdapter {
    slots: Box<[Option<State>]>,
    accepted: Option<Sender<Association>>,
    lifetimes: Arc<Semaphore>,
    datagrams: Arc<Semaphore>,
    wake: Arc<AtomicWaker>,
    outgoing: VecDeque<Output>,
    select_backend: fn(SocketAddr) -> Option<BackendId>,
    limits: Limits,
    next_id: u64,
    next_slot: usize,
    now: Duration,
    cancelled: bool,
    statistics: Statistics,
}

impl UdpAdapter {
    pub fn new(
        limits: Limits,
        select_backend: fn(SocketAddr) -> Option<BackendId>,
    ) -> Result<(Self, Receiver<Association>), Error> {
        if !(1..=MAX_ASSOCIATIONS).contains(&limits.associations)
            || !(1..=limits.associations).contains(&limits.accepted)
            || !(1..=MAX_QUEUE).contains(&limits.queue)
            || !(1..=MAX_DATAGRAMS).contains(&limits.datagrams)
            || [limits.idle_timeout, limits.max_age]
                .iter()
                .any(|duration| duration.is_zero() || duration.as_millis() > i64::MAX as u128)
        {
            return Err(Error::InvalidLimits);
        }
        let (accepted, receiver) = mpsc::channel(limits.accepted);
        Ok((
            Self {
                slots: (0..limits.associations).map(|_| None).collect(),
                accepted: Some(accepted),
                lifetimes: Arc::new(Semaphore::new(limits.associations)),
                datagrams: Arc::new(Semaphore::new(limits.datagrams)),
                wake: Arc::new(AtomicWaker::new()),
                outgoing: VecDeque::new(),
                select_backend,
                limits,
                next_id: 1,
                next_slot: 0,
                now: Duration::ZERO,
                cancelled: false,
                statistics: Statistics::default(),
            },
            receiver,
        ))
    }

    pub fn inject(&mut self, packet: &[u8]) -> Result<FlowId, Error> {
        let result = self.admit(packet);
        if result.is_err() {
            self.statistics.rejected = self.statistics.rejected.saturating_add(1);
        }
        result
    }

    pub fn poll(&mut self, now: Duration) -> Result<(), Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if now < self.now || now.as_millis() > i64::MAX as u128 {
            return Err(Error::InvalidTime);
        }
        self.now = now;
        for offset in 0..self.slots.len() {
            let index = (self.next_slot + offset) % self.slots.len();
            let slot = &mut self.slots[index];
            let Some(state) = slot else { continue };
            let expired = now - state.created >= self.limits.max_age
                || now - state.progress >= self.limits.idle_timeout;
            if expired || state.incoming.is_closed() {
                state.lifetime.termination.store(
                    if expired {
                        Termination::TimedOut
                    } else {
                        Termination::Cancelled
                    } as u8,
                    Ordering::Release,
                );
                self.outgoing
                    .retain(|output| output.id != state.metadata.id);
                if expired {
                    self.statistics.timed_out = self.statistics.timed_out.saturating_add(1);
                } else {
                    self.statistics.application_closed =
                        self.statistics.application_closed.saturating_add(1);
                }
                *slot = None;
                continue;
            }
            // Do not consume a reply unless its output slot is available.
            if self.outgoing.len() < PACKET_CAPACITY
                && let Ok(datagram) = state.replies.try_recv()
            {
                let bytes = encode(
                    state.metadata.destination,
                    state.metadata.source,
                    datagram.payload(),
                )?;
                self.outgoing.push_back(Output {
                    id: state.metadata.id,
                    bytes,
                    _permit: datagram.permit,
                });
                state.progress = now;
                self.statistics.replied = self.statistics.replied.saturating_add(1);
            }
        }
        self.next_slot = (self.next_slot + 1) % self.slots.len();
        Ok(())
    }

    pub fn poll_io(&mut self, cx: &mut Context<'_>, now: Duration) -> Result<(), Error> {
        self.wake.register(cx.waker());
        self.poll(now)
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front().map(|output| output.bytes)
    }

    pub fn has_packet(&self) -> bool {
        !self.outgoing.is_empty()
    }

    pub fn next_deadline(&self, transport_ready: bool) -> Option<Duration> {
        if self.cancelled {
            return None;
        }
        self.slots
            .iter()
            .filter_map(Option::as_ref)
            .map(|state| {
                if state.incoming.is_closed()
                    || (transport_ready
                        && self.outgoing.len() < PACKET_CAPACITY
                        && !state.replies.is_empty())
                {
                    self.now
                } else {
                    (state.created + self.limits.max_age)
                        .min(state.progress + self.limits.idle_timeout)
                }
            })
            .min()
    }

    pub fn active_associations(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.accepted = None;
        for state in self.slots.iter_mut().filter_map(Option::take) {
            state
                .lifetime
                .termination
                .store(Termination::Cancelled as u8, Ordering::Release);
        }
        self.outgoing.clear();
    }

    fn admit(&mut self, packet: &[u8]) -> Result<FlowId, Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        let (source, destination, payload) = decode(packet)?;
        if let Some(state) = self
            .slots
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|state| {
                state.metadata.source == source && state.metadata.destination == destination
            })
        {
            let queue = state.incoming.try_reserve().map_err(queue_error)?;
            let permit = reserve(&self.datagrams)?;
            queue.send(Datagram {
                bytes: payload.to_vec(),
                permit,
            });
            state.progress = self.now;
            self.statistics.received = self.statistics.received.saturating_add(1);
            return Ok(state.metadata.id);
        }
        let backend = (self.select_backend)(destination).ok_or(Error::UnselectedDestination)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(Error::ResourceLimit)?;
        let lifetime_permit = reserve(&self.lifetimes)?;
        let accepted = self
            .accepted
            .as_ref()
            .ok_or(Error::Cancelled)?
            .try_reserve()
            .map_err(queue_error)?;
        let datagram_permit = reserve(&self.datagrams)?;
        let next_id = self.next_id.checked_add(1).ok_or(Error::ResourceLimit)?;
        let (incoming, received) = mpsc::channel(self.limits.queue);
        let (replies, sent) = mpsc::channel(self.limits.queue);
        // Fresh nonzero queue; still propagate an unexpected channel failure.
        incoming
            .try_send(Datagram {
                bytes: payload.to_vec(),
                permit: datagram_permit,
            })
            .map_err(queue_error)?;
        let lifetime = Arc::new(Lifetime {
            termination: AtomicU8::new(Termination::Running as u8),
            _permit: lifetime_permit,
        });
        let metadata = FlowMetadata {
            id: FlowId(self.next_id),
            source,
            destination,
            backend,
        };
        *slot = Some(State {
            metadata,
            incoming,
            replies: sent,
            lifetime: lifetime.clone(),
            created: self.now,
            progress: self.now,
        });
        accepted.send(Association {
            metadata,
            incoming: received,
            replies,
            lifetime,
            datagrams: self.datagrams.clone(),
            wake: self.wake.clone(),
        });
        self.next_id = next_id;
        self.statistics.admitted = self.statistics.admitted.saturating_add(1);
        self.statistics.received = self.statistics.received.saturating_add(1);
        Ok(metadata.id)
    }
}

impl Drop for UdpAdapter {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn reserve(semaphore: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, Error> {
    semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::ResourceLimit)
}

fn queue_error<T>(error: mpsc::error::TrySendError<T>) -> Error {
    match error {
        mpsc::error::TrySendError::Full(_) => Error::QueueFull,
        mpsc::error::TrySendError::Closed(_) => Error::ConsumerClosed,
    }
}

fn max_payload(address: SocketAddr) -> usize {
    MTU - if address.is_ipv4() { 20 } else { 40 } - 8
}

fn decode(bytes: &[u8]) -> Result<(SocketAddr, SocketAddr, &[u8]), Error> {
    if bytes.len() > MTU {
        return Err(Error::DatagramTooLarge);
    }
    let checksums = ChecksumCapabilities::default();
    let malformed = |_| Error::MalformedPacket;
    let (source, destination, protocol, payload): (IpAddress, IpAddress, _, _) =
        match bytes.first().map(|byte| byte >> 4) {
            Some(4) => {
                let packet = Ipv4Packet::new_checked(bytes).map_err(malformed)?;
                // Be explicit even if a future dependency enables reassembly.
                if packet.more_frags() || packet.frag_offset() != 0 {
                    return Err(Error::UnsupportedProtocol);
                }
                let repr = Ipv4Repr::parse(&packet, &checksums).map_err(malformed)?;
                (
                    repr.src_addr.into(),
                    repr.dst_addr.into(),
                    repr.next_header,
                    packet.payload(),
                )
            }
            Some(6) => {
                let packet = Ipv6Packet::new_checked(bytes).map_err(malformed)?;
                let repr = Ipv6Repr::parse(&packet).map_err(malformed)?;
                (
                    repr.src_addr.into(),
                    repr.dst_addr.into(),
                    repr.next_header,
                    packet.payload(),
                )
            }
            _ => return Err(Error::MalformedPacket),
        };
    if protocol != IpProtocol::Udp {
        return Err(Error::UnsupportedProtocol);
    }
    if !source.is_unicast() || !destination.is_unicast() {
        return Err(Error::MalformedPacket);
    }
    let packet = UdpPacket::new_checked(payload).map_err(malformed)?;
    // The library's checksum verifier accepts zero for both families. This
    // boundary does not support the IPv6 zero-checksum tunnel exceptions.
    if matches!(source, IpAddress::Ipv6(_)) && packet.checksum() == 0 {
        return Err(Error::MalformedPacket);
    }
    let repr = UdpRepr::parse(&packet, &source, &destination, &checksums).map_err(malformed)?;
    // Source port zero cannot receive a reply under this association contract.
    if repr.src_port == 0 || usize::from(packet.len()) != payload.len() {
        return Err(Error::MalformedPacket);
    }
    Ok((
        SocketAddr::new(source.into(), repr.src_port),
        SocketAddr::new(destination.into(), repr.dst_port),
        packet.payload(),
    ))
}

fn encode(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if source.is_ipv4() != destination.is_ipv4() || payload.len() > max_payload(source) {
        return Err(Error::DatagramTooLarge);
    }
    let checksums = ChecksumCapabilities::default();
    let header = if source.is_ipv4() { 20 } else { 40 };
    let mut bytes = vec![0; header + 8 + payload.len()];
    match (source.ip(), destination.ip()) {
        (std::net::IpAddr::V4(src_addr), std::net::IpAddr::V4(dst_addr)) => Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len: 8 + payload.len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..]), &checksums),
        (std::net::IpAddr::V6(src_addr), std::net::IpAddr::V6(dst_addr)) => Ipv6Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len: 8 + payload.len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..])),
        _ => return Err(Error::MalformedPacket),
    }
    UdpRepr {
        src_port: source.port(),
        dst_port: destination.port(),
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut bytes[header..]),
        &source.ip().into(),
        &destination.ip().into(),
        payload.len(),
        |output| output.copy_from_slice(payload),
        &checksums,
    );
    Ok(bytes)
}

#[cfg(test)]
#[path = "udp_adapter_tests.rs"]
mod tests;
