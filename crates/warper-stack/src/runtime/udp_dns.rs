// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded virtual UDP DNS datagrams, separate from backend UDP forwarding.

use super::delivery::{Packet, Receipt};
use crate::{device::MTU, host::AdmissionError};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr},
};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    time::Instant,
};
use warper_core::transport::Request;

pub const MAX_PAYLOAD: usize = 1232;
const MAX_REQUESTS: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub endpoint: SocketAddr,
    pub requests: usize,
}
impl Config {
    pub fn required_buffer_capacity(self) -> Result<usize, Error> {
        if self.endpoint.port() != 53
            || matches!(self.endpoint,SocketAddr::V6(address) if address.scope_id()!=0 || address.flowinfo()!=0)
            || !IpAddress::from(self.endpoint.ip()).is_unicast()
            || self.endpoint.ip().is_loopback()
            || !(1..=MAX_REQUESTS).contains(&self.requests)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(self.requests * 2 * MTU)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    TooLarge,
    QueueFull,
    ConsumerClosed,
    RequestCancelled,
    RequestExpired,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "InvalidConfig: invalid virtual UDP DNS limits",
            Self::TooLarge => "ResourceLimit: virtual DNS datagram exceeds its payload limit",
            Self::QueueFull => "ResourceLimit: virtual DNS reply queue is full",
            Self::ConsumerClosed => "WorkerFailed: virtual DNS output owner stopped",
            Self::RequestCancelled => "Cancelled: virtual DNS reply request ended",
            Self::RequestExpired => "Timeout: virtual DNS reply request expired",
        })
    }
}
impl std::error::Error for Error {}

pub struct Endpoint {
    pub requests: mpsc::Receiver<Datagram>,
    config: Config,
    admission: Arc<Semaphore>,
}
impl Endpoint {
    pub fn local_addr(&self) -> SocketAddr {
        self.config.endpoint
    }
    pub fn retained_requests(&self) -> usize {
        self.config.requests - self.admission.available_permits()
    }
}
pub struct Datagram {
    source: SocketAddr,
    destination: SocketAddr,
    received_at: Instant,
    payload: Vec<u8>,
    replies: mpsc::Sender<Packet>,
    wake: Arc<Notify>,
    admission: Arc<OwnedSemaphorePermit>,
    cancellation: watch::Receiver<bool>,
}
impl Datagram {
    /// Accept one reply under the original request. Retain its receipt and the
    /// service's output guard through native delivery, even after wait timeout.
    pub fn respond(self, payload: &[u8], request: Request) -> Result<Receipt, Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::TooLarge);
        }
        if *self.cancellation.borrow() || self.cancellation.has_changed().is_err() {
            return Err(Error::ConsumerClosed);
        }
        if *request.cancellation.borrow() || request.cancellation.has_changed().is_err() {
            return Err(Error::RequestCancelled);
        }
        let now = Instant::now();
        if request.deadline <= now {
            return Err(Error::RequestExpired);
        }
        if request.deadline.duration_since(now) > Duration::from_secs(30) {
            return Err(Error::InvalidConfig);
        }
        let permit = self.replies.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Error::QueueFull,
            mpsc::error::TrySendError::Closed(_) => Error::ConsumerClosed,
        })?;
        let bytes = encode(self.destination, self.source, payload);
        let (packet, receipt) = Packet::tracked(
            bytes,
            request,
            self.admission.clone(),
            self.cancellation.clone(),
        );
        permit.send(packet);
        self.wake.notify_one();
        Ok(receipt)
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn source(&self) -> SocketAddr {
        self.source
    }
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
}
impl fmt::Debug for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalDnsDatagram([redacted])")
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Statistics {
    pub received: u64,
    pub rejected: u64,
    pub queued_replies: u64,
}
pub(super) struct Driver {
    config: Config,
    requests: mpsc::Sender<Datagram>,
    replies: mpsc::Receiver<Packet>,
    reply_sender: mpsc::Sender<Packet>,
    admission: Arc<Semaphore>,
    wake: Arc<Notify>,
    quiescent: bool,
    cancellation: watch::Sender<bool>,
    pub(super) statistics: Statistics,
    tcp: bool,
}
impl Driver {
    pub(super) fn new(config: Config, wake: Arc<Notify>) -> Result<(Self, Endpoint), Error> {
        config.required_buffer_capacity()?;
        let (requests, receiver) = mpsc::channel(config.requests);
        let (reply_sender, replies) = mpsc::channel(config.requests);
        let admission = Arc::new(Semaphore::new(config.requests));
        Ok((
            Self {
                config,
                requests,
                replies,
                reply_sender,
                admission: admission.clone(),
                wake,
                quiescent: false,
                cancellation: watch::channel(false).0,
                statistics: Statistics::default(),
                tcp: false,
            },
            Endpoint {
                requests: receiver,
                config,
                admission,
            },
        ))
    }
    pub(super) fn consumer(&self) -> mpsc::Sender<Datagram> {
        self.requests.clone()
    }
    pub(super) fn allow_tcp(&mut self) {
        self.tcp = true;
    }
    pub(super) fn inject(&mut self, packet: &[u8]) -> Result<bool, AdmissionError> {
        if destination(packet) != Some(self.config.endpoint.ip()) {
            return Ok(false);
        }
        if self.tcp
            && match packet.first().map(|byte| byte >> 4) {
                Some(4) => packet.get(9) == Some(&6),
                Some(6) => packet.get(6) == Some(&6),
                _ => false,
            }
        {
            return Ok(false);
        }
        self.statistics.received = self.statistics.received.saturating_add(1);
        let result = self.admit(packet);
        if result.is_err() {
            self.statistics.rejected = self.statistics.rejected.saturating_add(1);
        }
        result.map(|()| true)
    }
    fn admit(&self, packet: &[u8]) -> Result<(), AdmissionError> {
        if self.quiescent {
            return Err(AdmissionError::Quiescing);
        }
        let (source, destination, payload) = decode(packet)?;
        if destination != self.config.endpoint {
            return Err(AdmissionError::UnselectedDestination);
        }
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionError::ResourceLimit)?;
        let queue = self.requests.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => AdmissionError::AcceptQueueFull,
            mpsc::error::TrySendError::Closed(_) => AdmissionError::ConsumerClosed,
        })?;
        queue.send(Datagram {
            source,
            destination,
            received_at: Instant::now(),
            payload: payload.to_vec(),
            replies: self.reply_sender.clone(),
            wake: self.wake.clone(),
            admission: Arc::new(permit),
            cancellation: self.cancellation.subscribe(),
        });
        Ok(())
    }
    pub(super) fn take_reply(&mut self) -> Option<Packet> {
        let packet = self.replies.try_recv().ok()?;
        self.statistics.queued_replies = self.statistics.queued_replies.saturating_add(1);
        Some(packet)
    }
    pub(super) fn has_replies(&self) -> bool {
        !self.replies.is_empty()
    }
    pub(super) fn quiesce(&mut self) {
        self.quiescent = true;
    }
    pub(super) fn cancel(&mut self) {
        self.quiesce();
        self.cancellation.send_replace(true);
        self.replies.close();
        while self.replies.try_recv().is_ok() {}
    }
}

fn destination(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) => Ipv4Packet::new_checked(bytes)
            .ok()
            .map(|packet| packet.dst_addr().into()),
        Some(6) => Ipv6Packet::new_checked(bytes)
            .ok()
            .map(|packet| packet.dst_addr().into()),
        _ => None,
    }
}
fn decode(bytes: &[u8]) -> Result<(SocketAddr, SocketAddr, &[u8]), AdmissionError> {
    if bytes.len() > MTU {
        return Err(AdmissionError::PacketTooLarge);
    }
    let checksums = ChecksumCapabilities::default();
    let malformed = |_| AdmissionError::MalformedPacket;
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
                let repr = Ipv4Repr::parse(&packet, &checksums).map_err(malformed)?;
                (
                    repr.src_addr.into(),
                    repr.dst_addr.into(),
                    repr.next_header,
                    &bytes[20..],
                )
            }
            Some(6) => {
                let packet = Ipv6Packet::new_checked(bytes).map_err(malformed)?;
                if 40 + usize::from(packet.payload_len()) != bytes.len() {
                    return Err(AdmissionError::MalformedPacket);
                }
                let repr = Ipv6Repr::parse(&packet).map_err(malformed)?;
                (
                    repr.src_addr.into(),
                    repr.dst_addr.into(),
                    repr.next_header,
                    &bytes[40..],
                )
            }
            _ => return Err(AdmissionError::MalformedPacket),
        };
    if protocol != IpProtocol::Udp {
        return Err(AdmissionError::UnsupportedProtocol);
    }
    if !source.is_unicast() || !destination.is_unicast() {
        return Err(AdmissionError::MalformedPacket);
    }
    let packet = UdpPacket::new_checked(payload).map_err(malformed)?;
    if matches!(source, IpAddress::Ipv6(_)) && packet.checksum() == 0 {
        return Err(AdmissionError::MalformedPacket);
    }
    let repr = UdpRepr::parse(&packet, &source, &destination, &checksums).map_err(malformed)?;
    if repr.src_port == 0 || usize::from(packet.len()) != payload.len() {
        return Err(AdmissionError::MalformedPacket);
    }
    if packet.payload().len() > MAX_PAYLOAD {
        return Err(AdmissionError::PacketTooLarge);
    }
    Ok((
        SocketAddr::new(source.into(), repr.src_port),
        SocketAddr::new(destination.into(), repr.dst_port),
        &payload[8..],
    ))
}
fn encode(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let checksums = ChecksumCapabilities::default();
    let header = if source.is_ipv4() { 20 } else { 40 };
    let mut bytes = vec![0; header + 8 + payload.len()];
    // Both endpoints come from one checked incoming IP packet.
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len: 8 + payload.len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..]), &checksums),
        (IpAddr::V6(src_addr), IpAddr::V6(dst_addr)) => Ipv6Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len: 8 + payload.len(),
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..])),
        _ => unreachable!("checked incoming endpoints have the same address family"),
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
        |out| out.copy_from_slice(payload),
        &checksums,
    );
    bytes
}

#[cfg(test)]
mod tests;
