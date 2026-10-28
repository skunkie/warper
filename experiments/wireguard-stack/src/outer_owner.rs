// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled socket ownership and feedback retirement experiment.

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr, UdpSocket},
    time::Duration,
};

use crate::{
    outer_errors::{ErrorQueue, ReceivedError},
    outer_remote::Reservation,
    path_mtu::PathBudget,
};

const MAX_RETIRED_SOCKETS: usize = 8;
const MAX_SESSIONS_PER_SOCKET: usize = 8;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Error {
    InvalidPeer,
    InvalidPacket,
    RetiredSocketLimit,
    NonIncreasingCounter,
    SessionLimit,
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "owned outer transport: {self:?}")
    }
}

impl std::error::Error for Error {}

pub(super) struct Owner {
    socket: UdpSocket,
    queue: Option<ErrorQueue>,
    retired_sockets: Vec<UdpSocket>,
    sessions: Vec<SessionCounter>,
    reservation: Reservation,
    budget: PathBudget,
    remote_probe: bool,
}

struct SessionCounter {
    receiver_index: u32,
    counter: u64,
}

impl Owner {
    #[cfg(test)]
    fn new(local: SocketAddr, remote: SocketAddr, outer_mtu: usize) -> anyhow::Result<Self> {
        Self::new_with_mode(local, remote, outer_mtu, false)
    }

    pub(super) fn new_remote_probe(
        local: SocketAddr,
        remote: SocketAddr,
        outer_mtu: usize,
    ) -> anyhow::Result<Self> {
        Self::new_with_mode(local, remote, outer_mtu, true)
    }

    fn new_with_mode(
        local: SocketAddr,
        remote: SocketAddr,
        outer_mtu: usize,
        remote_probe: bool,
    ) -> anyhow::Result<Self> {
        Self::validate_peer(local, remote)?;
        let budget = PathBudget::new(outer_mtu, remote.is_ipv6())?;
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        socket.connect(remote)?;
        let queue = Self::enable_queue(&socket, remote_probe)?;
        Ok(Self {
            socket,
            queue: Some(queue),
            retired_sockets: Vec::with_capacity(MAX_RETIRED_SOCKETS),
            sessions: Vec::with_capacity(MAX_SESSIONS_PER_SOCKET),
            reservation: Reservation::default(),
            budget,
            remote_probe,
        })
    }

    pub(super) fn send_reserved(
        &mut self,
        packet: &[u8],
        reporter: IpAddr,
        now: Duration,
    ) -> anyhow::Result<()> {
        self.send_reserved_with(packet, reporter, now, |socket, data| socket.send(data))
    }

    fn send_reserved_with(
        &mut self,
        packet: &[u8],
        reporter: IpAddr,
        now: Duration,
        send: impl FnOnce(&UdpSocket, &[u8]) -> io::Result<usize>,
    ) -> anyhow::Result<()> {
        let queue = self.queue.as_ref().ok_or(Error::Unavailable)?;
        self.budget.check_datagram(packet.len())?;
        self.reservation
            .reserve(packet, queue, reporter, now, Duration::from_secs(1))?;
        if let Err(error) = self.record_header(packet) {
            self.reservation.cancel();
            return Err(error.into());
        }
        match send(&self.socket, packet) {
            Ok(length) if length == packet.len() => Ok(()),
            Ok(_) => {
                self.reservation.cancel();
                Err(io::Error::new(io::ErrorKind::WriteZero, "partial outer datagram").into())
            }
            Err(error) => {
                self.reservation.cancel();
                Err(error.into())
            }
        }
    }

    pub(super) fn apply(&mut self, report: &ReceivedError, now: Duration) -> anyhow::Result<bool> {
        let queue = self.queue.as_ref().ok_or(Error::Unavailable)?;
        self.reservation.apply(queue, report, &mut self.budget, now)
    }

    pub(super) fn reconnect(&mut self, remote: SocketAddr, outer_mtu: usize) -> anyhow::Result<()> {
        self.reconnect_with(remote, outer_mtu, |socket, address| socket.connect(address))
    }

    fn reconnect_with(
        &mut self,
        remote: SocketAddr,
        outer_mtu: usize,
        connect: impl FnOnce(&UdpSocket, SocketAddr) -> io::Result<()>,
    ) -> anyhow::Result<()> {
        let mut local = self.socket.local_addr()?;
        Self::validate_peer(local, remote)?;
        let budget = PathBudget::new(outer_mtu, remote.is_ipv6())?;
        if self.retired_sockets.len() == MAX_RETIRED_SOCKETS {
            return Err(Error::RetiredSocketLimit.into());
        }
        // Retire feedback first; keep old sockets bound until owner destruction
        // so their local ports cannot receive traffic for a later generation.
        self.reservation.cancel();
        self.queue = None;
        local.set_port(0);
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        connect(&socket, remote)?;
        let queue = Self::enable_queue(&socket, self.remote_probe)?;
        self.retired_sockets
            .push(std::mem::replace(&mut self.socket, socket));
        self.sessions.clear();
        self.budget = budget;
        self.queue = Some(queue);
        Ok(())
    }

    pub(super) fn receive_datagram(&self, buffer: &mut [u8]) -> anyhow::Result<Option<usize>> {
        let queue = self.queue.as_ref().ok_or(Error::Unavailable)?;
        queue.verify_socket()?;
        match self.socket.recv_from(buffer) {
            Ok((length, source)) if source == queue.remote() => Ok(Some(length)),
            Ok(_) => {
                Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected outer peer").into())
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn cancel_reservation(&mut self) {
        self.reservation.cancel();
    }

    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(super) fn outer_mtu(&self) -> usize {
        self.budget.outer_mtu()
    }

    pub(super) fn receive(&self) -> anyhow::Result<Option<ReceivedError>> {
        self.queue.as_ref().ok_or(Error::Unavailable)?.receive()
    }

    pub(super) fn advance(&mut self, now: Duration) -> anyhow::Result<()> {
        self.reservation.advance(now)?;
        Ok(())
    }

    fn enable_queue(socket: &UdpSocket, remote_probe: bool) -> anyhow::Result<ErrorQueue> {
        if remote_probe {
            ErrorQueue::enable_remote_probe(socket)
        } else {
            ErrorQueue::enable(socket)
        }
    }

    fn record_header(&mut self, packet: &[u8]) -> Result<(), Error> {
        // Reservation admission already validated a complete WireGuard header.
        let receiver_index = u32::from_le_bytes(
            packet
                .get(4..8)
                .ok_or(Error::InvalidPacket)?
                .try_into()
                .map_err(|_| Error::InvalidPacket)?,
        );
        let counter = u64::from_le_bytes(
            packet
                .get(8..16)
                .ok_or(Error::InvalidPacket)?
                .try_into()
                .map_err(|_| Error::InvalidPacket)?,
        );
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.receiver_index == receiver_index)
        {
            if counter <= session.counter {
                return Err(Error::NonIncreasingCounter);
            }
            session.counter = counter;
        } else {
            if self.sessions.len() == MAX_SESSIONS_PER_SOCKET {
                return Err(Error::SessionLimit);
            }
            self.sessions.push(SessionCounter {
                receiver_index,
                counter,
            });
        }
        Ok(())
    }

    fn validate_peer(local: SocketAddr, remote: SocketAddr) -> Result<(), Error> {
        if local.is_ipv6() != remote.is_ipv6()
            || remote.ip().is_unspecified()
            || remote.ip().is_multicast()
            || remote.port() == 0
        {
            return Err(Error::InvalidPeer);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outer_errors::Record;
    use nix::{errno::Errno, sys::socket::MsgFlags};
    use std::sync::Arc;

    fn packet(counter: u8) -> [u8; 64] {
        let mut packet = [0; 64];
        packet[0] = 4;
        packet[8] = counter;
        packet
    }

    fn report(owner: &Owner, packet: &[u8], reporter: IpAddr) -> ReceivedError {
        let queue = owner.queue.as_ref().unwrap();
        let ipv6 = queue.remote().is_ipv6();
        ReceivedError {
            identity: Arc::clone(queue.identity()),
            local: queue.local(),
            record: Record {
                ipv6,
                errno: Errno::EMSGSIZE as u32,
                origin: if ipv6 {
                    nix::libc::SO_EE_ORIGIN_ICMP6
                } else {
                    nix::libc::SO_EE_ORIGIN_ICMP
                },
                kind: if ipv6 { 2 } else { 3 },
                code: if ipv6 { 0 } else { 4 },
                mtu: 1400,
                reporter: Some(reporter),
            },
            destination: Some(queue.remote()),
            flags: MsgFlags::MSG_ERRQUEUE,
            prefix: packet[..16].try_into().unwrap(),
            quoted_len: 16,
        }
    }

    #[test]
    fn overlapping_owners_isolate_feedback_and_failed_transition() {
        for ipv6 in [false, true] {
            let peer = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let mut first = Owner::new(
                crate::loopback_address(ipv6),
                peer.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let mut second = Owner::new(
                crate::loopback_address(ipv6),
                peer.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let first_local = first.local_addr().unwrap();
            let second_local = second.local_addr().unwrap();
            let payload = packet(1);
            first
                .send_reserved(&payload, reporter, Duration::ZERO)
                .unwrap();
            second
                .send_reserved(&payload, reporter, Duration::ZERO)
                .unwrap();
            let mut buffer = [0; 128];
            for _ in 0..2 {
                let (length, _) = peer.recv_from(&mut buffer).unwrap();
                assert_eq!(&buffer[..length], &payload);
            }
            let first_report = report(&first, &payload, reporter);
            let second_report = report(&second, &payload, reporter);
            assert_eq!(
                first
                    .apply(&second_report, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::Unmatched)
            );
            assert_eq!(first.outer_mtu(), 1600);
            assert_eq!(second.outer_mtu(), 1600);
            let transition_error = second
                .reconnect_with(peer.local_addr().unwrap(), 1600, |_, _| {
                    Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                })
                .unwrap_err();
            assert_eq!(
                transition_error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::ConnectionRefused
            );
            assert_eq!(
                second
                    .apply(&second_report, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::Unavailable)
            );
            assert_eq!(
                second
                    .send_reserved(&packet(2), reporter, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::Unavailable)
            );
            assert!(first.apply(&first_report, Duration::ZERO).unwrap());
            assert_eq!(first.outer_mtu(), 1400);
            second.reconnect(peer.local_addr().unwrap(), 1600).unwrap();
            let next = packet(2);
            second
                .send_reserved(&next, reporter, Duration::ZERO)
                .unwrap();
            let (length, _) = peer.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], &next);
            assert_eq!(
                second
                    .apply(&second_report, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::Unmatched)
            );
            assert_eq!(second.outer_mtu(), 1600);
            assert!(
                second
                    .apply(&report(&second, &next, reporter), Duration::ZERO)
                    .unwrap()
            );
            assert_eq!(second.outer_mtu(), 1400);
            drop((first, second));
            drop(UdpSocket::bind(first_local).unwrap());
            drop(UdpSocket::bind(second_local).unwrap());
        }
    }

    #[test]
    fn changing_and_restoring_peers_retires_old_feedback_without_replay() {
        for ipv6 in [false, true] {
            let first = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let second = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            first
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            second
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                first.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let local = owner.socket.local_addr().unwrap();
            let original = packet(1);
            owner
                .send_reserved(&original, reporter, Duration::ZERO)
                .unwrap();
            let stale = report(&owner, &original, reporter);
            let mut buffer = [0; 128];
            let length = first.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], &original);
            owner.reconnect(second.local_addr().unwrap(), 1600).unwrap();
            let error = owner.apply(&stale, Duration::ZERO).unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::MissingReservation)
            );
            let next = packet(2);
            owner
                .send_reserved(&next, reporter, Duration::ZERO)
                .unwrap();
            let length = second.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], &next);
            owner.reconnect(first.local_addr().unwrap(), 1600).unwrap();
            let latest = packet(3);
            owner
                .send_reserved(&latest, reporter, Duration::ZERO)
                .unwrap();
            let length = first.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], &latest);
            for peer in [&first, &second] {
                peer.set_nonblocking(true).unwrap();
                assert_eq!(
                    peer.recv(&mut buffer).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
            let error = owner.apply(&stale, Duration::ZERO).unwrap_err();
            assert_eq!(
                error.downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::Unmatched)
            );
            assert_eq!(owner.budget.outer_mtu(), 1600);
            let mut same_header_stale = stale.clone();
            same_header_stale.prefix.copy_from_slice(&latest[..16]);
            assert_eq!(
                owner
                    .apply(&same_header_stale, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::Unmatched)
            );
            assert_eq!(owner.budget.outer_mtu(), 1600);
            let current = report(&owner, &latest, reporter);
            assert!(owner.apply(&current, Duration::ZERO).unwrap());
            assert_eq!(owner.budget.outer_mtu(), 1400);
            drop(owner);
            UdpSocket::bind(local).unwrap();
        }
    }

    #[test]
    fn failed_or_partial_send_releases_reservation_without_replay() {
        for ipv6 in [false, true] {
            for partial in [false, true] {
                let peer = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
                let mut owner = Owner::new(
                    crate::loopback_address(ipv6),
                    peer.local_addr().unwrap(),
                    1600,
                )
                .unwrap();
                let local = owner.socket.local_addr().unwrap();
                let error = owner
                    .send_reserved_with(&packet(1), reporter, Duration::ZERO, |_, _| {
                        if partial {
                            Ok(1)
                        } else {
                            Err(io::Error::from(io::ErrorKind::PermissionDenied))
                        }
                    })
                    .unwrap_err();
                assert_eq!(
                    error.downcast_ref::<io::Error>().unwrap().kind(),
                    if partial {
                        io::ErrorKind::WriteZero
                    } else {
                        io::ErrorKind::PermissionDenied
                    }
                );
                assert_eq!(
                    owner
                        .send_reserved(&packet(1), reporter, Duration::ZERO)
                        .unwrap_err()
                        .downcast_ref::<Error>(),
                    Some(&Error::NonIncreasingCounter)
                );
                let next = packet(2);
                owner
                    .send_reserved(&next, reporter, Duration::ZERO)
                    .unwrap();
                let mut buffer = [0; 128];
                let length = peer.recv(&mut buffer).unwrap();
                assert_eq!(&buffer[..length], &next);
                peer.set_nonblocking(true).unwrap();
                assert_eq!(
                    peer.recv(&mut buffer).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                drop(owner);
                UdpSocket::bind(local).unwrap();
            }
        }
    }

    #[test]
    fn retired_feedback_cannot_match_reused_counter_on_the_same_socket() {
        for ipv6 in [false, true] {
            for retirement in ["commit", "cancel", "expiry"] {
                let peer = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
                let mut owner = Owner::new(
                    crate::loopback_address(ipv6),
                    peer.local_addr().unwrap(),
                    1600,
                )
                .unwrap();
                let first = packet(1);
                owner
                    .send_reserved(&first, reporter, Duration::ZERO)
                    .unwrap();
                let stale = report(&owner, &first, reporter);
                let mut buffer = [0; 128];
                let length = peer.recv(&mut buffer).unwrap();
                assert_eq!(&buffer[..length], &first);
                let now = match retirement {
                    "commit" => {
                        assert!(owner.apply(&stale, Duration::ZERO).unwrap());
                        Duration::ZERO
                    }
                    "cancel" => {
                        owner.cancel_reservation();
                        Duration::ZERO
                    }
                    "expiry" => {
                        assert_eq!(
                            owner
                                .advance(Duration::from_secs(1))
                                .unwrap_err()
                                .downcast_ref::<crate::outer_remote::Error>(),
                            Some(&crate::outer_remote::Error::Timeout)
                        );
                        Duration::from_secs(1)
                    }
                    _ => unreachable!(),
                };
                let mut repeated = first;
                repeated[16] ^= 1;
                assert_eq!(
                    owner
                        .send_reserved(&repeated, reporter, now)
                        .unwrap_err()
                        .downcast_ref::<Error>(),
                    Some(&Error::NonIncreasingCounter),
                    "IPv6 {ipv6}, retirement {retirement}"
                );
                let next = packet(2);
                owner.send_reserved(&next, reporter, now).unwrap();
                assert_eq!(
                    owner
                        .apply(&stale, now)
                        .unwrap_err()
                        .downcast_ref::<crate::outer_remote::Error>(),
                    Some(&crate::outer_remote::Error::Unmatched)
                );
                let current = report(&owner, &next, reporter);
                assert_eq!(owner.apply(&current, now).unwrap(), retirement != "commit");
                assert_eq!(
                    owner
                        .send_reserved(&packet(0), reporter, now)
                        .unwrap_err()
                        .downcast_ref::<Error>(),
                    Some(&Error::NonIncreasingCounter)
                );
                let length = peer.recv(&mut buffer).unwrap();
                assert_eq!(&buffer[..length], &next);
                peer.set_nonblocking(true).unwrap();
                assert_eq!(
                    peer.recv(&mut buffer).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
        }
    }

    #[test]
    fn session_history_is_bounded_and_new_socket_starts_a_new_history() {
        for ipv6 in [false, true] {
            let peer = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                peer.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            for index in 0..MAX_SESSIONS_PER_SOCKET {
                let mut sample = packet(1);
                sample[4] = index as u8;
                owner
                    .send_reserved(&sample, reporter, Duration::ZERO)
                    .unwrap();
                owner.cancel_reservation();
            }
            let mut overflow = packet(1);
            overflow[4] = MAX_SESSIONS_PER_SOCKET as u8;
            let local = owner.local_addr().unwrap();
            assert_eq!(
                owner
                    .send_reserved(&overflow, reporter, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::SessionLimit)
            );
            assert_eq!(owner.local_addr().unwrap(), local);
            let mut buffer = [0; 128];
            for index in 0..MAX_SESSIONS_PER_SOCKET {
                let (length, source) = peer.recv_from(&mut buffer).unwrap();
                assert_eq!(length, 64);
                assert_eq!(source, local);
                assert_eq!(buffer[4], index as u8);
            }
            peer.set_nonblocking(true).unwrap();
            assert_eq!(
                peer.recv(&mut buffer).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            peer.set_nonblocking(false).unwrap();
            owner.reconnect(peer.local_addr().unwrap(), 1600).unwrap();
            assert_ne!(owner.local_addr().unwrap(), local);
            owner
                .send_reserved(&overflow, reporter, Duration::ZERO)
                .unwrap();
            let (length, source) = peer.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], &overflow);
            assert_eq!(source, owner.local_addr().unwrap());
        }
    }

    #[test]
    fn busy_reservation_does_not_consume_an_unsent_counter() {
        for ipv6 in [false, true] {
            let peer = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                peer.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            owner
                .send_reserved(&packet(1), reporter, Duration::ZERO)
                .unwrap();
            assert_eq!(
                owner
                    .send_reserved(&packet(2), reporter, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::Busy)
            );
            owner.cancel_reservation();
            owner
                .send_reserved(&packet(2), reporter, Duration::ZERO)
                .unwrap();
            let mut buffer = [0; 128];
            for expected in [packet(1), packet(2)] {
                let length = peer.recv(&mut buffer).unwrap();
                assert_eq!(&buffer[..length], &expected);
            }
        }
    }

    #[test]
    fn counter_order_uses_wireguard_little_endian_numeric_value() {
        for ipv6 in [false, true] {
            let peer = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                peer.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let mut first = packet(0);
            first[8..16].copy_from_slice(&255_u64.to_le_bytes());
            let mut next = packet(0);
            next[8..16].copy_from_slice(&256_u64.to_le_bytes());
            owner
                .send_reserved(&first, reporter, Duration::ZERO)
                .unwrap();
            owner.cancel_reservation();
            owner
                .send_reserved(&next, reporter, Duration::ZERO)
                .unwrap();
            owner.cancel_reservation();
            assert_eq!(
                owner
                    .send_reserved(&first, reporter, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::NonIncreasingCounter)
            );
            let mut buffer = [0; 128];
            for expected in [first, next] {
                let length = peer.recv(&mut buffer).unwrap();
                assert_eq!(&buffer[..length], &expected);
            }
        }
    }

    #[test]
    fn queued_old_peer_datagram_is_not_delivered_after_reconnect() {
        for ipv6 in [false, true] {
            let first = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let second = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                first.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let local = owner.local_addr().unwrap();
            first.send_to(b"old peer", local).unwrap();
            let mut buffer = [0; 128];
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            let (length, source) = loop {
                match owner.socket.peek_from(&mut buffer) {
                    Ok(datagram) => break datagram,
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                        assert!(
                            std::time::Instant::now() < deadline,
                            "old peer datagram was not queued"
                        );
                        std::thread::yield_now();
                    }
                }
            };
            assert_eq!(&buffer[..length], b"old peer");
            assert_eq!(source, first.local_addr().unwrap());

            owner.reconnect(second.local_addr().unwrap(), 1600).unwrap();
            assert_ne!(owner.local_addr().unwrap(), local);
            assert!(owner.receive_datagram(&mut buffer).unwrap().is_none());
            second
                .send_to(b"new peer", owner.local_addr().unwrap())
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                assert!(
                    std::time::Instant::now() < deadline,
                    "new peer datagram was not received"
                );
                match owner.receive_datagram(&mut buffer).unwrap() {
                    Some(length) => {
                        assert_eq!(&buffer[..length], b"new peer");
                        break;
                    }
                    None => {
                        std::thread::yield_now();
                    }
                }
            }
            assert!(owner.receive_datagram(&mut buffer).unwrap().is_none());
            drop(owner);
            UdpSocket::bind(local).unwrap();
        }
    }

    #[test]
    fn queued_datagram_is_retired_when_returning_to_the_same_peer() {
        for ipv6 in [false, true] {
            let first = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let second = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                first.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let local = owner.local_addr().unwrap();
            first.send_to(b"old generation", local).unwrap();
            let mut buffer = [0; 128];
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                match owner.socket.peek_from(&mut buffer) {
                    Ok((length, source)) => {
                        assert_eq!(&buffer[..length], b"old generation");
                        assert_eq!(source, first.local_addr().unwrap());
                        break;
                    }
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                        assert!(
                            std::time::Instant::now() < deadline,
                            "old datagram was not queued"
                        );
                        std::thread::yield_now();
                    }
                }
            }
            owner.reconnect(second.local_addr().unwrap(), 1600).unwrap();
            owner.reconnect(first.local_addr().unwrap(), 1600).unwrap();
            assert!(owner.receive_datagram(&mut buffer).unwrap().is_none());
            drop(owner);
            UdpSocket::bind(local).unwrap();
        }
    }

    #[test]
    fn retired_ports_remain_reserved_until_owner_drop_and_capacity_refusal_preserves_flow() {
        for ipv6 in [false, true] {
            let first = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let second = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                first.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let mut addresses = vec![owner.local_addr().unwrap()];
            for index in 0..MAX_RETIRED_SOCKETS {
                let remote = if index % 2 == 0 { &second } else { &first };
                owner.reconnect(remote.local_addr().unwrap(), 1600).unwrap();
                let local = owner.local_addr().unwrap();
                assert!(!addresses.contains(&local), "retained port was reused");
                addresses.push(local);
            }
            let old_local = addresses[0];
            assert_eq!(
                UdpSocket::bind(old_local).unwrap_err().kind(),
                io::ErrorKind::AddrInUse
            );
            first.send_to(b"delayed old datagram", old_local).unwrap();
            assert!(owner.receive_datagram(&mut [0; 128]).unwrap().is_none());
            let current = packet(42);
            owner
                .send_reserved(&current, reporter, Duration::ZERO)
                .unwrap();
            let feedback = report(&owner, &current, reporter);
            let local = owner.local_addr().unwrap();
            assert_eq!(
                owner
                    .reconnect(second.local_addr().unwrap(), 1600)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::RetiredSocketLimit)
            );
            assert_eq!(owner.local_addr().unwrap(), local);
            assert!(owner.apply(&feedback, Duration::ZERO).unwrap());
            assert_eq!(owner.outer_mtu(), 1400);
            let mut buffer = [0; 128];
            first
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let length = first.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], &current);
            drop(owner);
            let sockets = addresses
                .into_iter()
                .map(UdpSocket::bind)
                .collect::<io::Result<Vec<_>>>()
                .unwrap();
            drop(sockets);
        }
    }

    #[test]
    fn delayed_datagram_can_reach_new_owner_after_port_reuse() {
        for ipv6 in [false, true] {
            let peer = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let owner = Owner::new(
                crate::loopback_address(ipv6),
                peer.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let old_local = owner.local_addr().unwrap();
            drop(owner);

            // Force reuse instead of depending on the kernel's ephemeral port choice.
            let replacement = Owner::new(old_local, peer.local_addr().unwrap(), 1600).unwrap();
            peer.send_to(b"delayed old generation", old_local).unwrap();
            let mut buffer = [0; 128];
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                assert!(
                    std::time::Instant::now() < deadline,
                    "datagram was not received"
                );
                if let Some(length) = replacement.receive_datagram(&mut buffer).unwrap() {
                    assert_eq!(&buffer[..length], b"delayed old generation");
                    break;
                }
                std::thread::yield_now();
            }
        }
    }

    #[test]
    fn replacing_socket_discards_queued_datagram_before_returning_to_peer() {
        for ipv6 in [false, true] {
            let first = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let second = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                first.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let original_local = owner.local_addr().unwrap();
            first.send_to(b"old generation", original_local).unwrap();
            let mut buffer = [0; 128];
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                match owner.socket.peek_from(&mut buffer) {
                    Ok((length, source)) => {
                        assert_eq!(&buffer[..length], b"old generation");
                        assert_eq!(source, first.local_addr().unwrap());
                        break;
                    }
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                        assert!(
                            std::time::Instant::now() < deadline,
                            "old datagram was not queued"
                        );
                        std::thread::yield_now();
                    }
                }
            }
            let replacement = Owner::new(
                crate::loopback_address(ipv6),
                second.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            assert_ne!(replacement.local_addr().unwrap(), original_local);
            owner = replacement;
            let second_local = owner.local_addr().unwrap();
            let replacement = Owner::new(
                crate::loopback_address(ipv6),
                first.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            assert_ne!(replacement.local_addr().unwrap(), second_local);
            owner = replacement;
            let final_local = owner.local_addr().unwrap();
            assert!(owner.receive_datagram(&mut buffer).unwrap().is_none());
            first.send_to(b"new generation", final_local).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                assert!(
                    std::time::Instant::now() < deadline,
                    "new datagram was not received"
                );
                if let Some(length) = owner.receive_datagram(&mut buffer).unwrap() {
                    assert_eq!(&buffer[..length], b"new generation");
                    break;
                }
                std::thread::yield_now();
            }
            drop(owner);
            UdpSocket::bind(final_local).unwrap();
        }
    }

    #[test]
    fn failed_transition_retires_feedback_and_recovery_uses_new_reader() {
        for ipv6 in [false, true] {
            let first = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let other = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let reporter: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let mut owner = Owner::new(
                crate::loopback_address(ipv6),
                first.local_addr().unwrap(),
                1600,
            )
            .unwrap();
            let local = owner.socket.local_addr().unwrap();
            let initial = packet(1);
            owner
                .send_reserved(&initial, reporter, Duration::ZERO)
                .unwrap();
            let stale = report(&owner, &initial, reporter);
            let mut invalid = other.local_addr().unwrap();
            invalid.set_port(0);
            assert_eq!(
                owner
                    .reconnect(invalid, 1600)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::InvalidPeer)
            );
            assert!(owner.queue.is_some());
            assert_eq!(
                owner
                    .reconnect(other.local_addr().unwrap(), 1300)
                    .unwrap_err()
                    .downcast_ref::<crate::path_mtu::Error>(),
                Some(&crate::path_mtu::Error::PathTooSmall)
            );
            assert_eq!(
                owner
                    .send_reserved(&packet(2), reporter, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::Busy)
            );
            let error = owner
                .reconnect_with(other.local_addr().unwrap(), 1600, |socket, address| {
                    socket.connect(address)?;
                    Err(io::Error::from(io::ErrorKind::PermissionDenied))
                })
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(owner.queue.is_none());
            assert_eq!(
                owner.socket.peer_addr().unwrap(),
                first.local_addr().unwrap()
            );
            assert_eq!(
                owner
                    .apply(&stale, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::Unavailable)
            );
            assert_eq!(
                owner
                    .send_reserved(&packet(2), reporter, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::Unavailable)
            );
            owner.reconnect(first.local_addr().unwrap(), 1600).unwrap();
            let next = packet(3);
            owner
                .send_reserved(&next, reporter, Duration::ZERO)
                .unwrap();
            assert_eq!(
                owner
                    .apply(&stale, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<crate::outer_remote::Error>(),
                Some(&crate::outer_remote::Error::Unmatched)
            );
            assert_eq!(owner.budget.outer_mtu(), 1600);
            for _ in 1..MAX_RETIRED_SOCKETS {
                owner.reconnect(other.local_addr().unwrap(), 1600).unwrap();
            }
            assert_eq!(
                owner
                    .reconnect(first.local_addr().unwrap(), 1600)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::RetiredSocketLimit)
            );
            drop(owner);
            UdpSocket::bind(local).unwrap();
        }
    }
}
