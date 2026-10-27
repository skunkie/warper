// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One bounded, expiring correlation for a controlled router MTU error.

use crate::{outer_errors::ReceivedError, packet_peer::Peer, path_mtu::PathBudget};
use nix::{errno::Errno, sys::socket::MsgFlags};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidPacket,
    InvalidTime,
    Timeout,
    MissingReservation,
    Unmatched,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "remote outer MTU feedback: {self:?}")
    }
}

impl std::error::Error for Error {}

struct Pending {
    local: SocketAddr,
    prefix: [u8; 16],
    encrypted_len: usize,
    reporter: IpAddr,
    deadline: Duration,
}

#[derive(Default)]
pub struct Reservation {
    pending: Option<Pending>,
    now: Duration,
}

impl Reservation {
    pub fn reserve(
        &mut self,
        packet: &[u8],
        local: SocketAddr,
        reporter: IpAddr,
        now: Duration,
        lifetime: Duration,
    ) -> Result<(), Error> {
        self.advance(now)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if lifetime.is_zero() || lifetime > Duration::from_secs(10) {
            return Err(Error::InvalidTime);
        }
        if local.ip().is_unspecified()
            || local.ip().is_multicast()
            || local.port() == 0
            || local.is_ipv6() != reporter.is_ipv6()
            || !(33..=1536).contains(&packet.len())
            || packet[..4] != [4, 0, 0, 0]
            || reporter.is_unspecified()
            || reporter.is_multicast()
        {
            return Err(Error::InvalidPacket);
        }
        let deadline = now.checked_add(lifetime).ok_or(Error::InvalidTime)?;
        if deadline.as_millis() > i64::MAX as u128 {
            return Err(Error::InvalidTime);
        }
        let mut prefix = [0; 16];
        prefix.copy_from_slice(&packet[..16]);
        self.pending = Some(Pending {
            local,
            prefix,
            encrypted_len: packet.len(),
            reporter,
            deadline,
        });
        Ok(())
    }

    pub fn apply(
        &mut self,
        received: &ReceivedError,
        remote: SocketAddr,
        budget: &mut PathBudget,
        now: Duration,
    ) -> anyhow::Result<bool> {
        let mtu = self.reduction(received, remote, now)?;
        let changed = budget.reduce(mtu)?;
        self.cancel();
        Ok(changed)
    }

    pub fn apply_tcp(
        &mut self,
        received: &ReceivedError,
        remote: SocketAddr,
        peer: &mut Peer,
        budget: &mut PathBudget,
        now: Duration,
    ) -> anyhow::Result<usize> {
        let mtu = self.reduction(received, remote, now)?;
        let retired = crate::outer_tcp_probe::apply_outer(peer, budget, mtu, now)?;
        self.cancel();
        Ok(retired)
    }

    pub fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.now || now.as_millis() > i64::MAX as u128 {
            return Err(Error::InvalidTime);
        }
        self.now = now;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.deadline)
        {
            self.cancel();
            return Err(Error::Timeout);
        }
        Ok(())
    }

    pub fn cancel(&mut self) {
        self.pending = None;
    }
    fn reduction(
        &mut self,
        received: &ReceivedError,
        remote: SocketAddr,
        now: Duration,
    ) -> anyhow::Result<usize> {
        self.advance(now)?;
        let pending = self.pending.as_ref().ok_or(Error::MissingReservation)?;
        let record = &received.record;
        let (origin, kind, code) = if remote.is_ipv6() {
            (nix::libc::SO_EE_ORIGIN_ICMP6, 2, 0)
        } else {
            (nix::libc::SO_EE_ORIGIN_ICMP, 3, 4)
        };
        if !received.flags.contains(MsgFlags::MSG_ERRQUEUE)
            || received
                .flags
                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
            || record.ipv6 != remote.is_ipv6()
            || received.local != pending.local
            || received.destination != Some(remote)
            || record.errno != Errno::EMSGSIZE as u32
            || record.origin != origin
            || record.kind != kind
            || record.code != code
            || record.reporter != Some(pending.reporter)
            || pending.reporter.is_ipv6() != remote.is_ipv6()
            || received.quoted_len < 16
            || received.quoted_len > pending.encrypted_len
            || received.prefix != pending.prefix
            || record.mtu == 0
            || record.mtu > 65535
        {
            return Err(Error::Unmatched.into());
        }
        Ok(record.mtu as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outer_errors::Record;

    fn fixture(ipv6: bool) -> (Reservation, ReceivedError, SocketAddr) {
        let remote: SocketAddr = if ipv6 {
            "[fd77:2::2]:9010"
        } else {
            "198.19.0.2:9010"
        }
        .parse()
        .unwrap();
        let reporter: IpAddr = if ipv6 { "fd77:1::1" } else { "198.18.0.1" }
            .parse()
            .unwrap();
        let mut packet = [0; 1432];
        packet[0] = 4;
        packet[4] = 17;
        packet[8] = 29;
        let local = if ipv6 {
            "[fd77:1::2]:40000"
        } else {
            "198.18.0.2:40000"
        }
        .parse()
        .unwrap();
        let mut reservation = Reservation::default();
        reservation
            .reserve(
                &packet,
                local,
                reporter,
                Duration::ZERO,
                Duration::from_secs(1),
            )
            .unwrap();
        let mut prefix = [0; 16];
        prefix.copy_from_slice(&packet[..16]);
        let received = ReceivedError {
            local,
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
            destination: Some(remote),
            flags: MsgFlags::MSG_ERRQUEUE,
            prefix,
            quoted_len: 16,
        };
        (reservation, received, remote)
    }

    #[test]
    fn exact_header_and_router_commit_only_after_budget_validation() {
        for ipv6 in [false, true] {
            let (mut reservation, mut received, remote) = fixture(ipv6);
            let mut budget = PathBudget::new(1600, ipv6).unwrap();
            received.record.mtu = 1300;
            assert_eq!(
                reservation
                    .apply(&received, remote, &mut budget, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<crate::path_mtu::Error>(),
                Some(&crate::path_mtu::Error::PathTooSmall)
            );
            assert!(reservation.pending.is_some());
            assert_eq!(budget.outer_mtu(), 1600);
            received.record.mtu = 1400;
            assert!(
                reservation
                    .apply(&received, remote, &mut budget, Duration::ZERO)
                    .unwrap()
            );
            assert_eq!(budget.outer_mtu(), 1400);
            assert!(reservation.pending.is_none());
            assert_eq!(
                reservation
                    .apply(&received, remote, &mut budget, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::MissingReservation)
            );
            let (mut reservation, mut received, remote) = fixture(ipv6);
            received.record.mtu = 1500;
            assert!(
                !reservation
                    .apply(&received, remote, &mut budget, Duration::ZERO)
                    .unwrap()
            );
            assert_eq!(budget.outer_mtu(), 1400);
            assert!(reservation.pending.is_none());
        }
    }

    #[test]
    fn unrelated_truncated_or_malformed_reports_preserve_reservation_and_budget() {
        for ipv6 in [false, true] {
            for case in 0..20 {
                let (mut reservation, mut received, remote) = fixture(ipv6);
                match case {
                    0 => received.record.reporter = None,
                    1 => {
                        received.record.reporter = Some(
                            if ipv6 { "fd77:1::9" } else { "198.18.0.9" }
                                .parse()
                                .unwrap(),
                        )
                    }
                    2 => received.record.ipv6 = !ipv6,
                    3 => received.record.errno = Errno::ECONNREFUSED as u32,
                    4 => received.record.origin = nix::libc::SO_EE_ORIGIN_LOCAL,
                    5 => received.record.kind = 1,
                    6 => received.record.code = 1,
                    7 => received.destination = None,
                    8 => received.destination.as_mut().unwrap().set_port(9011),
                    9 => received.prefix[4] ^= 1,
                    10 => received.prefix[8] ^= 1,
                    11 => received.quoted_len = 15,
                    12 => received.quoted_len = 1433,
                    13 => received.flags |= MsgFlags::MSG_TRUNC,
                    14 => received.flags |= MsgFlags::MSG_CTRUNC,
                    15 => received.flags = MsgFlags::empty(),
                    16 => received.record.mtu = 65536,
                    17 => received.record.mtu = 0,
                    18 => received.prefix[0] ^= 1,
                    19 => received.destination.as_mut().unwrap().set_ip(
                        if ipv6 { "fd77:2::9" } else { "198.19.0.9" }
                            .parse()
                            .unwrap(),
                    ),
                    _ => unreachable!(),
                }
                let mut budget = PathBudget::new(1600, ipv6).unwrap();
                assert_eq!(
                    reservation
                        .apply(&received, remote, &mut budget, Duration::ZERO)
                        .unwrap_err()
                        .downcast_ref::<Error>(),
                    Some(&Error::Unmatched),
                    "case {case}"
                );
                assert!(reservation.pending.is_some());
                assert_eq!(budget.outer_mtu(), 1600);
            }
        }
    }

    #[test]
    fn every_short_quote_preserves_the_reservation_and_budget() {
        for ipv6 in [false, true] {
            for length in 0..16 {
                let (mut reservation, mut received, remote) = fixture(ipv6);
                received.quoted_len = length;
                received.prefix[length..].fill(0);
                let mut budget = PathBudget::new(1600, ipv6).unwrap();
                assert_eq!(
                    reservation
                        .apply(&received, remote, &mut budget, Duration::ZERO)
                        .unwrap_err()
                        .downcast_ref::<Error>(),
                    Some(&Error::Unmatched),
                    "IPv6 {ipv6}, quote length {length}"
                );
                assert!(reservation.pending.is_some());
                assert_eq!(budget.outer_mtu(), 1600);
            }
        }
    }

    #[test]
    fn delayed_feedback_cannot_change_a_later_distinct_reservation() {
        for ipv6 in [false, true] {
            for retirement in ["commit", "cancel", "expiry"] {
                let (mut reservation, stale, remote) = fixture(ipv6);
                let mut budget = PathBudget::new(1600, ipv6).unwrap();
                let now = match retirement {
                    "commit" => {
                        assert!(
                            reservation
                                .apply(&stale, remote, &mut budget, Duration::ZERO)
                                .unwrap()
                        );
                        // Use a fresh budget to observe whether stale feedback mutates it.
                        budget = PathBudget::new(1600, ipv6).unwrap();
                        Duration::ZERO
                    }
                    "cancel" => {
                        reservation.cancel();
                        Duration::ZERO
                    }
                    "expiry" => {
                        let now = Duration::from_secs(1);
                        assert_eq!(reservation.advance(now), Err(Error::Timeout));
                        now
                    }
                    _ => unreachable!(),
                };
                let mut packet = [0; 1432];
                packet[..16].copy_from_slice(&stale.prefix);
                packet[8] ^= 1;
                reservation
                    .reserve(
                        &packet,
                        stale.local,
                        stale.record.reporter.unwrap(),
                        now,
                        Duration::from_secs(1),
                    )
                    .unwrap();
                assert_eq!(
                    reservation
                        .apply(&stale, remote, &mut budget, now)
                        .unwrap_err()
                        .downcast_ref::<Error>(),
                    Some(&Error::Unmatched),
                    "IPv6 {ipv6}, retirement {retirement}"
                );
                assert_eq!(budget.outer_mtu(), 1600);
                assert!(reservation.pending.is_some());
                let (_, mut current, _) = fixture(ipv6);
                current.prefix.copy_from_slice(&packet[..16]);
                assert!(
                    reservation
                        .apply(&current, remote, &mut budget, now)
                        .unwrap()
                );
                assert_eq!(budget.outer_mtu(), 1400);
                assert!(reservation.pending.is_none());
            }
        }
    }

    #[test]
    fn matching_header_from_another_local_socket_cannot_reduce_budget() {
        for ipv6 in [false, true] {
            let (mut reservation, mut received, remote) = fixture(ipv6);
            let original = received.local;
            received.local.set_port(original.port() + 1);
            let mut budget = PathBudget::new(1600, ipv6).unwrap();
            assert_eq!(
                reservation
                    .apply(&received, remote, &mut budget, Duration::ZERO)
                    .unwrap_err()
                    .downcast_ref::<Error>(),
                Some(&Error::Unmatched)
            );
            assert_eq!(budget.outer_mtu(), 1600);
            assert!(reservation.pending.is_some());
            received.local = original;
            assert!(
                reservation
                    .apply(&received, remote, &mut budget, Duration::ZERO)
                    .unwrap()
            );
        }
    }

    #[test]
    fn invalid_local_socket_identity_cannot_reserve() {
        let mut packet = [0; 64];
        packet[0] = 4;
        for local in [
            "0.0.0.0:40000",
            "224.0.0.1:40000",
            "198.18.0.2:0",
            "[::1]:40000",
        ] {
            assert_eq!(
                Reservation::default().reserve(
                    &packet,
                    local.parse().unwrap(),
                    "198.18.0.1".parse().unwrap(),
                    Duration::ZERO,
                    Duration::from_secs(1)
                ),
                Err(Error::InvalidPacket),
                "{local}"
            );
        }
    }

    #[test]
    fn repeated_header_cannot_distinguish_old_feedback_from_current_feedback() {
        for ipv6 in [false, true] {
            let (mut reservation, received, remote) = fixture(ipv6);
            reservation.cancel();
            let mut packet = [0; 1432];
            packet[..16].copy_from_slice(&received.prefix);
            reservation
                .reserve(
                    &packet,
                    received.local,
                    received.record.reporter.unwrap(),
                    Duration::ZERO,
                    Duration::from_secs(1),
                )
                .unwrap();
            let mut budget = PathBudget::new(1600, ipv6).unwrap();
            assert!(
                reservation
                    .apply(&received, remote, &mut budget, Duration::ZERO)
                    .unwrap()
            );
            assert_eq!(budget.outer_mtu(), 1400);
        }
    }

    #[test]
    fn tcp_sizing_keeps_the_reservation_until_queue_busy_retry_commits() {
        use smoltcp::{phy::Device, socket::tcp};
        for ipv6 in [false, true] {
            let (mut reservation, received, remote) = fixture(ipv6);
            let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }
                .parse()
                .unwrap();
            let target: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }
                .parse()
                .unwrap();
            let mut peer = Peer::with_mtu(source, 40000, 1500).unwrap();
            peer.sockets
                .get_mut::<tcp::Socket>(peer.tcp)
                .connect(peer.interface.context(), (target, 9000), (source, 40001))
                .unwrap();
            peer.poll(0);
            let queued = peer.device.outgoing.clone();
            let tuple = {
                let socket = peer.sockets.get::<tcp::Socket>(peer.tcp);
                (
                    socket.local_endpoint(),
                    socket.remote_endpoint(),
                    socket.state(),
                )
            };
            peer.device.inject(vec![0]).unwrap();
            let mut budget = PathBudget::new(1600, ipv6).unwrap();
            let error = reservation
                .apply_tcp(&received, remote, &mut peer, &mut budget, Duration::ZERO)
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(reservation.pending.is_some());
            assert_eq!(budget.outer_mtu(), 1600);
            assert_eq!(peer.device.outgoing, queued);
            assert_eq!(peer.device.capabilities().max_transmission_unit, 1500);
            peer.poll(1);
            assert!(!peer.device.has_ingress());
            assert_eq!(
                reservation
                    .apply_tcp(
                        &received,
                        remote,
                        &mut peer,
                        &mut budget,
                        Duration::from_millis(1)
                    )
                    .unwrap(),
                queued.len()
            );
            assert!(reservation.pending.is_none());
            assert_eq!(budget.outer_mtu(), 1400);
            assert_eq!(
                peer.device.capabilities().max_transmission_unit,
                if ipv6 { 1312 } else { 1328 }
            );
            let socket = peer.sockets.get::<tcp::Socket>(peer.tcp);
            assert_eq!(
                (
                    socket.local_endpoint(),
                    socket.remote_endpoint(),
                    socket.state()
                ),
                tuple
            );
        }
    }

    #[test]
    fn tcp_rejects_invalid_feedback_limits_or_time_before_retiring_attempts() {
        use smoltcp::{phy::Device, socket::tcp};
        for case in 0..5 {
            let (mut reservation, mut received, remote) = fixture(false);
            let source: IpAddr = "10.66.66.2".parse().unwrap();
            let target: IpAddr = "10.66.66.10".parse().unwrap();
            let mut peer = Peer::with_mtu(source, 40000, 1500).unwrap();
            peer.sockets
                .get_mut::<tcp::Socket>(peer.tcp)
                .connect(peer.interface.context(), (target, 9000), (source, 40001))
                .unwrap();
            peer.poll(0);
            let queued = peer.device.outgoing.clone();
            match case {
                0 => received.prefix[8] ^= 1,
                1 => received.record.mtu = 1300,
                2 => {
                    received.record.mtu = 0;
                }
                3 | 4 => {}
                _ => unreachable!(),
            }
            let mut budget = PathBudget::new(1600, false).unwrap();
            let now = match case {
                3 => Duration::from_secs(1),
                4 => Duration::MAX,
                _ => Duration::ZERO,
            };
            let error = reservation
                .apply_tcp(&received, remote, &mut peer, &mut budget, now)
                .unwrap_err();
            if case == 1 {
                assert_eq!(
                    error.downcast_ref::<crate::path_mtu::Error>(),
                    Some(&crate::path_mtu::Error::PathTooSmall)
                );
            } else {
                let expected = match case {
                    3 => Error::Timeout,
                    4 => Error::InvalidTime,
                    _ => Error::Unmatched,
                };
                assert_eq!(error.downcast_ref::<Error>(), Some(&expected));
            }
            assert_eq!(reservation.pending.is_some(), case != 3);
            assert_eq!(peer.device.outgoing, queued);
            assert_eq!(budget.outer_mtu(), 1600);
            assert_eq!(peer.device.capabilities().max_transmission_unit, 1500);
        }
    }

    #[test]
    fn reservation_is_bounded_nonrenewing_expiring_and_cancellable() {
        let (mut reservation, received, remote) = fixture(false);
        let mut packet = [0; 1432];
        packet[0] = 4;
        assert_eq!(
            reservation.reserve(
                &packet,
                "198.18.0.2:40000".parse().unwrap(),
                "198.18.0.1".parse().unwrap(),
                Duration::ZERO,
                Duration::from_secs(1)
            ),
            Err(Error::Busy)
        );
        let mut budget = PathBudget::new(1600, false).unwrap();
        assert_eq!(
            reservation
                .apply(&received, remote, &mut budget, Duration::from_secs(1))
                .unwrap_err()
                .downcast_ref::<Error>(),
            Some(&Error::Timeout)
        );
        assert!(reservation.pending.is_none());
        assert_eq!(budget.outer_mtu(), 1600);
        assert_eq!(reservation.advance(Duration::ZERO), Err(Error::InvalidTime));
        assert_eq!(reservation.advance(Duration::MAX), Err(Error::InvalidTime));
        for lifetime in [Duration::ZERO, Duration::from_secs(11)] {
            assert_eq!(
                Reservation::default().reserve(
                    &packet,
                    "198.18.0.2:40000".parse().unwrap(),
                    "198.18.0.1".parse().unwrap(),
                    Duration::ZERO,
                    lifetime
                ),
                Err(Error::InvalidTime)
            );
        }
        for packet in [Vec::new(), vec![0; 32], vec![0; 1537], vec![1; 64]] {
            assert_eq!(
                Reservation::default().reserve(
                    &packet,
                    "198.18.0.2:40000".parse().unwrap(),
                    "198.18.0.1".parse().unwrap(),
                    Duration::ZERO,
                    Duration::from_secs(1)
                ),
                Err(Error::InvalidPacket)
            );
        }
        for reporter in ["0.0.0.0", "224.0.0.1", "::", "ff02::1"] {
            assert_eq!(
                Reservation::default().reserve(
                    &packet,
                    if reporter.contains(':') {
                        "[fd77:1::2]:40000"
                    } else {
                        "198.18.0.2:40000"
                    }
                    .parse()
                    .unwrap(),
                    reporter.parse().unwrap(),
                    Duration::ZERO,
                    Duration::from_secs(1)
                ),
                Err(Error::InvalidPacket)
            );
        }
        assert_eq!(
            Reservation::default().reserve(
                &packet,
                "198.18.0.2:40000".parse().unwrap(),
                "198.18.0.1".parse().unwrap(),
                Duration::from_millis(i64::MAX as u64),
                Duration::from_secs(1)
            ),
            Err(Error::InvalidTime)
        );
        let mut reservation = Reservation::default();
        reservation
            .reserve(
                &packet,
                "198.18.0.2:40000".parse().unwrap(),
                "198.18.0.1".parse().unwrap(),
                Duration::ZERO,
                Duration::from_secs(1),
            )
            .unwrap();
        reservation.cancel();
        assert!(reservation.pending.is_none());
    }
}
