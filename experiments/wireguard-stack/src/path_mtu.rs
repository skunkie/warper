// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Conservative declared outer-path envelope; not path MTU discovery.

use std::fmt;

use crate::packet_peer::MTU;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidMtu,
    PathTooSmall,
    PacketTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WireGuard path budget: {self:?}")
    }
}

impl std::error::Error for Error {}

pub struct PathBudget {
    outer_mtu: usize,
    outer_headers: usize,
}

impl PathBudget {
    pub fn new(outer_mtu: usize, ipv6: bool) -> Result<Self, Error> {
        let budget = Self {
            outer_mtu,
            outer_headers: if ipv6 { 48 } else { 28 },
        };
        // Reserve padding to a 16-byte boundary even though pinned BoringTun
        // emits unpadded data. Inner IPv6 still requires a 1280-byte link MTU.
        let minimum = MTU.div_ceil(16) * 16 + 32 + budget.outer_headers;
        if outer_mtu > 65535 {
            return Err(Error::InvalidMtu);
        }
        if outer_mtu < minimum {
            return Err(Error::PathTooSmall);
        }
        Ok(budget)
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn reduce(&mut self, outer_mtu: usize) -> Result<bool, Error> {
        let candidate = Self::new(outer_mtu, self.outer_headers == 48)?;
        if outer_mtu >= self.outer_mtu {
            return Ok(false);
        }
        *self = candidate;
        Ok(true)
    }

    pub fn outer_mtu(&self) -> usize {
        self.outer_mtu
    }

    pub fn check_datagram(&self, encrypted_length: usize) -> Result<(), Error> {
        if encrypted_length > self.outer_mtu() - self.outer_headers {
            return Err(Error::PacketTooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_outer_path_covers_inner_mtu_and_both_transport_families() {
        for (ipv6, minimum) in [(false, 1340), (true, 1360)] {
            assert!(matches!(
                PathBudget::new(minimum - 1, ipv6),
                Err(Error::PathTooSmall)
            ));
            let budget = PathBudget::new(minimum, ipv6).unwrap();
            assert_eq!(budget.check_datagram(1312), Ok(()));
            assert_eq!(budget.check_datagram(1313), Err(Error::PacketTooLarge));
            assert_eq!(
                budget.check_datagram(usize::MAX),
                Err(Error::PacketTooLarge)
            );
        }
        assert!(matches!(
            PathBudget::new(usize::MAX, false),
            Err(Error::InvalidMtu)
        ));
    }

    #[test]
    fn reductions_are_validated_before_mutation_and_never_grow_the_budget() {
        for ipv6 in [false, true] {
            let mut budget = PathBudget::new(1500, ipv6).unwrap();
            assert_eq!(budget.reduce(1400), Ok(true));
            assert_eq!(budget.outer_mtu(), 1400);
            assert_eq!(budget.reduce(1400), Ok(false));
            assert_eq!(budget.reduce(1500), Ok(false));
            assert_eq!(budget.reduce(1300), Err(Error::PathTooSmall));
            assert_eq!(budget.reduce(65536), Err(Error::InvalidMtu));
            assert_eq!(budget.outer_mtu(), 1400);
            assert_eq!(
                budget.check_datagram(1400 - if ipv6 { 48 } else { 28 }),
                Ok(())
            );
            assert_eq!(
                budget.check_datagram(1401 - if ipv6 { 48 } else { 28 }),
                Err(Error::PacketTooLarge)
            );
        }
    }
}
