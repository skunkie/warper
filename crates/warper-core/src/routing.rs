// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Immutable static CIDR selection with bounded construction and no fallback.

use std::{fmt, net::IpAddr};

use crate::BackendId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub network: IpAddr,
    pub prefix_len: u8,
    pub backend: BackendId,
}

impl Entry {
    fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) if self.prefix_len <= 32 => {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix_len))
                    .unwrap_or(0);
                u32::from(network) == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) if self.prefix_len <= 128 => {
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix_len))
                    .unwrap_or(0);
                u128::from(network) == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimit,
    ResourceLimit,
    InvalidPrefix { index: usize },
    DuplicateAssignment,
    ConflictingAssignment,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("route entry limit must be positive"),
            Self::ResourceLimit => formatter.write_str("route entry limit exceeded"),
            Self::InvalidPrefix { index } => {
                write!(formatter, "invalid canonical prefix at route entry {index}")
            }
            Self::DuplicateAssignment => formatter.write_str("duplicate route assignment"),
            Self::ConflictingAssignment => {
                formatter.write_str("the same prefix selects different backends")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A caller publishes a complete snapshot; established flows retain the result
/// of their original selection independently of later snapshots.
#[derive(Debug)]
pub struct Policy {
    entries: Box<[Entry]>,
}

impl Policy {
    /// Bound allocation and validate before publication. No OS state changes occur here.
    pub fn new(entries: &[Entry], limit: usize) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Error::InvalidLimit);
        }
        if entries.len() > limit {
            return Err(Error::ResourceLimit);
        }
        for (index, entry) in entries.iter().enumerate() {
            if !entry.contains(entry.network) {
                return Err(Error::InvalidPrefix { index });
            }
        }
        let mut entries = entries.to_vec();
        entries.sort_unstable_by(|first, second| {
            second
                .prefix_len
                .cmp(&first.prefix_len)
                .then_with(|| first.network.cmp(&second.network))
        });
        for pair in entries.windows(2) {
            if pair[0].network == pair[1].network && pair[0].prefix_len == pair[1].prefix_len {
                return Err(if pair[0].backend == pair[1].backend {
                    Error::DuplicateAssignment
                } else {
                    Error::ConflictingAssignment
                });
            }
        }
        Ok(Self {
            entries: entries.into_boxed_slice(),
        })
    }

    /// Canonical immutable entries in selection order, for installing the
    /// corresponding capture mappings without rebuilding routing policy.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Return the winning backend once. Capability/transport errors belong to
    /// that backend; they cannot cause selection of a broader prefix or direct I/O.
    pub fn select(&self, destination: IpAddr) -> Option<BackendId> {
        self.entries
            .iter()
            .find(|entry| entry.contains(destination))
            .map(|entry| entry.backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(network: &str, prefix_len: u8, backend: u64) -> Entry {
        Entry {
            network: network.parse().unwrap(),
            prefix_len,
            backend: BackendId(backend),
        }
    }

    #[test]
    fn longest_prefix_wins_in_both_families_regardless_of_configuration_order() {
        let entries = [
            entry("0.0.0.0", 0, 1),
            entry("192.0.2.0", 24, 2),
            entry("192.0.2.128", 25, 3),
            entry("::", 0, 4),
            entry("2001:db8::", 32, 5),
            entry("2001:db8::1", 128, 6),
        ];
        for entries in [entries.to_vec(), entries.into_iter().rev().collect()] {
            let policy = Policy::new(&entries, 6).unwrap();
            for (address, expected) in [
                ("198.51.100.1", 1),
                ("192.0.2.0", 2),
                ("192.0.2.127", 2),
                ("192.0.2.128", 3),
                ("192.0.2.255", 3),
                ("2001:db8::2", 5),
                ("2001:db8::1", 6),
                ("2001:db9::1", 4),
            ] {
                assert_eq!(
                    policy.select(address.parse().unwrap()),
                    Some(BackendId(expected)),
                    "{address}"
                );
            }
        }
    }

    #[test]
    fn unmatched_destinations_and_other_families_remain_unselected() {
        let policy = Policy::new(&[entry("192.0.2.1", 32, 1)], 1).unwrap();
        assert_eq!(
            policy.select("192.0.2.1".parse().unwrap()),
            Some(BackendId(1))
        );
        for address in ["192.0.2.0", "192.0.2.2", "2001:db8::1"] {
            assert_eq!(policy.select(address.parse().unwrap()), None, "{address}");
        }
        assert_eq!(
            Policy::new(&[], 1)
                .unwrap()
                .select("192.0.2.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn invalid_or_conflicting_input_cannot_publish_a_policy() {
        assert!(matches!(Policy::new(&[], 0), Err(Error::InvalidLimit)));
        assert!(matches!(
            Policy::new(&[entry("192.0.2.0", 24, 1)], 0),
            Err(Error::InvalidLimit)
        ));
        assert!(matches!(
            Policy::new(&[entry("192.0.2.0", 24, 1); 2], 1),
            Err(Error::ResourceLimit)
        ));
        for invalid in [
            entry("192.0.2.1", 24, 1),
            entry("192.0.2.0", 33, 1),
            entry("2001:db8::1", 64, 1),
            entry("2001:db8::", 129, 1),
        ] {
            assert!(matches!(
                Policy::new(&[invalid], 1),
                Err(Error::InvalidPrefix { index: 0 })
            ));
        }
        assert!(matches!(
            Policy::new(&[entry("192.0.2.0", 24, 1), entry("192.0.2.0", 24, 2)], 2),
            Err(Error::ConflictingAssignment)
        ));
        assert!(matches!(
            Policy::new(&[entry("192.0.2.0", 24, 1); 2], 2),
            Err(Error::DuplicateAssignment)
        ));
    }
}
