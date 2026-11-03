// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded canonical DNS names and immutable domain selection.
//!
//! Configuration performs IDNA conversion. Wire names retain arbitrary label
//! octets, including underscores and literal dots; only ASCII case is folded.

use std::{fmt, net::IpAddr};

use crate::BackendId;

const MAX_NAME_BYTES: usize = 255;

/// Uncompressed DNS name including label lengths and the terminating root.
/// Debug output deliberately excludes query names.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Name {
    bytes: [u8; MAX_NAME_BYTES],
    length: u8,
}

impl Name {
    /// Build from decoded wire labels, excluding the terminating root label.
    /// Label and total lengths are checked before copying. No allocation occurs.
    pub fn from_labels<'a>(labels: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, Error> {
        let mut name = Self {
            bytes: [0; MAX_NAME_BYTES],
            length: 1,
        };
        let mut end = 0;
        for label in labels {
            if label.is_empty() || label.len() > 63 || end + label.len() + 2 > MAX_NAME_BYTES {
                return Err(Error::InvalidName);
            }
            name.bytes[end] = label.len() as u8;
            end += 1;
            for &byte in label {
                name.bytes[end] = byte.to_ascii_lowercase();
                end += 1;
            }
        }
        name.length = (end + 1) as u8;
        Ok(name)
    }

    /// Parse unescaped ASCII presentation syntax. Accept one terminal root dot;
    /// use `from_labels` for binary labels or embedded literal dots.
    /// Unicode hostnames must first undergo configuration's IDNA conversion.
    pub fn from_ascii(value: &str) -> Result<Self, Error> {
        if value == "." {
            return Self::from_labels(std::iter::empty());
        }
        if value.is_empty() || !value.is_ascii() || value.len() > 254 {
            return Err(Error::InvalidName);
        }
        let value = value.strip_suffix('.').unwrap_or(value);
        Self::from_labels(value.as_bytes().split(|&byte| byte == b'.'))
    }

    pub fn wire(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    pub fn is_root(&self) -> bool {
        self.length == 1
    }

    /// Compare whole labels. A dot inside a wire label is never a separator.
    pub fn is_within(&self, domain: &Self) -> bool {
        let mut offset = 0;
        loop {
            if &self.wire()[offset..] == domain.wire() {
                return true;
            }
            let length = usize::from(self.bytes[offset]);
            if length == 0 {
                return false;
            }
            offset += length + 1;
        }
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Name([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidName,
    InvalidDomain,
    InvalidLimit,
    ResourceLimit,
    DuplicateAssignment,
    ConflictingAssignment,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "invalid DNS name",
            Self::InvalidDomain => "domain rule must be a canonical configuration domain",
            Self::InvalidLimit => "domain rule limit must be positive",
            Self::ResourceLimit => "domain rule limit exceeded",
            Self::DuplicateAssignment => "duplicate domain assignment",
            Self::ConflictingAssignment => "the same domain selects different backends",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule {
    domain: Name,
    backend: BackendId,
}

impl Rule {
    /// Accept only the normalized ASCII output of configuration validation.
    /// Core does not perform a second, potentially different IDNA conversion.
    pub fn new(domain: &str, backend: BackendId) -> Result<Self, Error> {
        if domain.is_empty()
            || domain.ends_with('.')
            || domain.parse::<IpAddr>().is_ok()
            || domain.split('.').any(|label| {
                label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(Error::InvalidDomain);
        }
        let domain = Name::from_ascii(domain).map_err(|_| Error::InvalidDomain)?;
        Ok(Self { domain, backend })
    }
}

/// A complete immutable snapshot. Failed selected-backend operations never
/// cause selection of another rule or direct resolution.
#[derive(Debug)]
pub struct Policy {
    rules: Box<[Rule]>,
}

impl Policy {
    /// Bound storage before allocation. Names have fixed capacity and selection
    /// allocates nothing; there are no learned rules or growing search indexes.
    pub fn new(rules: &[Rule], limit: usize) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Error::InvalidLimit);
        }
        if rules.len() > limit {
            return Err(Error::ResourceLimit);
        }
        let mut rules = rules.to_vec();
        rules.sort_unstable_by(|first, second| {
            second
                .domain
                .length
                .cmp(&first.domain.length)
                .then_with(|| first.domain.wire().cmp(second.domain.wire()))
        });
        for pair in rules.windows(2) {
            if pair[0].domain == pair[1].domain {
                return Err(if pair[0].backend == pair[1].backend {
                    Error::DuplicateAssignment
                } else {
                    Error::ConflictingAssignment
                });
            }
        }
        Ok(Self {
            rules: rules.into_boxed_slice(),
        })
    }

    /// The longest configured suffix wins independently of input order.
    pub fn select(&self, name: &Name) -> Option<BackendId> {
        self.rules
            .iter()
            .find(|rule| name.is_within(&rule.domain))
            .map(|rule| rule.backend)
    }
}

#[cfg(test)]
mod tests;
