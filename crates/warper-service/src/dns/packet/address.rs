// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Address dependencies without exposing the DNS library or granting output.

use std::{fmt, net::IpAddr, time::Duration};

use hickory_proto::rr::{DNSClass, RData};
use tokio::time::Instant;
use warper_core::dns::Name;

use super::{Packet, Question};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    InvalidQuestion,
    InvalidLimits,
    MismatchedResponse,
    Malformed,
    AliasLoop,
    ResourceLimit,
}

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidQuestion => "address discovery requires an IN A or AAAA question",
            Self::InvalidLimits => "invalid DNS address discovery limits",
            Self::MismatchedResponse => "address dependency response does not match",
            Self::Malformed => "ambiguous DNS address dependency",
            Self::AliasLoop => "DNS address alias loop",
            Self::ResourceLimit => "DNS address discovery admission exhausted",
        })
    }
}

impl std::error::Error for AddressError {}

/// Freshness only. Routing grace and active-flow ownership are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub ip: IpAddr,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct AddressAnswer {
    pub question: Question,
    pub canonical_name: Name,
    pub aliases: Vec<Name>,
    pub addresses: Vec<Address>,
    pub response_code: u16,
}

#[derive(Debug)]
pub enum AddressProgress {
    Followup(AddressLookup),
    Complete(AddressAnswer),
}

/// A single dependency path, moved between responses so an error cannot leave
/// a partially validated path available for publication.
#[derive(Debug)]
pub struct AddressLookup {
    original: Question,
    current: Question,
    aliases: Vec<Name>,
    expires_at: Option<Instant>,
    max_alias_hops: usize,
    max_addresses: usize,
}

impl AddressLookup {
    pub fn new(
        question: Question,
        max_alias_hops: usize,
        max_addresses: usize,
    ) -> Result<Self, AddressError> {
        if question.class != 1 || !matches!(question.record_type, 1 | 28) {
            return Err(AddressError::InvalidQuestion);
        }
        if max_addresses == 0 {
            return Err(AddressError::InvalidLimits);
        }
        Ok(Self {
            original: question,
            current: question,
            aliases: Vec::new(),
            expires_at: None,
            max_alias_hops,
            max_addresses,
        })
    }

    pub fn question(&self) -> Question {
        self.current
    }

    /// `received_at` is the observation timestamp of this packet, not the
    /// eventual output time. Earlier dependencies keep their original expiry.
    pub fn advance(
        mut self,
        response: &Packet,
        received_at: Instant,
    ) -> Result<AddressProgress, AddressError> {
        if !response.is_response() || response.question() != self.current {
            return Err(AddressError::MismatchedResponse);
        }
        // Error responses other than NXDOMAIN contain no authoritative answer
        // to traverse. Preserve their code without learning any routing data.
        if !matches!(response.response_code(), 0 | 3) {
            return Ok(self.finish(Vec::new(), response.response_code()));
        }
        let initial_name = self.current.name;
        loop {
            let mut target = None;
            let mut alias_expiry = None;
            let mut address_expiry = None;
            let mut addresses = Vec::new();
            let mut has_address = false;
            for record in &response.message.answers {
                if record.dns_class != DNSClass::IN
                    || Name::from_labels(record.name.iter()).map_err(|_| AddressError::Malformed)?
                        != self.current.name
                {
                    continue;
                }
                match &record.data {
                    RData::CNAME(alias) => {
                        let name = Name::from_labels(alias.0.iter())
                            .map_err(|_| AddressError::Malformed)?;
                        if target.is_some_and(|prior| prior != name) {
                            return Err(AddressError::Malformed);
                        }
                        target = Some(name);
                        constrain(&mut alias_expiry, expiry(received_at, record.ttl)?);
                    }
                    RData::A(_) | RData::AAAA(_) => {
                        has_address = true;
                        let ip = match &record.data {
                            RData::A(address) if self.current.record_type == 1 => {
                                IpAddr::V4(address.0)
                            }
                            RData::AAAA(address) if self.current.record_type == 28 => {
                                IpAddr::V6(address.0)
                            }
                            _ => continue,
                        };
                        constrain(&mut address_expiry, expiry(received_at, record.ttl)?);
                        if !addresses.iter().any(|address: &Address| address.ip == ip) {
                            if addresses.len() == self.max_addresses {
                                return Err(AddressError::ResourceLimit);
                            }
                            addresses
                                .try_reserve_exact(1)
                                .map_err(|_| AddressError::ResourceLimit)?;
                            addresses.push(Address {
                                ip,
                                expires_at: received_at,
                            });
                        }
                    }
                    _ => {}
                }
            }
            if let Some(target) = target {
                if has_address {
                    return Err(AddressError::Malformed);
                }
                if target == self.original.name || self.aliases.contains(&target) {
                    return Err(AddressError::AliasLoop);
                }
                if self.aliases.len() == self.max_alias_hops {
                    return Err(AddressError::ResourceLimit);
                }
                self.aliases
                    .try_reserve_exact(1)
                    .map_err(|_| AddressError::ResourceLimit)?;
                self.aliases.push(target);
                self.current.name = target;
                if let Some(expires_at) = alias_expiry {
                    constrain(&mut self.expires_at, expires_at);
                }
                continue;
            }
            if let Some(expires_at) = address_expiry {
                if response.response_code() != 0 {
                    return Err(AddressError::Malformed);
                }
                let expires_at = self
                    .expires_at
                    .map_or(expires_at, |prior| prior.min(expires_at));
                for address in &mut addresses {
                    address.expires_at = expires_at;
                }
                return Ok(self.finish(addresses, response.response_code()));
            }
            return if initial_name != self.current.name && response.response_code() == 0 {
                Ok(AddressProgress::Followup(self))
            } else {
                Ok(self.finish(Vec::new(), response.response_code()))
            };
        }
    }

    fn finish(self, addresses: Vec<Address>, response_code: u16) -> AddressProgress {
        AddressProgress::Complete(AddressAnswer {
            question: self.original,
            canonical_name: self.current.name,
            aliases: self.aliases,
            addresses,
            response_code,
        })
    }
}

fn expiry(received_at: Instant, ttl: u32) -> Result<Instant, AddressError> {
    let ttl = if ttl & 0x8000_0000 == 0 { ttl } else { 0 };
    received_at
        .checked_add(Duration::from_secs(u64::from(ttl)))
        .ok_or(AddressError::ResourceLimit)
}

fn constrain(expiry: &mut Option<Instant>, value: Instant) {
    *expiry = Some(expiry.map_or(value, |prior| prior.min(value)));
}

#[cfg(test)]
mod tests;
