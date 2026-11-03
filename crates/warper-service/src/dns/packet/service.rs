// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! RFC 9460 packet semantics, without client selection or output permission.

use std::{fmt, net::IpAddr, time::Duration};

use hickory_proto::rr::{
    DNSClass, RData, Record,
    rdata::{
        SVCB,
        svcb::{SvcParamKey, SvcParamValue},
    },
};
use tokio::time::Instant;
use warper_core::dns::Name;

use super::{Address, Packet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    InvalidQuestion,
    InvalidLimits,
    Malformed,
    ResourceLimit,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidQuestion => "service discovery requires an IN HTTPS or SVCB response",
            Self::InvalidLimits => "invalid related-address limit",
            Self::Malformed => "ambiguous or inconsistent service-binding data",
            Self::ResourceLimit => "service-binding metadata admission exhausted",
        })
    }
}

impl std::error::Error for ServiceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimedAlias {
    pub target: Name,
    pub expires_at: Instant,
}

#[allow(
    clippy::large_enum_variant,
    reason = "Fixed-capacity DNS names keep alias analysis allocation-free."
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAlias {
    Target(TimedAlias),
    Unavailable { expires_at: Instant },
}

#[allow(
    clippy::large_enum_variant,
    reason = "Fixed-capacity DNS names keep CNAME-only analysis allocation-free."
)]
#[derive(Debug)]
pub enum BindingSet<'a> {
    Negative(u16),
    Empty,
    Cname(TimedAlias),
    AliasMode(Vec<ServiceAlias>),
    ServiceMode(Vec<ServiceBinding<'a>>),
}

/// Borrows opaque parameters from the admitted packet. No hint or unknown
/// parameter is copied into a second unbounded allocation.
pub struct ServiceBinding<'a> {
    record: &'a SVCB,
    owner: Name,
    target: Name,
    expires_at: Instant,
}

impl ServiceBinding<'_> {
    pub fn owner(&self) -> Name {
        self.owner
    }
    pub fn target(&self) -> Name {
        self.target
    }
    pub fn priority(&self) -> u16 {
        self.record.svc_priority
    }
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub fn hints(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.record.svc_params.iter().flat_map(|(_, value)| {
            let v4 = if let SvcParamValue::Ipv4Hint(hints) = value {
                Some(hints.0.as_slice())
            } else {
                None
            };
            let v6 = if let SvcParamValue::Ipv6Hint(hints) = value {
                Some(hints.0.as_slice())
            } else {
                None
            };
            v4.into_iter()
                .flatten()
                .map(|address| IpAddr::V4(address.0))
                .chain(
                    v6.into_iter()
                        .flatten()
                        .map(|address| IpAddr::V6(address.0)),
                )
        })
    }
}

impl fmt::Debug for ServiceBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceBinding([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSection {
    Answer,
    Additional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelatedAddress {
    pub address: Address,
    pub section: AddressSection,
}

#[allow(
    clippy::large_enum_variant,
    reason = "Fixed-capacity DNS names keep CNAME-only analysis allocation-free."
)]
#[derive(Debug)]
pub enum RelatedSet {
    Empty,
    Cname(TimedAlias),
    Addresses(Vec<RelatedAddress>),
}

impl Packet {
    pub fn service_bindings(
        &self,
        owner: Name,
        received_at: Instant,
    ) -> Result<BindingSet<'_>, ServiceError> {
        if !self.is_response()
            || self.question.class != 1
            || !matches!(self.question.record_type, 64 | 65)
        {
            return Err(ServiceError::InvalidQuestion);
        }
        if self.response_code() != 0 {
            return Ok(BindingSet::Negative(self.response_code()));
        }
        let mut cname = None;
        let mut has_address = false;
        let mut count = 0;
        let mut expires_at = None;
        let mut alias_mode = false;
        for record in &self.message.answers {
            if !owned(record, owner)? {
                continue;
            }
            match &record.data {
                RData::CNAME(alias) => merge_alias(
                    &mut cname,
                    canonical(&alias.0)?,
                    expiry(received_at, record.ttl)?,
                )?,
                RData::A(_) | RData::AAAA(_) => has_address = true,
                _ => {}
            }
            if let Some(binding) = binding(record, self.question.record_type) {
                count += 1;
                constrain(&mut expires_at, expiry(received_at, record.ttl)?);
                alias_mode |= binding.svc_priority == 0;
            }
        }
        // CNAME ownership is not section-specific. Additional data must
        // not contradict the Answer alias or a reachable service RRset.
        let mut additional_cname = None;
        for record in &self.message.additionals {
            if !owned(record, owner)? {
                continue;
            }
            match &record.data {
                RData::CNAME(alias) => merge_alias(
                    &mut additional_cname,
                    canonical(&alias.0)?,
                    expiry(received_at, record.ttl)?,
                )?,
                RData::A(_) | RData::AAAA(_) => has_address = true,
                _ => {}
            }
        }
        if count != 0 && additional_cname.is_some() {
            return Err(ServiceError::Malformed);
        }
        if let (Some(_), Some(additional)) = (cname, additional_cname) {
            merge_alias(&mut cname, additional.target, additional.expires_at)?;
        }
        if let Some(cname) = cname {
            return if count != 0 || has_address {
                Err(ServiceError::Malformed)
            } else {
                Ok(BindingSet::Cname(cname))
            };
        }
        let Some(expires_at) = expires_at else {
            return Ok(BindingSet::Empty);
        };
        if alias_mode {
            let mut aliases = Vec::new();
            aliases
                .try_reserve_exact(count)
                .map_err(|_| ServiceError::ResourceLimit)?;
            for record in &self.message.answers {
                if !owned(record, owner)? {
                    continue;
                }
                let Some(binding) = binding(record, self.question.record_type) else {
                    continue;
                };
                if binding.svc_priority != 0 {
                    continue;
                }
                let target = canonical(&binding.target_name)?;
                let alias = if target.is_root() {
                    ServiceAlias::Unavailable { expires_at }
                } else {
                    ServiceAlias::Target(TimedAlias { target, expires_at })
                };
                if !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
            return Ok(BindingSet::AliasMode(aliases));
        }
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(count)
            .map_err(|_| ServiceError::ResourceLimit)?;
        for record in &self.message.answers {
            if !owned(record, owner)? {
                continue;
            }
            let Some(binding) = binding(record, self.question.record_type) else {
                continue;
            };
            validate(binding)?;
            let target = canonical(&binding.target_name)?;
            bindings.push(ServiceBinding {
                record: binding,
                owner,
                target: if target.is_root() { owner } else { target },
                expires_at,
            });
        }
        Ok(BindingSet::ServiceMode(bindings))
    }

    pub fn related_addresses(
        &self,
        owner: Name,
        received_at: Instant,
        address_limit: usize,
    ) -> Result<RelatedSet, ServiceError> {
        if !self.is_response() {
            return Err(ServiceError::InvalidQuestion);
        }
        if address_limit == 0 {
            return Err(ServiceError::InvalidLimits);
        }
        if self.response_code() != 0 {
            return Ok(RelatedSet::Empty);
        }
        let mut cname = None;
        let mut addresses: Vec<RelatedAddress> = Vec::new();
        let mut v4_expiry = None;
        let mut v6_expiry = None;
        let mut unique = 0;
        for (section, records) in [
            (AddressSection::Answer, &self.message.answers),
            (AddressSection::Additional, &self.message.additionals),
        ] {
            for record in records {
                if !owned(record, owner)? {
                    continue;
                }
                let ip = match &record.data {
                    RData::CNAME(alias) => {
                        merge_alias(
                            &mut cname,
                            canonical(&alias.0)?,
                            expiry(received_at, record.ttl)?,
                        )?;
                        continue;
                    }
                    RData::A(address) => {
                        constrain(&mut v4_expiry, expiry(received_at, record.ttl)?);
                        IpAddr::V4(address.0)
                    }
                    RData::AAAA(address) => {
                        constrain(&mut v6_expiry, expiry(received_at, record.ttl)?);
                        IpAddr::V6(address.0)
                    }
                    _ => continue,
                };
                if !addresses.iter().any(|prior| prior.address.ip == ip) {
                    if unique == address_limit {
                        return Err(ServiceError::ResourceLimit);
                    }
                    unique += 1;
                }
                if addresses
                    .iter()
                    .any(|prior| prior.address.ip == ip && prior.section == section)
                {
                    continue;
                }
                addresses
                    .try_reserve_exact(1)
                    .map_err(|_| ServiceError::ResourceLimit)?;
                addresses.push(RelatedAddress {
                    address: Address {
                        ip,
                        expires_at: received_at,
                    },
                    section,
                });
            }
        }
        if let Some(cname) = cname {
            return if addresses.is_empty() {
                Ok(RelatedSet::Cname(cname))
            } else {
                Err(ServiceError::Malformed)
            };
        }
        if addresses.is_empty() {
            return Ok(RelatedSet::Empty);
        }
        for address in &mut addresses {
            let expires_at = if address.address.ip.is_ipv4() {
                v4_expiry
            } else {
                v6_expiry
            };
            // Every retained address contributed to exactly one family above.
            address.address.expires_at = expires_at.ok_or(ServiceError::Malformed)?;
        }
        Ok(RelatedSet::Addresses(addresses))
    }
}

fn binding(record: &Record, record_type: u16) -> Option<&SVCB> {
    match (&record.data, record_type) {
        (RData::SVCB(binding), 64) => Some(binding),
        (RData::HTTPS(binding), 65) => Some(&binding.0),
        _ => None,
    }
}

fn owned(record: &Record, owner: Name) -> Result<bool, ServiceError> {
    Ok(record.dns_class == DNSClass::IN && canonical(&record.name)? == owner)
}

fn canonical(name: &hickory_proto::rr::Name) -> Result<Name, ServiceError> {
    Name::from_labels(name.iter()).map_err(|_| ServiceError::Malformed)
}

fn expiry(received_at: Instant, ttl: u32) -> Result<Instant, ServiceError> {
    let ttl = if ttl & 0x8000_0000 == 0 { ttl } else { 0 };
    received_at
        .checked_add(Duration::from_secs(u64::from(ttl)))
        .ok_or(ServiceError::ResourceLimit)
}

fn constrain(expires_at: &mut Option<Instant>, value: Instant) {
    *expires_at = Some(expires_at.map_or(value, |prior| prior.min(value)));
}

fn merge_alias(
    alias: &mut Option<TimedAlias>,
    target: Name,
    expires_at: Instant,
) -> Result<(), ServiceError> {
    if let Some(prior) = alias {
        if prior.target != target {
            return Err(ServiceError::Malformed);
        }
        prior.expires_at = prior.expires_at.min(expires_at);
    } else {
        *alias = Some(TimedAlias { target, expires_at });
    }
    Ok(())
}

fn validate(binding: &SVCB) -> Result<(), ServiceError> {
    let mut alpn = false;
    let mut no_default_alpn = false;
    for (key, value) in &binding.svc_params {
        match value {
            SvcParamValue::Mandatory(mandatory) => {
                let mut last = 0;
                for required in &mandatory.0 {
                    let number = u16::from(*required);
                    if number <= last
                        || !binding
                            .svc_params
                            .iter()
                            .any(|(present, _)| present == required)
                    {
                        return Err(ServiceError::Malformed);
                    }
                    last = number;
                }
            }
            SvcParamValue::Alpn(_) => alpn = true,
            SvcParamValue::NoDefaultAlpn => no_default_alpn = true,
            SvcParamValue::Ipv4Hint(hints) if hints.0.is_empty() => {
                return Err(ServiceError::Malformed);
            }
            SvcParamValue::Ipv6Hint(hints) if hints.0.is_empty() => {
                return Err(ServiceError::Malformed);
            }
            _ => {}
        }
        if *key == SvcParamKey::Key65535 {
            return Err(ServiceError::Malformed);
        }
    }
    if no_default_alpn && !alpn {
        return Err(ServiceError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
