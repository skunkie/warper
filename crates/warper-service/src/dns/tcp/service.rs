// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Whole-response service endpoint discovery through one selected backend.

use std::{fmt, net::IpAddr, sync::Arc};

use tokio::time::Instant;
use warper_core::{
    BackendId,
    dns::{Name, Policy},
    transport::Request,
};

use super::{Dial, ExchangeError, Packet, QueryBudget, TcpTransport, exchange_packet};
use crate::dns::{AddressSection, BindingSet, Question, RelatedSet, ServiceAlias, ServiceError};

const MAX_WORK_ITEMS: usize = 65536;

#[derive(Clone, Copy, Debug)]
pub struct ServiceDiscoveryLimits {
    pub alias_hops: usize,
    pub addresses: usize,
    pub ipv6: bool,
    pub work_items: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceDiscoveryError {
    InvalidLimits,
    DomainPolicy,
    DisabledFamily,
    AliasLoop,
    ResourceLimit,
    NegativeDependency(u16),
    Exchange(ExchangeError),
    Packet(ServiceError),
}

impl fmt::Display for ServiceDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "invalid service discovery limits",
            Self::DomainPolicy => {
                "service dependency requires a configured domain on the selected backend"
            }
            Self::DisabledFamily => "service response exposes a disabled address family",
            Self::AliasLoop => "service dependency alias loop",
            Self::ResourceLimit => "service discovery work or endpoint admission exhausted",
            Self::NegativeDependency(_) => "service endpoint dependency did not resolve",
            Self::Exchange(_) => "selected service dependency exchange failed",
            Self::Packet(_) => "service dependency data validation failed",
        })
    }
}

impl std::error::Error for ServiceDiscoveryError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyKind {
    Question,
    Cname,
    ServiceAlias,
    ServiceTarget { priority: u16 },
    AliasFallback,
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPath {
    pub parent: Option<usize>,
    pub question: Question,
    pub kind: DependencyKind,
    pub expires_at: Option<Instant>,
    pub alias_hops: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointSource {
    Hint,
    RelatedAnswer,
    Additional,
    Resolved,
}

#[derive(Clone, Copy)]
pub struct ServiceEndpoint {
    pub ip: IpAddr,
    pub expires_at: Instant,
    pub path: usize,
    pub source: EndpointSource,
}

impl fmt::Debug for ServiceEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceEndpoint([redacted])")
    }
}

#[derive(Debug)]
pub struct ServiceResolution {
    pub backend: BackendId,
    pub response: Arc<Packet>,
    pub paths: Vec<EndpointPath>,
    pub endpoints: Vec<ServiceEndpoint>,
}

#[derive(Clone)]
struct Observed {
    packet: Arc<Packet>,
    received_at: Instant,
}

struct Step {
    path: usize,
    observed: Observed,
    alias_seen: bool,
    requires_address: bool,
    requires_name: bool,
}

struct Discovery<'a> {
    policy: &'a Policy,
    backend: BackendId,
    limits: ServiceDiscoveryLimits,
    remaining: usize,
    paths: Vec<EndpointPath>,
    endpoints: Vec<ServiceEndpoint>,
    pending: Vec<Step>,
    responses: Vec<Observed>,
    unique_addresses: usize,
}

impl TcpTransport {
    pub async fn discover_service_bindings(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
        policy: &Policy,
        limits: ServiceDiscoveryLimits,
    ) -> Result<ServiceResolution, ServiceDiscoveryError> {
        request
            .clone()
            .run(async {
                Ok(self
                    .discover_services_owned(query, request, budget, policy, limits)
                    .await)
            })
            .await
            .map_err(|error| ServiceDiscoveryError::Exchange(ExchangeError::Backend(error)))?
    }

    async fn discover_services_owned(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
        policy: &Policy,
        limits: ServiceDiscoveryLimits,
    ) -> Result<ServiceResolution, ServiceDiscoveryError> {
        if query.is_response()
            || query.question().class != 1
            || !matches!(query.question().record_type, 64 | 65)
        {
            return Err(ServiceDiscoveryError::Packet(ServiceError::InvalidQuestion));
        }
        let mut discovery = Discovery::new(policy, self.backend(), limits)?;
        discovery.check_name(query.question().name)?;
        let permit = self
            .admission
            .reserve()
            .map_err(ServiceDiscoveryError::Exchange)?;
        let first = Arc::new(
            exchange_packet(
                Dial::Backend(self.backend.as_ref()),
                self.upstream,
                self.limits,
                query,
                request.clone(),
                budget,
                &permit,
            )
            .await
            .map_err(ServiceDiscoveryError::Exchange)?,
        );
        let observed = Observed {
            packet: first.clone(),
            received_at: Instant::now(),
        };
        discovery.save(observed.clone())?;
        let root = discovery.path(None, query.question(), DependencyKind::Question, None)?;
        discovery.queue(Step {
            path: root,
            observed,
            alias_seen: false,
            requires_address: false,
            requires_name: false,
        })?;
        while let Some(mut step) = discovery.pending.pop() {
            tokio::task::yield_now().await;
            loop {
                let question = discovery.paths[step.path].question;
                let need_query = if matches!(question.record_type, 64 | 65) {
                    discovery.service_step(&step)?
                } else {
                    discovery.address_step(&step)?
                };
                if !need_query {
                    break;
                }
                if let Some(prior) = discovery
                    .responses
                    .iter()
                    .find(|prior| prior.packet.question() == question)
                {
                    step.observed = prior.clone();
                } else {
                    let dependency = query.dependency(question).map_err(|error| {
                        ServiceDiscoveryError::Exchange(ExchangeError::Packet(error))
                    })?;
                    let packet = exchange_packet(
                        Dial::Backend(self.backend.as_ref()),
                        self.upstream,
                        self.limits,
                        &dependency,
                        request.clone(),
                        budget,
                        &permit,
                    )
                    .await
                    .map_err(ServiceDiscoveryError::Exchange)?;
                    step.observed = Observed {
                        packet: Arc::new(packet),
                        received_at: Instant::now(),
                    };
                    discovery.save(step.observed.clone())?;
                }
            }
        }
        Ok(ServiceResolution {
            backend: self.backend(),
            response: first,
            paths: discovery.paths,
            endpoints: discovery.endpoints,
        })
    }
}

impl<'a> Discovery<'a> {
    fn new(
        policy: &'a Policy,
        backend: BackendId,
        limits: ServiceDiscoveryLimits,
    ) -> Result<Self, ServiceDiscoveryError> {
        if limits.addresses == 0 || !(1..=MAX_WORK_ITEMS).contains(&limits.work_items) {
            return Err(ServiceDiscoveryError::InvalidLimits);
        }
        Ok(Self {
            policy,
            backend,
            limits,
            remaining: limits.work_items,
            paths: Vec::new(),
            endpoints: Vec::new(),
            pending: Vec::new(),
            responses: Vec::new(),
            unique_addresses: 0,
        })
    }

    fn service_step(&mut self, step: &Step) -> Result<bool, ServiceDiscoveryError> {
        let path = self.paths[step.path];
        match step
            .observed
            .packet
            .service_bindings(path.question.name, step.observed.received_at)
            .map_err(ServiceDiscoveryError::Packet)?
        {
            BindingSet::Empty if step.observed.packet.question() != path.question => {
                return Ok(true);
            }
            BindingSet::Negative(code) if step.path != 0 && code != 3 => {
                return Err(ServiceDiscoveryError::NegativeDependency(code));
            }
            BindingSet::Empty | BindingSet::Negative(_) => {
                if step.alias_seen {
                    self.addresses(
                        step,
                        path.question.name,
                        DependencyKind::AliasFallback,
                        None,
                        &[],
                    )?;
                }
            }
            BindingSet::Cname(alias) => {
                let question = Question {
                    name: alias.target,
                    ..path.question
                };
                let next = self.path(
                    Some(step.path),
                    question,
                    DependencyKind::Cname,
                    Some(alias.expires_at),
                )?;
                self.queue(Step {
                    path: next,
                    observed: step.observed.clone(),
                    alias_seen: step.alias_seen,
                    requires_address: false,
                    requires_name: false,
                })?;
            }
            BindingSet::AliasMode(aliases) => {
                for alias in aliases {
                    match alias {
                        ServiceAlias::Target(alias) => {
                            let question = Question {
                                name: alias.target,
                                ..path.question
                            };
                            let next = self.path(
                                Some(step.path),
                                question,
                                DependencyKind::ServiceAlias,
                                Some(alias.expires_at),
                            )?;
                            self.queue(Step {
                                path: next,
                                observed: step.observed.clone(),
                                alias_seen: true,
                                requires_address: false,
                                requires_name: false,
                            })?;
                        }
                        ServiceAlias::Unavailable { .. } => {
                            if step.alias_seen {
                                self.addresses(
                                    step,
                                    path.question.name,
                                    DependencyKind::AliasFallback,
                                    None,
                                    &[],
                                )?;
                            }
                        }
                    }
                }
            }
            BindingSet::ServiceMode(bindings) => {
                for binding in bindings {
                    self.check_name(binding.target())?;
                    // Hints borrow packet storage; collect only while charging
                    // per-contribution metadata in addresses/add_endpoint.
                    self.addresses_iter(
                        step,
                        binding.target(),
                        DependencyKind::ServiceTarget {
                            priority: binding.priority(),
                        },
                        Some(binding.expires_at()),
                        binding.hints(),
                    )?;
                }
                if step.alias_seen {
                    self.addresses(
                        step,
                        path.question.name,
                        DependencyKind::AliasFallback,
                        None,
                        &[],
                    )?;
                }
            }
        }
        Ok(false)
    }

    fn address_step(&mut self, step: &Step) -> Result<bool, ServiceDiscoveryError> {
        let path = self.paths[step.path];
        let packet = &step.observed.packet;
        let mut alias: Option<crate::dns::TimedAlias> = None;
        let mut found = false;
        let mut any_address = false;
        let mut nxdomain = false;
        // Preserve client-visible original data and relevant address responses
        // from this request. An A lookup's Additional AAAA can satisfy its
        // sibling family without hiding the earlier contribution or TTL.
        for index in 0..=self.responses.len() {
            let observed = if index == 0 {
                step.observed.clone()
            } else {
                let saved = &self.responses[index - 1];
                if Arc::ptr_eq(&saved.packet, packet) {
                    continue;
                }
                let question = saved.packet.question();
                if index != 1
                    && !(matches!(question.record_type, 1 | 28)
                        && self.address_ancestor(step.path, question.name))
                {
                    continue;
                }
                saved.clone()
            };
            if observed.packet.question().name == path.question.name
                && observed.packet.response_code() == 3
            {
                nxdomain = true;
            }
            match observed
                .packet
                .related_addresses(
                    path.question.name,
                    observed.received_at,
                    self.limits.addresses,
                )
                .map_err(ServiceDiscoveryError::Packet)?
            {
                RelatedSet::Cname(next) => {
                    if let Some(prior) = &mut alias {
                        if prior.target != next.target {
                            return Err(ServiceDiscoveryError::Packet(ServiceError::Malformed));
                        }
                        prior.expires_at = prior.expires_at.min(next.expires_at);
                    } else {
                        alias = Some(next);
                    }
                }
                RelatedSet::Empty => {}
                RelatedSet::Addresses(addresses) => {
                    any_address = true;
                    for related in addresses {
                        if related.address.ip.is_ipv6() && !self.limits.ipv6 {
                            return Err(ServiceDiscoveryError::DisabledFamily);
                        }
                        if related.address.ip.is_ipv4() != (path.question.record_type == 1) {
                            continue;
                        }
                        let source = match related.section {
                            AddressSection::Additional => EndpointSource::Additional,
                            AddressSection::Answer
                                if matches!(observed.packet.question().record_type, 1 | 28) =>
                            {
                                EndpointSource::Resolved
                            }
                            AddressSection::Answer => EndpointSource::RelatedAnswer,
                        };
                        self.add_endpoint(
                            related.address.ip,
                            related.address.expires_at,
                            step.path,
                            source,
                        )?;
                        found = true;
                    }
                }
            }
        }
        if nxdomain {
            if any_address || alias.is_some() || step.requires_name {
                return Err(ServiceDiscoveryError::NegativeDependency(3));
            }
            return Ok(false);
        }
        if let Some(alias) = alias {
            if any_address {
                return Err(ServiceDiscoveryError::Packet(ServiceError::Malformed));
            }
            let question = Question {
                name: alias.target,
                ..path.question
            };
            let next = self.path(
                Some(step.path),
                question,
                DependencyKind::Cname,
                Some(alias.expires_at),
            )?;
            self.queue(Step {
                path: next,
                observed: step.observed.clone(),
                alias_seen: step.alias_seen,
                requires_address: step.requires_address,
                requires_name: step.requires_name,
            })?;
            return Ok(false);
        }
        if packet.question() == path.question {
            let code = packet.response_code();
            if code != 0 && (code != 3 || step.requires_address || found) {
                return Err(ServiceDiscoveryError::NegativeDependency(code));
            }
            if !found && step.requires_address {
                return Err(ServiceDiscoveryError::NegativeDependency(code));
            }
            return Ok(false);
        }
        Ok(!found)
    }

    fn addresses(
        &mut self,
        step: &Step,
        target: Name,
        kind: DependencyKind,
        expiry: Option<Instant>,
        hints: &[IpAddr],
    ) -> Result<(), ServiceDiscoveryError> {
        self.addresses_iter(step, target, kind, expiry, hints.iter().copied())
    }

    fn addresses_iter(
        &mut self,
        step: &Step,
        target: Name,
        kind: DependencyKind,
        expiry: Option<Instant>,
        hints: impl Iterator<Item = IpAddr>,
    ) -> Result<(), ServiceDiscoveryError> {
        let mut v4 = Step {
            path: self.path(
                Some(step.path),
                Question {
                    name: target,
                    record_type: 1,
                    class: 1,
                },
                kind,
                expiry,
            )?,
            observed: step.observed.clone(),
            alias_seen: step.alias_seen,
            requires_address: false,
            requires_name: false,
        };
        let mut v6 = if self.limits.ipv6 {
            Some(Step {
                path: self.path(
                    Some(step.path),
                    Question {
                        name: target,
                        record_type: 28,
                        class: 1,
                    },
                    kind,
                    expiry,
                )?,
                observed: step.observed.clone(),
                alias_seen: step.alias_seen,
                requires_address: false,
                requires_name: false,
            })
        } else {
            None
        };
        for ip in hints {
            let hint = if ip.is_ipv4() {
                &mut v4
            } else {
                v6.as_mut().ok_or(ServiceDiscoveryError::DisabledFamily)?
            };
            hint.requires_address = true;
            self.add_endpoint(
                ip,
                expiry.ok_or(ServiceDiscoveryError::Packet(ServiceError::Malformed))?,
                hint.path,
                EndpointSource::Hint,
            )?;
        }
        let requires_name =
            v4.requires_address || v6.as_ref().is_some_and(|step| step.requires_address);
        v4.requires_name = requires_name;
        if let Some(v6) = &mut v6 {
            v6.requires_name = requires_name;
        }
        self.queue(v4)?;
        if let Some(v6) = v6 {
            self.queue(v6)?;
        }
        Ok(())
    }

    fn path(
        &mut self,
        parent: Option<usize>,
        question: Question,
        kind: DependencyKind,
        expires_at: Option<Instant>,
    ) -> Result<usize, ServiceDiscoveryError> {
        self.check_name(question.name)?;
        let alias = matches!(kind, DependencyKind::Cname | DependencyKind::ServiceAlias);
        let mut hops = 0;
        let mut expiry = expires_at;
        if let Some(parent) = parent {
            let prior = self.paths[parent];
            hops = prior.alias_hops;
            if let Some(prior_expiry) = prior.expires_at {
                expiry = Some(expiry.map_or(prior_expiry, |value| value.min(prior_expiry)));
            }
            if alias {
                hops = hops
                    .checked_add(1)
                    .ok_or(ServiceDiscoveryError::ResourceLimit)?;
                if hops > self.limits.alias_hops {
                    return Err(ServiceDiscoveryError::ResourceLimit);
                }
                let mut cursor = Some(parent);
                while let Some(index) = cursor {
                    if self.paths[index].question == question {
                        return Err(ServiceDiscoveryError::AliasLoop);
                    }
                    cursor = self.paths[index].parent;
                }
            }
        }
        self.charge()?;
        self.paths
            .try_reserve_exact(1)
            .map_err(|_| ServiceDiscoveryError::ResourceLimit)?;
        let index = self.paths.len();
        self.paths.push(EndpointPath {
            parent,
            question,
            kind,
            expires_at: expiry,
            alias_hops: hops,
        });
        Ok(index)
    }

    fn add_endpoint(
        &mut self,
        ip: IpAddr,
        expires_at: Instant,
        path: usize,
        source: EndpointSource,
    ) -> Result<(), ServiceDiscoveryError> {
        if ip.is_ipv6() && !self.limits.ipv6 {
            return Err(ServiceDiscoveryError::DisabledFamily);
        }
        if !self.endpoints.iter().any(|endpoint| endpoint.ip == ip) {
            if self.unique_addresses == self.limits.addresses {
                return Err(ServiceDiscoveryError::ResourceLimit);
            }
            self.unique_addresses += 1;
        }
        let expires_at = self.paths[path]
            .expires_at
            .map_or(expires_at, |prior| prior.min(expires_at));
        if let Some(prior) = self
            .endpoints
            .iter_mut()
            .find(|prior| prior.ip == ip && prior.path == path && prior.source == source)
        {
            prior.expires_at = prior.expires_at.min(expires_at);
            return Ok(());
        }
        self.charge()?;
        self.endpoints
            .try_reserve_exact(1)
            .map_err(|_| ServiceDiscoveryError::ResourceLimit)?;
        self.endpoints.push(ServiceEndpoint {
            ip,
            expires_at,
            path,
            source,
        });
        Ok(())
    }

    fn queue(&mut self, step: Step) -> Result<(), ServiceDiscoveryError> {
        self.charge()?;
        self.pending
            .try_reserve_exact(1)
            .map_err(|_| ServiceDiscoveryError::ResourceLimit)?;
        self.pending.push(step);
        Ok(())
    }

    fn save(&mut self, response: Observed) -> Result<(), ServiceDiscoveryError> {
        self.charge()?;
        self.responses
            .try_reserve_exact(1)
            .map_err(|_| ServiceDiscoveryError::ResourceLimit)?;
        self.responses.push(response);
        Ok(())
    }

    fn address_ancestor(&self, path: usize, name: Name) -> bool {
        let mut cursor = Some(path);
        while let Some(index) = cursor {
            let path = self.paths[index];
            if matches!(path.question.record_type, 1 | 28) && path.question.name == name {
                return true;
            }
            cursor = path.parent;
        }
        false
    }

    fn check_name(&self, name: Name) -> Result<(), ServiceDiscoveryError> {
        if name.is_root() || self.policy.select(&name) != Some(self.backend) {
            return Err(ServiceDiscoveryError::DomainPolicy);
        }
        Ok(())
    }

    fn charge(&mut self) -> Result<(), ServiceDiscoveryError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(ServiceDiscoveryError::ResourceLimit)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
