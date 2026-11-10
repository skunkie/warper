// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Selected discovery and whole-response reservation, without publication.

use std::{fmt, net::IpAddr, sync::Arc};
use tokio::time::Instant;
use warper_config::schema::RoutingMode;
use warper_core::{
    dns::{
        Policy,
        lease::{Contribution, QuestionKey, Response},
    },
    transport::{Error as RequestError, Request},
};

use super::{
    AddressDiscoveryLimits, DiscoveryError, LocalReply, Packet, QueryBudget, ServiceDiscoveryError,
    ServiceDiscoveryLimits, TcpTransport,
    routes::{self, Controller},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    UnsupportedQuestion,
    DomainPolicy,
    DisabledFamily,
    UnsupportedFamily,
    ResourceLimit,
    SharedResponse,
    Request(RequestError),
    Packet(super::Error),
    Address(DiscoveryError),
    Service(ServiceDiscoveryError),
    Routes(routes::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "InvalidConfig: DNS preparation limits are invalid",
            Self::UnsupportedQuestion => {
                "UnsupportedCapability: DNS question requires another handler"
            }
            Self::DomainPolicy => "PolicyDenied: DNS question does not select this backend",
            Self::DisabledFamily => "UnsupportedCapability: DNS response exposes a disabled family",
            Self::UnsupportedFamily => {
                "UnsupportedCapability: selected backend cannot carry DNS endpoints"
            }
            Self::ResourceLimit => "ResourceLimit: DNS preparation admission exhausted",
            Self::SharedResponse => "Conflict: DNS discovery response remains shared",
            Self::Request(RequestError::Cancelled) => "Cancelled: DNS preparation request ended",
            Self::Request(RequestError::Timeout) => "Timeout: DNS preparation request ended",
            Self::Request(_) => "DNS preparation request failed",
            Self::Packet(_) => "DnsProtocol: DNS local reply preparation failed",
            Self::Address(_) => "DnsProtocol: selected address discovery failed",
            Self::Service(_) => "DnsProtocol: selected service discovery failed",
            Self::Routes(_) => "Routing: DNS response reservation failed",
        })
    }
}
impl std::error::Error for Error {}

/// A reservation is not committed and cannot authorize positive output.
pub enum Prepared {
    Local(Vec<u8>),
    Upstream {
        packet: Box<Packet>,
        received_at: Instant,
        udp_payload_limit: usize,
        reservation: Option<Response>,
    },
}

pub struct Resolver<'a> {
    transport: &'a TcpTransport,
    domains: &'a Policy,
    routes: &'a Controller,
    mode: RoutingMode,
    limits: ServiceDiscoveryLimits,
}
impl<'a> Resolver<'a> {
    pub fn new(
        transport: &'a TcpTransport,
        domains: &'a Policy,
        routes: &'a Controller,
        mode: RoutingMode,
        limits: ServiceDiscoveryLimits,
    ) -> Result<Self, Error> {
        Self::validate_limits(limits)?;
        Ok(Self {
            transport,
            domains,
            routes,
            mode,
            limits,
        })
    }

    pub(super) fn validate_limits(limits: ServiceDiscoveryLimits) -> Result<(), Error> {
        if limits.addresses == 0
            || limits.addresses > 65536
            || limits.alias_hops > 65536
            || limits.work_items == 0
            || limits.work_items > 65536
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }

    pub async fn prepare(
        &self,
        query: &Packet,
        operation: Request,
        budget: &QueryBudget,
    ) -> Result<Prepared, Error> {
        operation
            .clone()
            .run(async { Ok(self.prepare_owned(query, operation, budget).await) })
            .await
            .map_err(Error::Request)?
    }

    async fn prepare_owned(
        &self,
        query: &Packet,
        operation: Request,
        budget: &QueryBudget,
    ) -> Result<Prepared, Error> {
        let question = query.question();
        if query.is_response()
            || question.class != 1
            || !matches!(question.record_type, 1 | 28 | 64 | 65)
        {
            return Err(Error::UnsupportedQuestion);
        }
        if self.domains.select(&question.name) != Some(self.transport.backend()) {
            return Err(Error::DomainPolicy);
        }
        query.check_synthesis().map_err(Error::Packet)?;
        if self.routes.is_closed().map_err(Error::Routes)? {
            return Err(Error::Routes(routes::Error::Ledger(
                warper_core::dns::lease::Error::Closed,
            )));
        }
        if query.edns_version().is_some_and(|version| version != 0) {
            return query
                .local_reply(LocalReply::ServFail)
                .map(Prepared::Local)
                .map_err(Error::Packet);
        }
        if question.record_type == 28 && !self.limits.ipv6 {
            return query
                .local_reply(LocalReply::DisabledIpv6)
                .map(Prepared::Local)
                .map_err(Error::Packet);
        }
        let mut contributions = Vec::new();
        let (packet, received_at) = if matches!(question.record_type, 1 | 28) {
            let resolution = self
                .transport
                .discover_addresses(
                    query,
                    operation.clone(),
                    budget,
                    AddressDiscoveryLimits {
                        alias_hops: self.limits.alias_hops,
                        addresses: self.limits.addresses,
                    },
                )
                .await
                .map_err(Error::Address)?;
            contributions
                .try_reserve_exact(resolution.answer.addresses.len())
                .map_err(|_| Error::ResourceLimit)?;
            for address in resolution.answer.addresses {
                self.add(&mut contributions, address.ip, address.expires_at)?;
            }
            (resolution.response, resolution.response_received_at)
        } else {
            let resolution = self
                .transport
                .discover_service_bindings(
                    query,
                    operation.clone(),
                    budget,
                    self.domains,
                    self.limits,
                )
                .await
                .map_err(Error::Service)?;
            contributions
                .try_reserve_exact(resolution.endpoints.len().min(self.limits.addresses))
                .map_err(|_| Error::ResourceLimit)?;
            for endpoint in resolution.endpoints {
                self.add(&mut contributions, endpoint.ip, endpoint.expires_at)?;
            }
            (
                Arc::try_unwrap(resolution.response).map_err(|_| Error::SharedResponse)?,
                resolution.response_received_at,
            )
        };
        // Recheck before synchronous mutation even if discovery completed in
        // the same poll in which the original deadline elapsed.
        operation
            .clone()
            .run(async { Ok(()) })
            .await
            .map_err(Error::Request)?;
        let reservation = if contributions.is_empty() {
            None
        } else {
            Some(
                self.routes
                    .reserve(
                        self.mode,
                        QuestionKey {
                            backend: self.transport.backend(),
                            name: question.name,
                            record_type: question.record_type,
                            class: question.class,
                        },
                        &contributions,
                        operation.deadline,
                    )
                    .map_err(Error::Routes)?,
            )
        };
        Ok(Prepared::Upstream {
            packet: Box::new(packet),
            received_at,
            udp_payload_limit: query.udp_payload_limit(),
            reservation,
        })
    }

    fn add(
        &self,
        contributions: &mut Vec<Contribution>,
        address: IpAddr,
        expiry: Instant,
    ) -> Result<(), Error> {
        if address.is_ipv6() && !self.limits.ipv6 {
            return Err(Error::DisabledFamily);
        }
        let capabilities = self.transport.capabilities();
        if (address.is_ipv4() && !capabilities.ipv4) || (address.is_ipv6() && !capabilities.ipv6) {
            return Err(Error::UnsupportedFamily);
        }
        if let Some(existing) = contributions
            .iter_mut()
            .find(|item| item.address == address)
        {
            existing.expires_at = existing.expires_at.min(self.routes.elapsed(expiry));
            return Ok(());
        }
        if contributions.len() == self.limits.addresses
            || contributions.len() == contributions.capacity()
        {
            return Err(Error::ResourceLimit);
        }
        contributions.push(Contribution {
            address,
            expires_at: self.routes.elapsed(expiry),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests;
