// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One domain selection and ordered upstream attempts within that role.

use std::{fmt, sync::Arc};
use tokio::time::Instant;
use warper_config::schema::RoutingMode;
use warper_core::{
    BackendId,
    dns::Policy,
    transport::{Error as TransportError, Rejection, Request},
};

use super::{
    DirectUdpTransport, DiscoveryError, ExchangeError, LocalReply, Packet, QueryBudget,
    ServiceDiscoveryError, ServiceDiscoveryLimits, TcpTransport,
    prepare::{self, Prepared, Resolver},
    routes::Controller,
};

pub struct Selected {
    pub mode: RoutingMode,
    pub upstreams: Vec<Arc<TcpTransport>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidRegistry,
    MissingBackend,
    Unmatched,
    Closed,
    Routes(super::routes::Error),
    Request(TransportError),
    Packet(super::Error),
    Selected(prepare::Error),
    Direct(ExchangeError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS dispatch: {self:?}")
    }
}
impl std::error::Error for Error {}

pub struct Dispatcher {
    domains: Arc<Policy>,
    routes: Arc<Controller>,
    selected: Vec<Selected>,
    direct: Vec<Arc<DirectUdpTransport>>,
    serve_dns: bool,
    limits: ServiceDiscoveryLimits,
}
impl Dispatcher {
    pub fn new(
        domains: Arc<Policy>,
        routes: Arc<Controller>,
        selected: Vec<Selected>,
        direct: Vec<Arc<DirectUdpTransport>>,
        serve_dns: bool,
        limits: ServiceDiscoveryLimits,
    ) -> Result<Self, Error> {
        Resolver::validate_limits(limits).map_err(Error::Selected)?;
        let count = selected.iter().try_fold(direct.len(), |count, group| {
            count.checked_add(group.upstreams.len())
        });
        if selected.len() > 64
            || count.is_none_or(|count| count > 4096)
            || (serve_dns && direct.is_empty())
        {
            return Err(Error::InvalidRegistry);
        }
        for (index, group) in selected.iter().enumerate() {
            let first = group.upstreams.first().ok_or(Error::InvalidRegistry)?;
            if group
                .upstreams
                .iter()
                .any(|transport| transport.backend() != first.backend())
                || selected[..index].iter().any(|other| {
                    other
                        .upstreams
                        .first()
                        .is_some_and(|transport| transport.backend() == first.backend())
                })
            {
                return Err(Error::InvalidRegistry);
            }
            Resolver::new(first, &domains, &routes, group.mode, limits).map_err(Error::Selected)?;
        }
        Ok(Self {
            domains,
            routes,
            selected,
            direct,
            serve_dns,
            limits,
        })
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

    pub(super) fn wire_bytes(&self) -> usize {
        self.selected
            .iter()
            .flat_map(|group| {
                group
                    .upstreams
                    .iter()
                    .map(|transport| transport.wire_bytes())
            })
            .chain(self.direct.iter().map(|transport| transport.wire_bytes()))
            .max()
            .unwrap_or(0)
    }

    async fn prepare_owned(
        &self,
        query: &Packet,
        operation: Request,
        budget: &QueryBudget,
    ) -> Result<Prepared, Error> {
        if self.routes.is_closed().map_err(Error::Routes)? {
            return Err(Error::Closed);
        }
        let selected = self.domains.select(&query.question().name);
        let group = match selected {
            Some(backend) => Some(self.group(backend)?),
            None if !self.serve_dns => return Err(Error::Unmatched),
            None => None,
        };
        if query.is_response() {
            return Err(Error::Packet(super::Error::Malformed));
        }
        if query.edns_version().is_some_and(|version| version != 0) {
            return query
                .local_reply(LocalReply::ServFail)
                .map(Prepared::Local)
                .map_err(Error::Packet);
        }
        if query.question().class == 1 && query.question().record_type == 28 && !self.limits.ipv6 {
            return query
                .local_reply(LocalReply::DisabledIpv6)
                .map(Prepared::Local)
                .map_err(Error::Packet);
        }
        if let Some(group) = group {
            for (index, transport) in group.upstreams.iter().enumerate() {
                let resolver = Resolver::new(
                    transport,
                    &self.domains,
                    &self.routes,
                    group.mode,
                    self.limits,
                )
                .map_err(Error::Selected)?;
                match resolver.prepare(query, operation.clone(), budget).await {
                    Err(error) if index + 1 < group.upstreams.len() && retry_selected(error) => {}
                    result => return result.map_err(Error::Selected),
                }
            }
            return Err(Error::MissingBackend);
        }
        for (index, transport) in self.direct.iter().enumerate() {
            match transport.exchange(query, operation.clone(), budget).await {
                Err(error) if index + 1 < self.direct.len() && retry_exchange(error) => {}
                Err(error) => return Err(Error::Direct(error)),
                Ok(packet) => {
                    return Ok(Prepared::Upstream {
                        packet: Box::new(packet),
                        received_at: Instant::now(),
                        udp_payload_limit: query.udp_payload_limit(),
                        reservation: None,
                    });
                }
            }
        }
        Err(Error::InvalidRegistry)
    }

    fn group(&self, backend: BackendId) -> Result<&Selected, Error> {
        self.selected
            .iter()
            .find(|group| {
                group
                    .upstreams
                    .first()
                    .is_some_and(|transport| transport.backend() == backend)
            })
            .ok_or(Error::MissingBackend)
    }
}

fn retry_selected(error: prepare::Error) -> bool {
    match error {
        prepare::Error::Address(DiscoveryError::Exchange(error))
        | prepare::Error::Service(ServiceDiscoveryError::Exchange(error)) => retry_exchange(error),
        _ => false,
    }
}

fn retry_exchange(error: ExchangeError) -> bool {
    match error {
        ExchangeError::Io(kind) => retry_io(kind),
        ExchangeError::Backend(TransportError::Io(kind))
        | ExchangeError::Direct(TransportError::Io(kind)) => retry_io(kind),
        ExchangeError::Backend(error) | ExchangeError::Direct(error) => matches!(
            error,
            TransportError::Timeout
                | TransportError::Rejected(
                    Rejection::General
                        | Rejection::NetworkUnreachable
                        | Rejection::HostUnreachable
                        | Rejection::ConnectionRefused
                        | Rejection::TtlExpired
                )
        ),
        _ => false,
    }
}

fn retry_io(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind;
    matches!(
        kind,
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::TimedOut
            | ErrorKind::UnexpectedEof
            | ErrorKind::BrokenPipe
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::NetworkDown
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::Other
    )
}

#[cfg(test)]
mod tests;
