// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded TCP DNS through an explicit selected backend or direct physical path.

use std::{fmt, io, net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use warper_core::{
    BackendId,
    transport::{Backend, EndpointConnector, Error as BackendError, OpenTcp, Request},
};

use super::{Error as PacketError, Limits, Packet, QueryBudget};

mod address;
mod service;

pub use address::{AddressDiscoveryLimits, AddressResolution, DiscoveryError};

pub use service::{
    DependencyKind, EndpointPath, EndpointSource, ServiceDiscoveryError, ServiceDiscoveryLimits,
    ServiceEndpoint, ServiceResolution,
};

const MAX_REQUESTS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeError {
    InvalidAdmission,
    InvalidUpstream,
    InvalidRequest,
    UnsupportedCapability,
    ResourceLimit,
    Backend(BackendError),
    Direct(BackendError),
    Packet(PacketError),
    Io(io::ErrorKind),
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAdmission => "invalid DNS admission scope or limit",
            Self::InvalidUpstream => "invalid DNS upstream address",
            Self::InvalidRequest => "DNS transport requires a query packet",
            Self::UnsupportedCapability => "selected backend cannot carry DNS TCP",
            Self::ResourceLimit => "DNS request, query or frame admission exhausted",
            Self::Backend(_) => "selected DNS backend failed",
            Self::Direct(_) => "direct DNS physical path failed",
            Self::Packet(_) => "DNS packet validation failed",
            Self::Io(_) => "DNS stream I/O failed",
        })
    }
}

impl std::error::Error for ExchangeError {}

/// One service-owned admission pool shared by every DNS transport. Acquisition
/// never queues; the caller rejects excess requests before backend work starts.
#[derive(Clone)]
pub struct Admission {
    permits: Arc<Semaphore>,
    limit: usize,
}

impl Admission {
    pub fn new(limit: usize) -> Result<Self, ExchangeError> {
        if !(1..=MAX_REQUESTS).contains(&limit) {
            return Err(ExchangeError::InvalidAdmission);
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(limit)),
            limit,
        })
    }

    pub fn active(&self) -> usize {
        self.limit - self.permits.available_permits()
    }

    pub(super) fn reserve(&self) -> Result<OwnedSemaphorePermit, ExchangeError> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ExchangeError::ResourceLimit)
    }
}

pub struct TcpTransport {
    backend: Arc<dyn Backend>,
    upstream: SocketAddr,
    limits: Limits,
    admission: Admission,
}

impl TcpTransport {
    /// The service supplies one selected backend and a literal DNS upstream.
    /// No resolver, alternate backend or direct connector is owned here.
    pub fn new(
        backend: Arc<dyn Backend>,
        upstream: SocketAddr,
        limits: Limits,
        admission: Admission,
    ) -> Result<Self, ExchangeError> {
        validate_upstream(upstream)?;
        let capabilities = backend.capabilities();
        if !capabilities.tcp
            || (upstream.is_ipv4() && !capabilities.ipv4)
            || (upstream.is_ipv6() && !capabilities.ipv6)
        {
            return Err(ExchangeError::UnsupportedCapability);
        }
        Ok(Self {
            backend,
            upstream,
            limits,
            admission,
        })
    }

    /// Keep one total deadline/cancellation context through encoding, backend
    /// setup, partial frame writes/reads and validation. Dropping this future
    /// closes its stream and releases admission; no child task is spawned.
    pub async fn exchange(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
    ) -> Result<Packet, ExchangeError> {
        exchange(
            Dial::Backend(self.backend.as_ref()),
            self.upstream,
            self.limits,
            &self.admission,
            query,
            request,
            budget,
        )
        .await
    }

    pub fn backend(&self) -> BackendId {
        self.backend.id()
    }

    pub fn capabilities(&self) -> warper_core::transport::Capabilities {
        self.backend.capabilities()
    }
}

/// Direct DNS is a separate transport, constructed only for preserved physical
/// upstreams. A selected-backend transport never owns or invokes this adapter.
pub struct DirectTcpTransport {
    connector: Arc<dyn EndpointConnector>,
    upstream: SocketAddr,
    limits: Limits,
    admission: Admission,
}

impl DirectTcpTransport {
    pub fn new(
        connector: Arc<dyn EndpointConnector>,
        upstream: SocketAddr,
        limits: Limits,
        admission: Admission,
    ) -> Result<Self, ExchangeError> {
        validate_upstream(upstream)?;
        Ok(Self {
            connector,
            upstream,
            limits,
            admission,
        })
    }

    pub async fn exchange(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
    ) -> Result<Packet, ExchangeError> {
        exchange(
            Dial::Direct(self.connector.as_ref()),
            self.upstream,
            self.limits,
            &self.admission,
            query,
            request,
            budget,
        )
        .await
    }

    pub(super) async fn exchange_admitted(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
        permit: &OwnedSemaphorePermit,
    ) -> Result<Packet, ExchangeError> {
        request
            .clone()
            .run(async {
                Ok(
                    if !Arc::ptr_eq(&self.admission.permits, permit.semaphore()) {
                        Err(ExchangeError::InvalidAdmission)
                    } else if query.is_response() {
                        Err(ExchangeError::InvalidRequest)
                    } else {
                        exchange_packet(
                            Dial::Direct(self.connector.as_ref()),
                            self.upstream,
                            self.limits,
                            query,
                            request,
                            budget,
                            permit,
                        )
                        .await
                    },
                )
            })
            .await
            .map_err(ExchangeError::Direct)?
    }
}

#[derive(Clone, Copy)]
enum Dial<'a> {
    Backend(&'a dyn Backend),
    Direct(&'a dyn EndpointConnector),
}

impl<'a> Dial<'a> {
    fn open(self, upstream: SocketAddr, request: Request) -> OpenTcp<'a> {
        match self {
            Self::Backend(backend) => backend.open_tcp(upstream, request),
            Self::Direct(connector) => connector.connect_tcp(upstream, request),
        }
    }

    fn error(self, error: BackendError) -> ExchangeError {
        match self {
            Self::Backend(_) => ExchangeError::Backend(error),
            Self::Direct(_) => ExchangeError::Direct(error),
        }
    }
}

async fn exchange(
    dial: Dial<'_>,
    upstream: SocketAddr,
    limits: Limits,
    admission: &Admission,
    query: &Packet,
    request: Request,
    budget: &QueryBudget,
) -> Result<Packet, ExchangeError> {
    request
        .clone()
        .run(async {
            Ok(exchange_owned(dial, upstream, limits, admission, query, request, budget).await)
        })
        .await
        .map_err(|error| dial.error(error))?
}

async fn exchange_owned(
    dial: Dial<'_>,
    upstream: SocketAddr,
    limits: Limits,
    admission: &Admission,
    query: &Packet,
    request: Request,
    budget: &QueryBudget,
) -> Result<Packet, ExchangeError> {
    if query.is_response() {
        return Err(ExchangeError::InvalidRequest);
    }
    let permit = admission.reserve()?;
    exchange_packet(dial, upstream, limits, query, request, budget, &permit).await
}

async fn exchange_packet(
    dial: Dial<'_>,
    upstream: SocketAddr,
    limits: Limits,
    query: &Packet,
    request: Request,
    budget: &QueryBudget,
    _permit: &OwnedSemaphorePermit,
) -> Result<Packet, ExchangeError> {
    let mut frame = query.encode().map_err(ExchangeError::Packet)?;
    let length = frame.len();
    if length > limits.wire_bytes() {
        return Err(ExchangeError::ResourceLimit);
    }
    frame
        .try_reserve_exact(2)
        .map_err(|_| ExchangeError::ResourceLimit)?;
    frame.resize(length + 2, 0);
    frame.copy_within(..length, 2);
    frame[..2].copy_from_slice(&(length as u16).to_be_bytes());
    budget.charge()?;
    let mut stream = dial
        .open(upstream, request)
        .await
        .map_err(|error| dial.error(error))?;
    // Keep the length and query in one write operation to avoid a tiny
    // prefix being delayed by Nagle/ACK interaction on real TCP streams.
    stream
        .write_all(&frame)
        .await
        .map_err(|error| ExchangeError::Io(error.kind()))?;
    let mut prefix = [0; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|error| ExchangeError::Io(error.kind()))?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length > limits.wire_bytes() {
        return Err(ExchangeError::ResourceLimit);
    }
    if length < 12 {
        return Err(ExchangeError::Packet(PacketError::Malformed));
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| ExchangeError::Io(error.kind()))?;
    Packet::response(&bytes, query, limits).map_err(ExchangeError::Packet)
}

fn validate_upstream(upstream: SocketAddr) -> Result<(), ExchangeError> {
    if upstream.port() == 0
        || upstream.ip().is_unspecified()
        || upstream.ip().is_multicast()
        || matches!(upstream.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        Err(ExchangeError::InvalidUpstream)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
