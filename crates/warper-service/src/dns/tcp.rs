// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One bounded DNS exchange through the original selected TCP backend.

use std::{fmt, io, net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
};
use warper_core::{
    BackendId,
    transport::{Backend, Error as BackendError, Request},
};

use super::{Error as PacketError, Limits, Packet};

const MAX_REQUESTS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeError {
    InvalidAdmission,
    InvalidUpstream,
    InvalidRequest,
    UnsupportedCapability,
    ResourceLimit,
    Backend(BackendError),
    Packet(PacketError),
    Io(io::ErrorKind),
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAdmission => "invalid DNS request admission limit",
            Self::InvalidUpstream => "invalid DNS upstream address",
            Self::InvalidRequest => "DNS transport requires a query packet",
            Self::UnsupportedCapability => "selected backend cannot carry DNS TCP",
            Self::ResourceLimit => "DNS request or frame admission exhausted",
            Self::Backend(_) => "selected DNS backend failed",
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
        if upstream.port() == 0
            || upstream.ip().is_unspecified()
            || upstream.ip().is_multicast()
            || matches!(upstream.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(ExchangeError::InvalidUpstream);
        }
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
    ) -> Result<Packet, ExchangeError> {
        request
            .clone()
            .run(async { Ok(self.exchange_owned(query, request).await) })
            .await
            .map_err(ExchangeError::Backend)?
    }

    pub fn backend(&self) -> BackendId {
        self.backend.id()
    }

    async fn exchange_owned(
        &self,
        query: &Packet,
        request: Request,
    ) -> Result<Packet, ExchangeError> {
        if query.is_response() {
            return Err(ExchangeError::InvalidRequest);
        }
        let _permit = self
            .admission
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ExchangeError::ResourceLimit)?;
        let mut frame = query.encode().map_err(ExchangeError::Packet)?;
        let length = frame.len();
        if length > self.limits.wire_bytes() {
            return Err(ExchangeError::ResourceLimit);
        }
        frame
            .try_reserve_exact(2)
            .map_err(|_| ExchangeError::ResourceLimit)?;
        frame.resize(length + 2, 0);
        frame.copy_within(..length, 2);
        frame[..2].copy_from_slice(&(length as u16).to_be_bytes());
        let mut stream = self
            .backend
            .open_tcp(self.upstream, request)
            .await
            .map_err(ExchangeError::Backend)?;
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
        if length > self.limits.wire_bytes() {
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
        Packet::response(&bytes, query, self.limits).map_err(ExchangeError::Packet)
    }
}

#[cfg(test)]
mod tests;
