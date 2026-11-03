// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Direct UDP DNS and explicitly correlated TCP retry to the same upstream.

use std::{future::poll_fn, net::SocketAddr, sync::Arc};

use warper_core::transport::{EndpointConnector, Request, datagram::DatagramConnector};

use super::{
    Admission, DirectTcpTransport, Error as PacketError, ExchangeError, Limits, Packet, QueryBudget,
};

// A conservative non-jumbo ceiling also valid for IPv6. Large queries use TCP
// before opening a UDP socket rather than emitting an oversized datagram.
const MAX_UDP_BYTES: usize = 65507;

pub struct DirectUdpTransport {
    connector: Arc<dyn DatagramConnector>,
    tcp: DirectTcpTransport,
    upstream: SocketAddr,
    limits: Limits,
    admission: Admission,
}

impl DirectUdpTransport {
    /// Both connectors must be prepared physical paths for this same literal
    /// upstream. No selected backend or alternate resolver is owned here.
    pub fn new(
        connector: Arc<dyn DatagramConnector>,
        tcp: Arc<dyn EndpointConnector>,
        upstream: SocketAddr,
        limits: Limits,
        admission: Admission,
    ) -> Result<Self, ExchangeError> {
        let tcp = DirectTcpTransport::new(tcp, upstream, limits, admission.clone())?;
        Ok(Self {
            connector,
            tcp,
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
        request
            .clone()
            .run(async { Ok(self.exchange_owned(query, request, budget).await) })
            .await
            .map_err(ExchangeError::Direct)?
    }

    async fn exchange_owned(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
    ) -> Result<Packet, ExchangeError> {
        if query.is_response() {
            return Err(ExchangeError::InvalidRequest);
        }
        let permit = self.admission.reserve()?;
        let encoded = query.encode().map_err(ExchangeError::Packet)?;
        if encoded.len() > self.limits.wire_bytes() {
            return Err(ExchangeError::ResourceLimit);
        }
        if encoded.len() > MAX_UDP_BYTES {
            drop(encoded);
            return self
                .tcp
                .exchange_admitted(query, request, budget, &permit)
                .await;
        }
        budget.charge()?;
        let mut socket = self
            .connector
            .connect_udp(self.upstream, request.clone())
            .await
            .map_err(ExchangeError::Direct)?;
        poll_fn(|context| socket.poll_send(context, &encoded))
            .await
            .map_err(|error| ExchangeError::Io(error.kind()))?;
        let mut bytes = vec![0; self.limits.wire_bytes() + 1];
        let received = poll_fn(|context| socket.poll_recv(context, &mut bytes))
            .await
            .map_err(|error| ExchangeError::Io(error.kind()))?;
        if received.truncated || received.length > self.limits.wire_bytes() {
            return Err(ExchangeError::ResourceLimit);
        }
        match Packet::response(&bytes[..received.length], query, self.limits) {
            Err(PacketError::Truncated) => {
                // Release UDP buffers and native association before TCP setup,
                // while retaining the parent request permit and deadline.
                drop(socket);
                drop(bytes);
                drop(encoded);
                self.tcp
                    .exchange_admitted(query, request, budget, &permit)
                    .await
            }
            result => result.map_err(ExchangeError::Packet),
        }
    }
}

#[cfg(test)]
mod tests;
