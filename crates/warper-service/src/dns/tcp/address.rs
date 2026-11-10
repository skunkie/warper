// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Parent-owned selected-backend address dependency I/O.

use std::fmt;

use tokio::time::Instant;
use warper_core::{BackendId, transport::Request};

use super::{Dial, ExchangeError, Packet, QueryBudget, TcpTransport, exchange_packet};
use crate::dns::{AddressAnswer, AddressError, AddressLookup, AddressProgress};

#[derive(Clone, Copy, Debug)]
pub struct AddressDiscoveryLimits {
    pub alias_hops: usize,
    pub addresses: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    Exchange(ExchangeError),
    Answer(AddressError),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Exchange(_) => "DNS address dependency exchange failed",
            Self::Answer(_) => "DNS address dependency validation failed",
        })
    }
}

impl std::error::Error for DiscoveryError {}

/// Prepared discovery data only. A route commit and response handoff are still
/// required before any positive response may be exposed.
#[derive(Debug)]
pub struct AddressResolution {
    pub backend: BackendId,
    pub response: Packet,
    pub response_received_at: Instant,
    pub answer: AddressAnswer,
}

impl TcpTransport {
    pub async fn discover_addresses(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
        limits: AddressDiscoveryLimits,
    ) -> Result<AddressResolution, DiscoveryError> {
        request
            .clone()
            .run(async { Ok(self.discover_owned(query, request, budget, limits).await) })
            .await
            .map_err(|error| DiscoveryError::Exchange(ExchangeError::Backend(error)))?
    }

    async fn discover_owned(
        &self,
        query: &Packet,
        request: Request,
        budget: &QueryBudget,
        limits: AddressDiscoveryLimits,
    ) -> Result<AddressResolution, DiscoveryError> {
        if query.is_response() {
            return Err(DiscoveryError::Exchange(ExchangeError::InvalidRequest));
        }
        let mut lookup = AddressLookup::new(query.question(), limits.alias_hops, limits.addresses)
            .and_then(|lookup| lookup.with_packet_storage(query))
            .map_err(DiscoveryError::Answer)?;
        let permit = self.admission.reserve().map_err(DiscoveryError::Exchange)?;
        let first = exchange_packet(
            Dial::Backend(self.backend.as_ref()),
            self.upstream,
            self.limits,
            query,
            request.clone(),
            budget,
            &permit,
        )
        .await
        .map_err(DiscoveryError::Exchange)?;
        let response_received_at = Instant::now();
        let mut progress = lookup
            .advance(&first, response_received_at)
            .map_err(DiscoveryError::Answer)?;
        loop {
            match progress {
                AddressProgress::Complete(answer) => {
                    return Ok(AddressResolution {
                        backend: self.backend(),
                        response: first,
                        response_received_at,
                        answer,
                    });
                }
                AddressProgress::Followup(next) => lookup = next,
            }
            let dependency = query
                .dependency(lookup.question())
                .map_err(|error| DiscoveryError::Exchange(ExchangeError::Packet(error)))?;
            let response = exchange_packet(
                Dial::Backend(self.backend.as_ref()),
                self.upstream,
                self.limits,
                &dependency,
                request.clone(),
                budget,
                &permit,
            )
            .await
            .map_err(DiscoveryError::Exchange)?;
            progress = lookup
                .advance(&response, Instant::now())
                .map_err(DiscoveryError::Answer)?;
        }
    }
}

#[cfg(test)]
mod tests;
