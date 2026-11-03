// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Explicit foreground approval; no managed-state installation or control API.

use super::{configuration, network, recovery};
use std::{fmt, sync::Arc};
use tokio::sync::watch;

#[derive(Debug)]
pub enum Error {
    Configuration(configuration::Error),
    Recovery(recovery::Error),
    Network(network::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => error.fmt(f),
            Self::Recovery(error) => error.fmt(f),
            Self::Network(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {}

pub struct Diagnostic {
    network: network::Network,
}
impl Diagnostic {
    /// Synchronous bootstrap before the caller starts its async runtime.
    /// The caller already materialized bytes under the invoking account.
    pub fn new(encoded: &[u8]) -> Result<Self, Error> {
        let snapshot = configuration::validate(encoded).map_err(Error::Configuration)?;
        let context = Arc::new(recovery::diagnostic_context().map_err(Error::Recovery)?);
        let lease = configuration::ConfigurationLease::diagnostic(context, snapshot)
            .map_err(Error::Configuration)?;
        let network = network::Network::new(lease).map_err(Error::Network)?;
        Ok(Self { network })
    }
    pub async fn run(
        &mut self,
        cancellation: watch::Receiver<bool>,
        state: &watch::Sender<network::State>,
    ) -> Result<network::Report, network::Failure> {
        self.network.run(cancellation, state).await
    }
}
