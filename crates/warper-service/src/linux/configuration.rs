// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Approved immutable configuration ownership, not network or control readiness.
//! All operations run in retained synchronous native workers.

use std::{fmt, os::unix::net::UnixStream, sync::Arc};

use warper_config::{
    managed::Snapshot,
    schema::{Config, Platform},
};
use warper_control::{
    Access, OwnerPolicy,
    runtime::managed::{ClaimError, Error as StorageError, ManagedStore, Ownership},
    unix,
};

use super::context::Context;
use crate::preflight::Plan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Context(super::context::Error),
    Authentication(warper_control::Error),
    Storage(StorageError),
    Managed(warper_config::managed::Error),
    Preflight(crate::preflight::Error),
    Control(warper_control::admission::Error),
    Busy,
    Conflict,
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => error.fmt(formatter),
            Self::Storage(error) => error.fmt(formatter),
            Self::Managed(error) => error.fmt(formatter),
            Self::Preflight(error) => error.fmt(formatter),
            Self::Control(error) => error.fmt(formatter),
            Self::Authentication(_) => formatter.write_str(
                "PermissionDenied: configuration installation requires an administrator",
            ),
            Self::Busy => {
                formatter.write_str("Busy: approved configuration is retained by service work")
            }
            Self::Conflict => {
                formatter.write_str("Conflict: approved configuration generation changed")
            }
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub generation: u64,
    pub present: bool,
}

struct Approved {
    generation: u64,
    snapshot: Snapshot,
    // Keep instance ownership until the last supervisor/worker lease drops.
    context: Arc<Context>,
    _ownership: Arc<Ownership>,
}

#[derive(Clone)]
pub struct ConfigurationLease(Arc<Approved>);
impl ConfigurationLease {
    pub fn generation(&self) -> u64 {
        self.0.generation
    }
    pub(super) fn context(&self) -> Arc<Context> {
        self.0.context.clone()
    }
    pub fn config(&self) -> &Config {
        self.0.snapshot.config()
    }
}
impl fmt::Debug for ConfigurationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigurationLease(<redacted>)")
    }
}

pub struct Configurations {
    context: Arc<Context>,
    store: ManagedStore,
    approved: Option<Arc<Approved>>,
    ownership: Arc<Ownership>,
}
impl Configurations {
    pub fn open(context: Arc<Context>) -> Result<Self, Error> {
        context.revalidate().map_err(Error::Context)?;
        let ownership = Arc::new(Ownership::acquire(context.retain_runtime()).map_err(
            |error| match error {
                ClaimError::Busy => Error::Busy,
                ClaimError::Runtime(error) => Error::Storage(StorageError::Runtime(error)),
            },
        )?);
        let store = ManagedStore::open(context.runtime()).map_err(Error::Storage)?;
        let approved = store
            .read(context.runtime())
            .map_err(Error::Storage)?
            .map(|stored| {
                validate(stored.payload()).map(|snapshot| {
                    Arc::new(Approved {
                        generation: stored.revision(),
                        snapshot,
                        context: context.clone(),
                        _ownership: ownership.clone(),
                    })
                })
            })
            .transpose()?;
        Ok(Self {
            context,
            store,
            approved,
            ownership,
        })
    }

    pub fn install(
        &mut self,
        peer: &UnixStream,
        expected_generation: u64,
        encoded: &[u8],
    ) -> Result<u64, Error> {
        self.context.revalidate().map_err(Error::Context)?;
        authorize_admin(peer)?;
        if self
            .approved
            .as_ref()
            .is_some_and(|approved| Arc::strong_count(approved) != 1)
        {
            return Err(Error::Busy);
        }
        let status = self.status()?;
        if status.generation != expected_generation {
            return Err(Error::Conflict);
        }
        let snapshot = validate(encoded)?;
        let stored = self
            .store
            .replace(self.context.runtime(), expected_generation, encoded)
            .map_err(Error::Storage)?;
        let generation = stored.revision();
        self.approved = Some(Arc::new(Approved {
            generation,
            snapshot,
            context: self.context.clone(),
            _ownership: self.ownership.clone(),
        }));
        Ok(generation)
    }

    pub fn status(&self) -> Result<Status, Error> {
        self.context.revalidate().map_err(Error::Context)?;
        let observed = self
            .store
            .read(self.context.runtime())
            .map_err(Error::Storage)?;
        let generation = observed.as_ref().map_or(0, |stored| stored.revision());
        if generation
            != self
                .approved
                .as_ref()
                .map_or(0, |approved| approved.generation)
        {
            return Err(Error::Conflict);
        }
        Ok(Status {
            generation,
            present: observed.is_some(),
        })
    }

    pub fn lease(&self) -> Result<Option<ConfigurationLease>, Error> {
        self.status()?;
        Ok(self
            .approved
            .as_ref()
            .map(|approved| ConfigurationLease(approved.clone())))
    }
}
impl fmt::Debug for Configurations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Configurations(<redacted>)")
    }
}

fn authorize_admin(peer: &UnixStream) -> Result<(), Error> {
    let policy = OwnerPolicy::new(None).map_err(Error::Authentication)?;
    unix::authenticate_client(peer, &policy, Access::Administer).map_err(Error::Authentication)?;
    Ok(())
}

fn validate(encoded: &[u8]) -> Result<Snapshot, Error> {
    let snapshot = Snapshot::decode(encoded, Platform::Linux).map_err(Error::Managed)?;
    let limits = &snapshot.config().limits;
    warper_control::admission::Plan::new(
        limits.max_control_clients,
        limits.max_control_inflight_requests,
        limits.max_control_message_bytes,
        limits.max_control_buffered_bytes_total,
    )
    .map_err(Error::Control)?;
    // Drop the pure plan after validating bounds and credentials; a later
    // network owner prepares its own plan while retaining ConfigurationLease.
    Plan::prepare(snapshot.config(), Platform::Linux).map_err(Error::Preflight)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use warper_core::configuration::paths::{Account, Paths};

    fn encoded(sample: &str) -> warper_config::schema::Secret<Vec<u8>> {
        let paths = Paths::new(
            &Account {
                uid: 1234,
                name: "sample".into(),
                home: "/sample".into(),
            },
            Path::new("/sample"),
            Some("/sample/source.yaml"),
        )
        .unwrap();
        Snapshot::import(sample.as_bytes(), &paths, Platform::Linux)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn installation_validation_rejects_corrupt_and_unavailable_service_capabilities() {
        assert!(matches!(validate(b"invalid"), Err(Error::Managed(_))));
        let sample = "tunnel: {ip: 198.18.0.1}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]";
        validate(encoded(sample).expose()).unwrap();
        for limits in [
            "max_control_clients: 65",
            "max_control_inflight_requests: 65",
            "max_control_message_bytes: 67",
            "max_control_buffered_bytes_total: 1",
        ] {
            let sample = format!("{sample}\nlimits: {{{limits}}}\n");
            assert!(matches!(
                validate(encoded(&sample).expose()),
                Err(Error::Control(_))
            ));
        }
        for timeout in ["connect_ms", "shutdown_ms"] {
            let sample = format!("{sample}\ntimeouts: {{{timeout}: 30001}}\n");
            assert!(matches!(
                validate(encoded(&sample).expose()),
                Err(Error::Preflight(crate::preflight::Error::InvalidLimits))
            ));
        }
        let sample = sample.replace("127.0.0.1:1080", "proxy.example.test:1080");
        assert!(matches!(
            validate(encoded(&sample).expose()),
            Err(Error::Preflight(
                crate::preflight::Error::EndpointResolutionRequired
            ))
        ));
        let sample = "tunnel: {ip: 198.18.0.1, serve_dns: true}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]";
        assert!(matches!(
            validate(encoded(sample).expose()),
            Err(Error::Preflight(crate::preflight::Error::UnsupportedDns))
        ));
    }

    #[test]
    fn installation_authorization_uses_actual_administrative_peer_credentials() {
        let (peer, _client) = UnixStream::pair().unwrap();
        let expected = if nix::unistd::geteuid().is_root() {
            Ok(())
        } else {
            Err(Error::Authentication(
                warper_control::Error::PermissionDenied,
            ))
        };
        assert_eq!(authorize_admin(&peer), expected);
    }
}
