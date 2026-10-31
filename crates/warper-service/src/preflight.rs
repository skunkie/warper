// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Pure preparation, not host approval, physical-path verification or readiness.

use crate::relay;
use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use warper_backends::socks5::{Credentials, Socks5};
use warper_config::schema::{
    BackendSettings, Config, Host, PasswordSource, Platform, RoutingMode, Tunnel,
};
use warper_core::{
    BackendId,
    routing::Policy,
    transport::{Backend, EndpointConnector},
};
use warper_stack::{
    Seed, host,
    runtime::{Channels, Runtime},
};

const PACKET_QUEUE: usize = 64;
const MAX_BACKENDS: usize = 64;
const SETUP_BYTES: usize = 513 + 22 + 257;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedPlatform,
    UnsupportedDns,
    UnsupportedRouting,
    UnsupportedBackend,
    UnsupportedFamily,
    UnsupportedMtu,
    EndpointResolutionRequired,
    CredentialImportRequired,
    InvalidConfiguration,
    InvalidCredentials,
    InvalidLimits,
    BufferBudget,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "InvalidConfig: service snapshot is inconsistent",
            Self::InvalidCredentials => "InvalidConfig: SOCKS5 credentials are invalid",
            Self::InvalidLimits => "ResourceLimit: service limits exceed adapter capabilities",
            Self::BufferBudget => {
                "ResourceLimit: service payload buffers exceed the configured budget"
            }
            Self::CredentialImportRequired => {
                "UnsupportedCapability: file credentials require protected managed import"
            }
            Self::EndpointResolutionRequired => {
                "UnsupportedCapability: verified physical endpoint resolution is unavailable"
            }
            _ => "UnsupportedCapability: configuration requires an unavailable service capability",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Buffers {
    pub stack_runtime: usize,
    pub relays: usize,
    pub tun_io: usize,
    pub backend_setup: usize,
    pub credentials: usize,
    pub total: usize,
}

struct BackendPlan {
    id: BackendId,
    endpoint: SocketAddr,
    credentials: Option<Credentials>,
}

pub struct Plan {
    tunnel: Tunnel,
    backends: Box<[BackendPlan]>,
    policy: Arc<Policy>,
    host_limits: host::Limits,
    relay_limits: relay::Limits,
    buffers: Buffers,
}
impl Plan {
    /// Validate and reserve before mutation. Does not read files, resolve names,
    /// open sockets, initialize entropy, spawn tasks or publish connected state.
    pub fn prepare(config: &Config, platform: Platform) -> Result<Self, Error> {
        if platform != Platform::Linux {
            return Err(Error::UnsupportedPlatform);
        }
        let address = config.tunnel.ipv4;
        if address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.is_broadcast()
            || config.tunnel.name.as_ref().is_some_and(|name| {
                name.is_empty()
                    || name.len() > 15
                    || !name.is_ascii()
                    || name == "."
                    || name == ".."
                    || name
                        .bytes()
                        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b':' | 0))
            })
        {
            return Err(Error::InvalidConfiguration);
        }
        if config.ipv6 || config.tunnel.ipv6.is_some() {
            return Err(Error::UnsupportedFamily);
        }
        if config.tunnel.mtu != host::MTU as u16 {
            return Err(Error::UnsupportedMtu);
        }
        if config.tunnel.serve_dns || !config.direct_upstreams.is_empty() {
            return Err(Error::UnsupportedDns);
        }
        if config.protocols.is_empty() || config.protocols.len() > MAX_BACKENDS {
            return Err(Error::InvalidLimits);
        }
        if config.limits.max_tcp_flows == 0 {
            return Err(Error::InvalidLimits);
        }
        let flows = config.limits.max_tcp_flows.min(host::MAX_FLOW_SLOTS);
        let host_limits = host::Limits {
            flows,
            accepted: flows,
            setup_timeout: config.timeouts.connect,
            idle_timeout: config.timeouts.tcp_idle,
            max_age: config.timeouts.flow_max_age,
        };
        let relay_limits = relay::Limits {
            flows,
            setup_timeout: config.timeouts.connect,
            idle_timeout: config.timeouts.tcp_idle,
            max_age: config.timeouts.flow_max_age,
            shutdown_timeout: config.timeouts.shutdown,
        };
        let stack_runtime = Runtime::required_buffer_capacity(host_limits, PACKET_QUEUE)
            .map_err(|_| Error::InvalidLimits)?;
        let relays = relay::Relays::required_buffer_capacity(relay_limits)
            .map_err(|_| Error::InvalidLimits)?;
        let mut ids = BTreeSet::new();
        struct Input<'a> {
            id: BackendId,
            endpoint: SocketAddr,
            authentication: Option<(&'a str, &'a str)>,
        }
        let mut inputs = Vec::with_capacity(config.protocols.len());
        let mut credential_bytes = 0usize;
        for backend in &config.protocols {
            if !ids.insert(backend.registry_id.0)
                || backend.registry_id.0 == 0
                || backend
                    .routes
                    .iter()
                    .any(|route| route.backend != backend.registry_id)
            {
                return Err(Error::InvalidConfiguration);
            }
            if backend.routing_mode != RoutingMode::Static || backend.routes.is_empty() {
                return Err(Error::UnsupportedRouting);
            }
            if !backend.domains.is_empty() || !backend.dns.is_empty() {
                return Err(Error::UnsupportedDns);
            }
            if backend.routes.iter().any(|route| route.network.is_ipv6()) {
                return Err(Error::UnsupportedFamily);
            }
            let BackendSettings::Socks5(socks) = &backend.settings else {
                return Err(Error::UnsupportedBackend);
            };
            let endpoint = match socks.endpoint.host {
                Host::Ip(IpAddr::V4(address))
                    if socks.endpoint.port != 0
                        && !address.is_unspecified()
                        && !address.is_multicast()
                        && !address.is_broadcast() =>
                {
                    SocketAddr::new(address.into(), socks.endpoint.port)
                }
                Host::Ip(IpAddr::V6(_)) => return Err(Error::UnsupportedFamily),
                Host::Name(_) => return Err(Error::EndpointResolutionRequired),
                _ => return Err(Error::InvalidConfiguration),
            };
            let authentication = match &socks.authentication {
                None => None,
                Some((_, PasswordSource::File(_))) => return Err(Error::CredentialImportRequired),
                Some((user, PasswordSource::Inline(password))) => {
                    let password = password.expose().as_str();
                    if !(1..=255).contains(&user.len()) || !(1..=255).contains(&password.len()) {
                        return Err(Error::InvalidCredentials);
                    }
                    credential_bytes = credential_bytes
                        .checked_add(user.len() + password.len())
                        .ok_or(Error::BufferBudget)?;
                    Some((user.as_str(), password))
                }
            };
            inputs.push(Input {
                id: backend.registry_id,
                endpoint,
                authentication,
            });
        }
        let policy = Arc::new(
            config
                .static_policy()
                .map_err(|_| Error::InvalidConfiguration)?,
        );
        let tun_io = host::MTU * 2 + 1;
        let backend_setup = flows.checked_mul(SETUP_BYTES).ok_or(Error::BufferBudget)?;
        let total = [
            stack_runtime,
            relays,
            tun_io,
            backend_setup,
            credential_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .ok_or(Error::BufferBudget)?;
        if total > config.limits.max_buffered_bytes_total {
            return Err(Error::BufferBudget);
        }
        let backends = inputs
            .into_iter()
            .map(|input| {
                let credentials = input
                    .authentication
                    .map(|(user, password)| {
                        Credentials::new(user.as_bytes().to_vec(), password.as_bytes().to_vec())
                    })
                    .transpose()
                    .map_err(|_| Error::InvalidCredentials)?;
                Ok(BackendPlan {
                    id: input.id,
                    endpoint: input.endpoint,
                    credentials,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self {
            tunnel: config.tunnel.clone(),
            backends: backends.into_boxed_slice(),
            policy,
            host_limits,
            relay_limits,
            buffers: Buffers {
                stack_runtime,
                relays,
                tun_io,
                backend_setup,
                credentials: credential_bytes,
                total,
            },
        })
    }
    /// Allocate the admitted adapters without spawning workers or modifying the
    /// host. The service must supply a connector whose physical paths are
    /// verified before publishing capture routes; there is no default connector.
    pub fn instantiate(
        self,
        seed: Seed,
        connector: Arc<dyn EndpointConnector>,
    ) -> Result<Networking, Error> {
        let backends = self
            .backends
            .into_vec()
            .into_iter()
            .map(|backend| {
                Socks5::new(
                    backend.id,
                    backend.endpoint,
                    backend.credentials,
                    self.host_limits.flows,
                    connector.clone(),
                )
                .map(|backend| Arc::new(backend) as Arc<dyn Backend>)
                .map_err(|_| Error::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let relays =
            relay::Relays::new(backends, self.relay_limits).map_err(|_| Error::InvalidLimits)?;
        let (runtime, channels) = Runtime::new(self.host_limits, self.policy, PACKET_QUEUE, seed)
            .map_err(|_| Error::InvalidLimits)?;
        Ok(Networking {
            tunnel: self.tunnel,
            runtime,
            channels,
            relays,
            buffers: self.buffers,
        })
    }
    pub fn flow_capacity(&self) -> usize {
        self.host_limits.flows
    }
    pub fn buffers(&self) -> Buffers {
        self.buffers
    }
    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }
    pub fn endpoints(&self) -> impl ExactSizeIterator<Item = (BackendId, SocketAddr)> + '_ {
        self.backends
            .iter()
            .map(|backend| (backend.id, backend.endpoint))
    }
}
/// Allocated owners awaiting service supervision and journaled host setup.
/// Their construction establishes no network readiness or OS approval.
pub struct Networking {
    pub tunnel: Tunnel,
    pub runtime: Runtime,
    pub channels: Channels,
    pub relays: relay::Relays,
    pub buffers: Buffers,
}
impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Plan(<redacted>)")
    }
}

#[cfg(test)]
mod tests;
