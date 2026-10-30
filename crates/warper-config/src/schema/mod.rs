// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Offline configuration validation. Runtime preflight is a separate gate.

use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use warper_core::{BackendId, configuration::paths::Paths, routing};

use crate::yaml;

mod backend;
mod fields;

pub use backend::{
    Authentication, Backend, BackendSettings, DnsTransport, Endpoint, Host, PasswordSource,
    Requirements, RoutingMode, Secret, Socks5, Ssh, Trust, WireGuard,
};
use fields::{Object, local_address};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Linux,
    MacOs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    Yaml(yaml::Reason),
    Path(warper_core::configuration::paths::Error),
    MissingField,
    UnknownField,
    WrongType,
    OutOfRange,
    InvalidAddress,
    InvalidName,
    InvalidDomain,
    InvalidHost,
    InvalidCidr,
    InvalidKey,
    ZeroPeerKey,
    InvalidId,
    DuplicateId,
    DuplicateDomain,
    DuplicateRoute,
    DuplicateAddress,
    BackendCount,
    MissingRouting,
    RoutingMode,
    MissingDns,
    Credentials,
    TrustConflict,
    UnsupportedFamily,
    RouteLimit,
}

impl Reason {
    fn message(self) -> &'static str {
        match self {
            Self::Yaml(_) => "invalid or excessive YAML input",
            Self::Path(_) => "use a nonempty path with invoking-user home expansion",
            Self::MissingField => "provide the required field",
            Self::UnknownField => "remove the unknown key from this mapping",
            Self::WrongType => "use the documented YAML field type without coercion",
            Self::OutOfRange => "value is outside the documented range",
            Self::InvalidAddress => "provide a safe bare IP address",
            Self::InvalidName => "provide a valid name for the selected platform",
            Self::InvalidDomain => {
                "provide a valid normalized domain name without wildcards or IP literals"
            }
            Self::InvalidHost => "provide a hostname or IP with the documented port syntax",
            Self::InvalidCidr => "provide a canonical CIDR without host bits",
            Self::InvalidKey => "provide a canonical Base64 key with the required length",
            Self::ZeroPeerKey => "peer_public_key must not be all zero",
            Self::InvalidId => {
                "use a lowercase backend ID of at most 64 ASCII letters, digits, underscores or hyphens"
            }
            Self::DuplicateId => "assign each backend a unique ID",
            Self::DuplicateDomain => "assign each normalized domain only once",
            Self::DuplicateRoute => "assign each identical CIDR only once",
            Self::DuplicateAddress => {
                "remove duplicate addresses or unsupported repeated inner families"
            }
            Self::BackendCount => "provide exactly one backend type per protocol item",
            Self::MissingRouting => "provide domains or static CIDRs for the backend",
            Self::RoutingMode => "routing mode must agree with the domain and CIDR lists",
            Self::MissingDns => "provide backend DNS servers when domains are configured",
            Self::Credentials => {
                "provide exactly one supported credential source and its required user/key fields"
            }
            Self::TrustConflict => "choose known_hosts or a host-key pin, not both",
            Self::UnsupportedFamily => {
                "enable the captured family and provide the required WireGuard inner address families"
            }
            Self::RouteLimit => "static routes exceed limits.max_route_entries",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub field: String,
    pub reason: Reason,
}

impl Error {
    fn new(field: impl Into<String>, reason: Reason) -> Self {
        Self {
            field: field.into(),
            reason,
        }
    }

    pub fn category(&self) -> yaml::Category {
        match self.reason {
            Reason::Yaml(reason) => reason.category(),
            Reason::RouteLimit => yaml::Category::ResourceLimit,
            _ => yaml::Category::InvalidConfig,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {}: {}",
            self.category(),
            self.field,
            self.reason.message()
        )
    }
}

impl std::error::Error for Error {}

impl From<yaml::Error> for Error {
    fn from(error: yaml::Error) -> Self {
        Self::new(error.field, Reason::Yaml(error.reason))
    }
}

/// Source material has passed offline validation only, not runtime preflight.
#[derive(Clone)]
pub struct Config {
    pub tunnel: Tunnel,
    pub protocols: Vec<Backend>,
    pub ipv6: bool,
    pub direct_upstreams: Vec<IpAddr>,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub autoconnect: bool,
}

impl Config {
    pub fn parse(source: &[u8], paths: &Paths, platform: Platform) -> Result<Self, Error> {
        let document = yaml::decode(source)?;
        let root = Object::new(
            &document,
            "$",
            &[
                "tunnel",
                "protocols",
                "ipv6",
                "dns",
                "timeouts",
                "limits",
                "service",
            ],
        )?;
        let ipv6 = root.boolean("ipv6", false)?;
        let tunnel = Tunnel::parse(root.required("tunnel")?, ipv6, platform)?;
        let limits = Limits::parse(root.child("limits", LIMIT_NAMES)?)?;
        let timeouts = Timeouts::parse(root.child("timeouts", TIMEOUT_NAMES)?)?;
        let service = root.child("service", &["autoconnect"])?;
        let autoconnect = service.boolean("autoconnect", false)?;
        let dns = root.child("dns", &["direct_upstreams"])?;
        let direct_upstreams = fields::addresses(&dns, "direct_upstreams")?;
        let entries = root.sequence("protocols", true)?;
        if entries.is_empty() {
            return Err(Error::new("protocols", Reason::OutOfRange));
        }
        let mut protocols = Vec::with_capacity(entries.len());
        let mut ids = BTreeSet::new();
        let mut domains = BTreeSet::new();
        let mut routes = BTreeSet::new();
        for (index, entry) in entries.iter().enumerate() {
            let registry_id = BackendId(index as u64 + 1);
            let backend = Backend::parse(entry, index, registry_id, ipv6, paths)?;
            if !ids.insert(backend.id.clone()) {
                return Err(Error::new(
                    format!("protocols[{index}].id"),
                    Reason::DuplicateId,
                ));
            }
            let base = format!("protocols[{index}].{}", backend.settings.kind());
            for (index, domain) in backend.domains.iter().enumerate() {
                if !domains.insert(domain.clone()) {
                    return Err(Error::new(
                        format!("{base}.domains[{index}]"),
                        Reason::DuplicateDomain,
                    ));
                }
            }
            for (index, route) in backend.routes.iter().enumerate() {
                if !routes.insert((route.network, route.prefix_len)) {
                    return Err(Error::new(
                        format!("{base}.ips[{index}]"),
                        Reason::DuplicateRoute,
                    ));
                }
                if routes.len() > limits.max_route_entries {
                    return Err(Error::new("limits.max_route_entries", Reason::RouteLimit));
                }
            }
            protocols.push(backend);
        }
        Ok(Self {
            tunnel,
            protocols,
            ipv6,
            direct_upstreams,
            timeouts,
            limits,
            autoconnect,
        })
    }

    /// Build the existing core policy without changing host routes.
    pub fn static_policy(&self) -> Result<routing::Policy, routing::Error> {
        if self.limits.max_route_entries == 0 {
            return Err(routing::Error::InvalidLimit);
        }
        let count = self
            .protocols
            .iter()
            .try_fold(0usize, |count, backend| {
                count.checked_add(backend.routes.len())
            })
            .ok_or(routing::Error::ResourceLimit)?;
        if count > self.limits.max_route_entries {
            return Err(routing::Error::ResourceLimit);
        }
        let entries: Vec<_> = self
            .protocols
            .iter()
            .flat_map(|backend| backend.routes.iter().copied())
            .collect();
        routing::Policy::new(&entries, self.limits.max_route_entries)
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Config(<redacted>)")
    }
}

#[derive(Clone, Debug)]
pub struct Tunnel {
    pub name: Option<String>,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub serve_dns: bool,
    pub mtu: u16,
}

impl Tunnel {
    fn parse(value: &yaml::Value, ipv6_enabled: bool, platform: Platform) -> Result<Self, Error> {
        let object = Object::new(
            value,
            "tunnel",
            &["name", "ip", "ipv6_address", "serve_dns", "mtu"],
        )?;
        let name = object.string("name")?;
        if let Some(name) = &name {
            let valid = match platform {
                Platform::Linux => {
                    !name.is_empty()
                        && name.len() <= 15
                        && name.is_ascii()
                        && !name.bytes().any(|byte| {
                            byte.is_ascii_whitespace() || matches!(byte, b'/' | b':' | 0)
                        })
                        && name != "."
                        && name != ".."
                }
                Platform::MacOs => name.strip_prefix("utun").is_some_and(|number| {
                    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                }),
            };
            if !valid {
                return Err(Error::new("tunnel.name", Reason::InvalidName));
            }
        }
        let ip = local_address(&object.required_string("ip")?, "tunnel.ip")?;
        let IpAddr::V4(ipv4) = ip else {
            return Err(Error::new("tunnel.ip", Reason::InvalidAddress));
        };
        let ipv6 = object.string("ipv6_address")?;
        if ipv6_enabled != ipv6.is_some() {
            return Err(Error::new("tunnel.ipv6_address", Reason::UnsupportedFamily));
        }
        let ipv6 = ipv6
            .map(
                |sample| match local_address(&sample, "tunnel.ipv6_address")? {
                    IpAddr::V6(value) => Ok(value),
                    _ => Err(Error::new("tunnel.ipv6_address", Reason::InvalidAddress)),
                },
            )
            .transpose()?;
        let serve_dns = object.boolean("serve_dns", false)?;
        let mtu = object.number("mtu", 1280, 1280, 9000)? as u16;
        Ok(Self {
            name,
            ipv4,
            ipv6,
            serve_dns,
            mtu,
        })
    }
}

const TIMEOUT_NAMES: &[&str] = &[
    "connect_ms",
    "dns_ms",
    "dns_route_grace_ms",
    "tcp_idle_ms",
    "udp_idle_ms",
    "flow_max_age_ms",
    "shutdown_ms",
    "control_ms",
];

#[derive(Clone, Debug)]
pub struct Timeouts {
    pub connect: Duration,
    pub dns: Duration,
    pub dns_route_grace: Duration,
    pub tcp_idle: Duration,
    pub udp_idle: Duration,
    pub flow_max_age: Duration,
    pub shutdown: Duration,
    pub control: Duration,
}

impl Timeouts {
    fn parse(object: Object<'_>) -> Result<Self, Error> {
        let duration = |name, default| {
            object
                .number(name, default, 1, u64::MAX)
                .map(Duration::from_millis)
        };
        Ok(Self {
            connect: duration("connect_ms", 10_000)?,
            dns: duration("dns_ms", 5000)?,
            dns_route_grace: duration("dns_route_grace_ms", 30_000)?,
            tcp_idle: duration("tcp_idle_ms", 300_000)?,
            udp_idle: duration("udp_idle_ms", 60_000)?,
            flow_max_age: duration("flow_max_age_ms", 86_400_000)?,
            shutdown: duration("shutdown_ms", 10_000)?,
            control: duration("control_ms", 5000)?,
        })
    }
}

const LIMIT_NAMES: &[&str] = &[
    "max_tcp_flows",
    "max_udp_flows",
    "max_dns_requests",
    "max_dns_alias_hops",
    "max_dns_dependency_queries",
    "max_dns_endpoint_addresses",
    "max_dns_lease_entries",
    "max_dns_cache_entries",
    "max_dns_state_bytes_total",
    "max_route_entries",
    "max_pending_route_ops",
    "max_queued_datagrams_per_flow",
    "max_buffered_bytes_total",
    "max_log_entries",
    "max_log_message_bytes",
    "max_control_clients",
    "max_control_message_bytes",
    "max_control_inflight_requests",
    "max_control_events_per_client",
    "max_control_buffered_bytes_total",
    "max_control_operations",
];

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_tcp_flows: usize,
    pub max_udp_flows: usize,
    pub max_dns_requests: usize,
    pub max_dns_alias_hops: usize,
    pub max_dns_dependency_queries: usize,
    pub max_dns_endpoint_addresses: usize,
    pub max_dns_lease_entries: usize,
    pub max_dns_cache_entries: usize,
    pub max_dns_state_bytes_total: usize,
    pub max_route_entries: usize,
    pub max_pending_route_ops: usize,
    pub max_queued_datagrams_per_flow: usize,
    pub max_buffered_bytes_total: usize,
    pub max_log_entries: usize,
    pub max_log_message_bytes: usize,
    pub max_control_clients: usize,
    pub max_control_message_bytes: usize,
    pub max_control_inflight_requests: usize,
    pub max_control_events_per_client: usize,
    pub max_control_buffered_bytes_total: usize,
    pub max_control_operations: usize,
}

impl Limits {
    fn parse(object: Object<'_>) -> Result<Self, Error> {
        let limit = |name, default| {
            object
                .number(name, default, 1, usize::MAX as u64)
                .map(|value| value as usize)
        };
        Ok(Self {
            max_tcp_flows: limit("max_tcp_flows", 1024)?,
            max_udp_flows: limit("max_udp_flows", 1024)?,
            max_dns_requests: limit("max_dns_requests", 128)?,
            max_dns_alias_hops: limit("max_dns_alias_hops", 8)?,
            max_dns_dependency_queries: limit("max_dns_dependency_queries", 32)?,
            max_dns_endpoint_addresses: limit("max_dns_endpoint_addresses", 64)?,
            max_dns_lease_entries: limit("max_dns_lease_entries", 32_768)?,
            max_dns_cache_entries: limit("max_dns_cache_entries", 4096)?,
            max_dns_state_bytes_total: limit("max_dns_state_bytes_total", 16_777_216)?,
            max_route_entries: limit("max_route_entries", 16_384)?,
            max_pending_route_ops: limit("max_pending_route_ops", 256)?,
            max_queued_datagrams_per_flow: limit("max_queued_datagrams_per_flow", 64)?,
            max_buffered_bytes_total: limit("max_buffered_bytes_total", 67_108_864)?,
            max_log_entries: limit("max_log_entries", 2000)?,
            max_log_message_bytes: limit("max_log_message_bytes", 4096)?,
            max_control_clients: limit("max_control_clients", 16)?,
            max_control_message_bytes: limit("max_control_message_bytes", 1_048_576)?,
            max_control_inflight_requests: limit("max_control_inflight_requests", 64)?,
            max_control_events_per_client: limit("max_control_events_per_client", 256)?,
            max_control_buffered_bytes_total: limit("max_control_buffered_bytes_total", 8_388_608)?,
            max_control_operations: limit("max_control_operations", 256)?,
        })
    }
}
