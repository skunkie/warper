// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded, secret-bearing managed data. This is not installation authority.

use std::{collections::BTreeMap, fmt, net::IpAddr, path::Path};

use warper_core::configuration::paths::{Account, Paths};

use crate::{
    credential,
    schema::{
        BackendSettings, Config, Host, PasswordSource, Platform, Reason, RoutingMode, Secret,
    },
    yaml::{MAX_SOURCE_BYTES, Value},
};

const HEADER: usize = 16;
const MAX_BACKENDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig(Reason),
    Credential(credential::Error),
    UnsupportedBackend,
    BackendLimit,
    InvalidCredentials,
    InvalidEnvelope,
    ResourceLimit,
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig(_) => "InvalidConfig: managed source failed schema validation",
            Self::Credential(_) => "InvalidConfig: managed credential import failed",
            Self::UnsupportedBackend => {
                "UnsupportedCapability: managed import requires SOCKS5 backends"
            }
            Self::BackendLimit => "ResourceLimit: managed import exceeds 64 backends",
            Self::InvalidCredentials => {
                "InvalidConfig: managed SOCKS5 credentials must contain 1..255 UTF-8 bytes"
            }
            Self::InvalidEnvelope => "InvalidConfig: invalid managed snapshot envelope",
            Self::ResourceLimit => "ResourceLimit: managed snapshot exceeds 1 MiB",
        })
    }
}
impl std::error::Error for Error {}

pub struct Snapshot {
    document: Vec<u8>,
    config: Config,
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedSnapshot(<redacted>)")
    }
}
impl Snapshot {
    /// Synchronous client-side import. No privileged endpoint may forward paths
    /// here. Validate every backend before any selected credential file read.
    pub fn import(source: &[u8], paths: &Paths, platform: Platform) -> Result<Self, Error> {
        let mut config = Config::parse(source, paths, platform)
            .map_err(|error| Error::InvalidConfig(error.reason))?;
        validate_backends(&config)?;
        for backend in &mut config.protocols {
            let BackendSettings::Socks5(socks) = &mut backend.settings else {
                return Err(Error::UnsupportedBackend);
            };
            if let Some((user, source)) = &mut socks.authentication {
                if let PasswordSource::File(path) = source {
                    *source = PasswordSource::Inline(
                        credential::read_secret(path).map_err(Error::Credential)?,
                    );
                }
                validate_credentials(user, source)?;
            }
        }
        let document = canonical_document(&config)?;
        // Materialized defaults add nodes. An admitted source may sit at the
        // source decoder's node boundary, so recheck the stored representation
        // before producing data the service could not decode.
        crate::yaml::decode(&document)
            .map_err(|error| Error::InvalidConfig(Reason::Yaml(error.reason)))?;
        encoded_size(&document, &config)?;
        Ok(Self { document, config })
    }

    /// The returned envelope includes secrets. Only protected storage or the
    /// authenticated installation request may receive its exposed bytes.
    pub fn encode(&self) -> Result<Secret<Vec<u8>>, Error> {
        let size = encoded_size(&self.document, &self.config)?;
        let count = self.config.protocols.iter().filter(|backend| {
            matches!(&backend.settings, BackendSettings::Socks5(socks) if socks.authentication.is_some())
        }).count();
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(b"WMCF");
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&(self.document.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(count as u16).to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.document);
        for (index, backend) in self.config.protocols.iter().enumerate() {
            let BackendSettings::Socks5(socks) = &backend.settings else {
                return Err(Error::UnsupportedBackend);
            };
            if let Some((user, PasswordSource::Inline(password))) = &socks.authentication {
                bytes.extend_from_slice(&(index as u16).to_be_bytes());
                bytes.extend_from_slice(&(user.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&(password.expose().len() as u16).to_be_bytes());
                bytes.extend_from_slice(&[0; 2]);
                bytes.extend_from_slice(user.as_bytes());
                bytes.extend_from_slice(password.expose().as_bytes());
            }
        }
        Ok(Secret::new(bytes))
    }

    /// Pure decoding: no account lookup, file open, environment or networking.
    pub fn decode(bytes: &[u8], platform: Platform) -> Result<Self, Error> {
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < HEADER
            || &bytes[..4] != b"WMCF"
            || bytes[4..8] != 1u32.to_be_bytes()
            || bytes[14..16] != [0; 2]
        {
            return Err(Error::InvalidEnvelope);
        }
        let length = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| Error::InvalidEnvelope)?,
        ) as usize;
        let count = usize::from(u16::from_be_bytes([bytes[12], bytes[13]]));
        if count > MAX_BACKENDS {
            return Err(Error::BackendLimit);
        }
        let end = HEADER.checked_add(length).ok_or(Error::InvalidEnvelope)?;
        let document = bytes.get(HEADER..end).ok_or(Error::InvalidEnvelope)?;
        // Fixed lexical paths satisfy the offline schema API. Canonical managed
        // documents cannot contain any field which causes a file read.
        let account = Account {
            uid: 0,
            name: "managed".into(),
            home: "/".into(),
        };
        let paths = Paths::new(&account, Path::new("/"), Some("/managed.yaml"))
            .map_err(|_| Error::InvalidEnvelope)?;
        let mut config =
            Config::parse(document, &paths, platform).map_err(|_| Error::InvalidEnvelope)?;
        validate_backends(&config)?;
        if canonical_document(&config)? != document {
            return Err(Error::InvalidEnvelope);
        }
        let mut rest = &bytes[end..];
        let mut previous = None;
        for _ in 0..count {
            let header = take(&mut rest, 8)?;
            let index = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let user_length = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let password_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
            if previous.is_some_and(|previous| index <= previous)
                || header[6..8] != [0; 2]
                || !(1..=255).contains(&user_length)
                || !(1..=255).contains(&password_length)
            {
                return Err(Error::InvalidEnvelope);
            }
            let user = std::str::from_utf8(take(&mut rest, user_length)?)
                .map_err(|_| Error::InvalidEnvelope)?
                .to_owned();
            let password = std::str::from_utf8(take(&mut rest, password_length)?)
                .map_err(|_| Error::InvalidEnvelope)?
                .to_owned();
            let backend = config
                .protocols
                .get_mut(index)
                .ok_or(Error::InvalidEnvelope)?;
            let BackendSettings::Socks5(socks) = &mut backend.settings else {
                return Err(Error::UnsupportedBackend);
            };
            socks.authentication = Some((user, PasswordSource::Inline(Secret::new(password))));
            previous = Some(index);
        }
        if !rest.is_empty() {
            return Err(Error::InvalidEnvelope);
        }
        encoded_size(document, &config)?;
        Ok(Self {
            document: document.to_vec(),
            config,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

fn validate_backends(config: &Config) -> Result<(), Error> {
    if config.protocols.is_empty() || config.protocols.len() > MAX_BACKENDS {
        return Err(Error::BackendLimit);
    }
    if config
        .protocols
        .iter()
        .any(|backend| !matches!(&backend.settings, BackendSettings::Socks5(_)))
    {
        return Err(Error::UnsupportedBackend);
    }
    Ok(())
}

fn validate_credentials(user: &str, source: &PasswordSource) -> Result<(), Error> {
    let PasswordSource::Inline(password) = source else {
        return Err(Error::InvalidCredentials);
    };
    if !(1..=255).contains(&user.len()) || !(1..=255).contains(&password.expose().len()) {
        return Err(Error::InvalidCredentials);
    }
    Ok(())
}

fn encoded_size(document: &[u8], config: &Config) -> Result<usize, Error> {
    let mut size = HEADER
        .checked_add(document.len())
        .ok_or(Error::ResourceLimit)?;
    for backend in &config.protocols {
        if let BackendSettings::Socks5(socks) = &backend.settings
            && let Some((user, source)) = &socks.authentication
        {
            validate_credentials(user, source)?;
            let PasswordSource::Inline(password) = source else {
                return Err(Error::InvalidCredentials);
            };
            size = size
                .checked_add(8 + user.len() + password.expose().len())
                .ok_or(Error::ResourceLimit)?;
        }
    }
    if size > MAX_SOURCE_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(size)
}

fn take<'a>(rest: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    let (taken, remaining) = rest
        .split_at_checked(length)
        .ok_or(Error::InvalidEnvelope)?;
    *rest = remaining;
    Ok(taken)
}

fn mapping<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Mapping(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn number(value: impl ToString) -> Value {
    Value::Integer(value.to_string())
}
fn text(value: impl ToString) -> Value {
    Value::String(value.to_string())
}
fn sequence(values: impl IntoIterator<Item = impl ToString>) -> Value {
    Value::Sequence(values.into_iter().map(text).collect())
}

fn canonical_document(config: &Config) -> Result<Vec<u8>, Error> {
    let mut tunnel = BTreeMap::from([
        ("ip".to_owned(), text(config.tunnel.ipv4)),
        ("mtu".to_owned(), number(config.tunnel.mtu)),
        (
            "serve_dns".to_owned(),
            Value::Boolean(config.tunnel.serve_dns),
        ),
    ]);
    if let Some(name) = &config.tunnel.name {
        tunnel.insert("name".into(), text(name));
    }
    if let Some(address) = config.tunnel.ipv6 {
        tunnel.insert("ipv6_address".into(), text(address));
    }
    let mut protocols = Vec::with_capacity(config.protocols.len());
    for backend in &config.protocols {
        let BackendSettings::Socks5(socks) = &backend.settings else {
            return Err(Error::UnsupportedBackend);
        };
        let host = match &socks.endpoint.host {
            Host::Ip(IpAddr::V6(address)) => format!("[{address}]:{}", socks.endpoint.port),
            Host::Ip(address) => format!("{address}:{}", socks.endpoint.port),
            Host::Name(name) => format!("{name}:{}", socks.endpoint.port),
        };
        protocols.push(mapping([
            ("id", text(&backend.id)),
            (
                "socks5",
                mapping([
                    ("host", text(host)),
                    ("domains", sequence(&backend.domains)),
                    (
                        "ips",
                        sequence(
                            backend
                                .routes
                                .iter()
                                .map(|route| format!("{}/{}", route.network, route.prefix_len)),
                        ),
                    ),
                    ("dns", sequence(&backend.dns)),
                    (
                        "routing_mode",
                        text(match backend.routing_mode {
                            RoutingMode::Static => "static",
                            RoutingMode::Dynamic => "dynamic",
                            RoutingMode::Mixed => "mixed",
                        }),
                    ),
                ]),
            ),
        ]));
    }
    let timeouts = &config.timeouts;
    let duration = |value: std::time::Duration| -> Result<Value, Error> {
        Ok(number(
            u64::try_from(value.as_millis()).map_err(|_| Error::ResourceLimit)?,
        ))
    };
    let limits = &config.limits;
    macro_rules! limits { ($($field:ident),+ $(,)?) => { mapping([$( (stringify!($field), number(limits.$field)), )+]) }; }
    let document = mapping([
        ("tunnel", Value::Mapping(tunnel)),
        ("protocols", Value::Sequence(protocols)),
        ("ipv6", Value::Boolean(config.ipv6)),
        (
            "dns",
            mapping([("direct_upstreams", sequence(&config.direct_upstreams))]),
        ),
        (
            "timeouts",
            mapping([
                ("connect_ms", duration(timeouts.connect)?),
                ("dns_ms", duration(timeouts.dns)?),
                ("dns_route_grace_ms", duration(timeouts.dns_route_grace)?),
                ("tcp_idle_ms", duration(timeouts.tcp_idle)?),
                ("udp_idle_ms", duration(timeouts.udp_idle)?),
                ("flow_max_age_ms", duration(timeouts.flow_max_age)?),
                ("shutdown_ms", duration(timeouts.shutdown)?),
                ("control_ms", duration(timeouts.control)?),
            ]),
        ),
        (
            "limits",
            limits!(
                max_tcp_flows,
                max_udp_flows,
                max_dns_requests,
                max_dns_alias_hops,
                max_dns_dependency_queries,
                max_dns_endpoint_addresses,
                max_dns_lease_entries,
                max_dns_cache_entries,
                max_dns_state_bytes_total,
                max_route_entries,
                max_pending_route_ops,
                max_queued_datagrams_per_flow,
                max_buffered_bytes_total,
                max_log_entries,
                max_log_message_bytes,
                max_control_clients,
                max_control_message_bytes,
                max_control_inflight_requests,
                max_control_events_per_client,
                max_control_buffered_bytes_total,
                max_control_operations
            ),
        ),
        (
            "service",
            mapping([("autoconnect", Value::Boolean(config.autoconnect))]),
        ),
    ]);
    let mut output = Vec::new();
    emit(&document, &mut output)?;
    Ok(output)
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_SOURCE_BYTES.saturating_sub(output.len()) {
        return Err(Error::ResourceLimit);
    }
    output.extend_from_slice(bytes);
    Ok(())
}
fn quoted(value: &str, output: &mut Vec<u8>) -> Result<(), Error> {
    append(output, b"\"")?;
    for character in value.chars() {
        match character {
            '"' => append(output, b"\\\"")?,
            '\\' => append(output, b"\\\\")?,
            character
                if character.is_control()
                    || matches!(character, '\u{85}' | '\u{2028}' | '\u{2029}') =>
            {
                append(
                    output,
                    format!("\\u{:04x}", u32::from(character)).as_bytes(),
                )?;
            }
            character => append(output, character.encode_utf8(&mut [0; 4]).as_bytes())?,
        }
    }
    append(output, b"\"")
}
fn emit(value: &Value, output: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::String(value) => quoted(value, output),
        Value::Boolean(value) => append(output, if *value { b"true" } else { b"false" }),
        Value::Integer(value) => append(output, value.as_bytes()),
        Value::Sequence(values) => {
            append(output, b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    append(output, b",")?;
                }
                emit(value, output)?;
            }
            append(output, b"]")
        }
        Value::Mapping(values) => {
            append(output, b"{")?;
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    append(output, b",")?;
                }
                quoted(key, output)?;
                append(output, b":")?;
                emit(value, output)?;
            }
            append(output, b"}")
        }
        Value::Float(_) => Err(Error::InvalidEnvelope),
    }
}
