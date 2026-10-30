// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Backend schema, routing constraints, and credential-source selection.

use std::{fmt, net::IpAddr, path::PathBuf, time::Duration};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use warper_core::{BackendId, configuration::paths::Paths, routing};

use super::{
    Error, Reason,
    fields::{self, Object},
};
use crate::yaml::Value;

const COMMON: &[&str] = &["domains", "ips", "dns", "routing_mode"];
const SSH: &[&str] = &[
    "host",
    "port",
    "user",
    "password",
    "password_file",
    "private_key_file",
    "private_key_passphrase_file",
    "known_hosts",
    "pinned_host_key_sha256",
];
const SOCKS5: &[&str] = &["host", "user", "password", "password_file"];
const WIREGUARD: &[&str] = &[
    "private_key",
    "peer_public_key",
    "preshared_key",
    "endpoint",
    "address",
    "extra_addresses",
    "persistent_keepalive_secs",
    "inner_mtu",
];

#[derive(Clone)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingMode {
    Static,
    Dynamic,
    Mixed,
}

#[derive(Clone)]
pub struct Backend {
    pub id: String,
    pub registry_id: BackendId,
    pub routing_mode: RoutingMode,
    pub domains: Vec<String>,
    pub routes: Vec<routing::Entry>,
    pub dns: Vec<IpAddr>,
    pub settings: BackendSettings,
}

impl Backend {
    pub(super) fn parse(
        value: &Value,
        index: usize,
        registry_id: BackendId,
        ipv6: bool,
        paths: &Paths,
    ) -> Result<Self, Error> {
        let item = Object::new(
            value,
            format!("protocols[{index}]"),
            &["id", "ssh", "socks5", "wireguard"],
        )?;
        let kinds: Vec<_> = ["ssh", "socks5", "wireguard"]
            .into_iter()
            .filter(|name| item.get(name).is_some())
            .collect();
        let [kind] = kinds.as_slice() else {
            return Err(Error::new(&item.path, Reason::BackendCount));
        };
        let id = item
            .string("id")?
            .unwrap_or_else(|| format!("{kind}-{}", index + 1));
        if id.is_empty()
            || id.len() > 64
            || !id.as_bytes()[0].is_ascii_lowercase()
            || !id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            return Err(Error::new(item.field("id"), Reason::InvalidId));
        }
        let specific = match *kind {
            "ssh" => SSH,
            "socks5" => SOCKS5,
            _ => WIREGUARD,
        };
        let allowed: Vec<_> = COMMON.iter().chain(specific).copied().collect();
        let object = Object::new(item.required(kind)?, item.field(kind), &allowed)?;
        let domains = object
            .strings("domains")?
            .iter()
            .enumerate()
            .map(|(index, name)| fields::domain(name, &format!("{}.domains[{index}]", object.path)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut routes = Vec::new();
        for (index, text) in object.strings("ips")?.iter().enumerate() {
            let field = format!("{}.ips[{index}]", object.path);
            let (network, prefix) = text
                .split_once('/')
                .ok_or_else(|| Error::new(&field, Reason::InvalidCidr))?;
            let network: IpAddr = network
                .parse()
                .map_err(|_| Error::new(&field, Reason::InvalidCidr))?;
            let prefix_len: u8 = prefix
                .parse()
                .map_err(|_| Error::new(&field, Reason::InvalidCidr))?;
            if prefix != prefix_len.to_string() {
                return Err(Error::new(&field, Reason::InvalidCidr));
            }
            let route = routing::Entry {
                network,
                prefix_len,
                backend: registry_id,
            };
            routing::Policy::new(&[route], 1)
                .map_err(|_| Error::new(&field, Reason::InvalidCidr))?;
            if network.is_ipv6() && !ipv6 {
                return Err(Error::new(&field, Reason::UnsupportedFamily));
            }
            routes.push(route);
        }
        let dns = fields::addresses(&object, "dns")?;
        if !domains.is_empty() && dns.is_empty() {
            return Err(Error::new(object.field("dns"), Reason::MissingDns));
        }
        if domains.is_empty() && routes.is_empty() {
            return Err(Error::new(&object.path, Reason::MissingRouting));
        }
        let default = if routes.is_empty() {
            "dynamic"
        } else {
            "static"
        };
        let mode = object.string("routing_mode")?;
        let routing_mode = match mode.as_deref().unwrap_or(default) {
            "static" if !routes.is_empty() => RoutingMode::Static,
            "dynamic" if routes.is_empty() && !domains.is_empty() => RoutingMode::Dynamic,
            "mixed" if !routes.is_empty() && !domains.is_empty() => RoutingMode::Mixed,
            _ => {
                return Err(Error::new(
                    object.field("routing_mode"),
                    Reason::RoutingMode,
                ));
            }
        };
        let settings = match *kind {
            "ssh" => BackendSettings::Ssh(Ssh::parse(&object, paths)?),
            "socks5" => BackendSettings::Socks5(Socks5::parse(&object, paths)?),
            _ => BackendSettings::WireGuard(WireGuard::parse(&object)?),
        };
        if let BackendSettings::WireGuard(wireguard) = &settings {
            let has_family = |v4| {
                wireguard
                    .addresses
                    .iter()
                    .any(|address| address.is_ipv4() == v4)
            };
            if (routing_mode != RoutingMode::Static
                && (!has_family(true) || (ipv6 && !has_family(false))))
                || dns.iter().any(|address| !has_family(address.is_ipv4()))
                || routes
                    .iter()
                    .any(|route| !has_family(route.network.is_ipv4()))
            {
                return Err(Error::new(
                    object.field("address"),
                    Reason::UnsupportedFamily,
                ));
            }
        }
        Ok(Self {
            id,
            registry_id,
            routing_mode,
            domains,
            routes,
            dns,
            settings,
        })
    }
}

#[derive(Clone)]
pub enum BackendSettings {
    Ssh(Ssh),
    Socks5(Socks5),
    WireGuard(WireGuard),
}

/// Required protocol behavior, not evidence that a runtime adapter is available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirements {
    pub tcp: bool,
    pub udp: bool,
    pub dns_transport: DnsTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsTransport {
    Tcp,
    UdpWithTcpFallback,
}

impl BackendSettings {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ssh(_) => "ssh",
            Self::Socks5(_) => "socks5",
            Self::WireGuard(_) => "wireguard",
        }
    }

    pub fn requirements(&self) -> Requirements {
        let wireguard = matches!(self, Self::WireGuard(_));
        Requirements {
            tcp: true,
            udp: wireguard,
            dns_transport: if wireguard {
                DnsTransport::UdpWithTcpFallback
            } else {
                DnsTransport::Tcp
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

impl Host {
    fn parse(text: &str, field: &str) -> Result<Self, Error> {
        if let Ok(address) = text.parse() {
            return Ok(Self::Ip(address));
        }
        fields::domain(text, field)
            .map(Self::Name)
            .map_err(|_| Error::new(field, Reason::InvalidHost))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub host: Host,
    pub port: u16,
}

impl Endpoint {
    fn parse(text: &str, field: &str) -> Result<Self, Error> {
        let invalid = || Error::new(field, Reason::InvalidHost);
        let (host, port, bracketed) = if let Some(text) = text.strip_prefix('[') {
            let (host, suffix) = text.split_once(']').ok_or_else(invalid)?;
            (host, suffix.strip_prefix(':').ok_or_else(invalid)?, true)
        } else {
            let (host, port) = text.rsplit_once(':').ok_or_else(invalid)?;
            if host.contains(':') {
                return Err(invalid());
            }
            (host, port, false)
        };
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let port: u16 = port.parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }
        let host = Host::parse(host, field)?;
        if bracketed && !matches!(host, Host::Ip(IpAddr::V6(_))) {
            return Err(invalid());
        }
        Ok(Self { host, port })
    }
}

#[derive(Clone)]
pub enum PasswordSource {
    Inline(Secret<String>),
    File(PathBuf),
}

fn password(
    object: &Object<'_>,
    paths: &Paths,
    max: usize,
) -> Result<Option<PasswordSource>, Error> {
    let inline = object.string("password")?;
    let file = object.path("password_file", paths)?;
    if inline.is_some() && file.is_some() {
        return Err(Error::new(object.field("password"), Reason::Credentials));
    }
    if let Some(text) = inline {
        if text.is_empty() || text.len() > max {
            return Err(Error::new(object.field("password"), Reason::OutOfRange));
        }
        Ok(Some(PasswordSource::Inline(Secret(text))))
    } else {
        Ok(file.map(PasswordSource::File))
    }
}

#[derive(Clone)]
pub enum Authentication {
    Password(PasswordSource),
    PrivateKey {
        file: PathBuf,
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Clone)]
pub enum Trust {
    KnownHosts(PathBuf),
    Sha256([u8; 32]),
}

#[derive(Clone)]
pub struct Ssh {
    pub host: Host,
    pub port: u16,
    pub user: String,
    pub authentication: Authentication,
    pub trust: Trust,
}

impl Ssh {
    fn parse(object: &Object<'_>, paths: &Paths) -> Result<Self, Error> {
        let host = Host::parse(&object.required_string("host")?, &object.field("host"))?;
        let port = object.number("port", 22, 1, 65535)? as u16;
        let user = object.required_string("user")?;
        if user.is_empty() {
            return Err(Error::new(object.field("user"), Reason::OutOfRange));
        }
        let password = password(object, paths, usize::MAX)?;
        let private_key = object.path("private_key_file", paths)?;
        let passphrase_file = object.path("private_key_passphrase_file", paths)?;
        if passphrase_file.is_some() && private_key.is_none() {
            return Err(Error::new(
                object.field("private_key_passphrase_file"),
                Reason::Credentials,
            ));
        }
        let authentication = match (password, private_key) {
            (Some(password), None) => Authentication::Password(password),
            (None, Some(file)) => Authentication::PrivateKey {
                file,
                passphrase_file,
            },
            _ => return Err(Error::new(object.field("password"), Reason::Credentials)),
        };
        let known_hosts = object.path("known_hosts", paths)?;
        let pin = object.string("pinned_host_key_sha256")?;
        let trust = match (known_hosts, pin) {
            (Some(_), Some(_)) => {
                return Err(Error::new(
                    object.field("known_hosts"),
                    Reason::TrustConflict,
                ));
            }
            (_, Some(pin)) => {
                let field = object.field("pinned_host_key_sha256");
                let text = pin
                    .strip_prefix("SHA256:")
                    .ok_or_else(|| Error::new(&field, Reason::InvalidKey))?;
                Trust::Sha256(decode_key(text, &STANDARD_NO_PAD, &field)?)
            }
            (known_hosts, None) => {
                let file = match known_hosts {
                    Some(file) => file,
                    None => paths.resolve_value("~/.ssh/known_hosts").map_err(|error| {
                        Error::new(object.field("known_hosts"), Reason::Path(error))
                    })?,
                };
                Trust::KnownHosts(file)
            }
        };
        Ok(Self {
            host,
            port,
            user,
            authentication,
            trust,
        })
    }
}

#[derive(Clone)]
pub struct Socks5 {
    pub endpoint: Endpoint,
    pub authentication: Option<(String, PasswordSource)>,
}

impl Socks5 {
    fn parse(object: &Object<'_>, paths: &Paths) -> Result<Self, Error> {
        let endpoint = Endpoint::parse(&object.required_string("host")?, &object.field("host"))?;
        let user = object.string("user")?;
        if user
            .as_ref()
            .is_some_and(|user| user.is_empty() || user.len() > 255)
        {
            return Err(Error::new(object.field("user"), Reason::OutOfRange));
        }
        let password = password(object, paths, 255)?;
        let authentication = match (user, password) {
            (None, None) => None,
            (Some(user), Some(password)) => Some((user, password)),
            (Some(_), None) => {
                return Err(Error::new(object.field("password"), Reason::Credentials));
            }
            (None, Some(_)) => return Err(Error::new(object.field("user"), Reason::Credentials)),
        };
        Ok(Self {
            endpoint,
            authentication,
        })
    }
}

#[derive(Clone)]
pub struct WireGuard {
    pub private_key: Secret<[u8; 32]>,
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<Secret<[u8; 32]>>,
    pub endpoint: Endpoint,
    pub addresses: Vec<IpAddr>,
    pub persistent_keepalive: Duration,
    pub inner_mtu: Option<u16>,
}

impl WireGuard {
    fn parse(object: &Object<'_>) -> Result<Self, Error> {
        let private_key = Secret(decode_key(
            &object.required_string("private_key")?,
            &STANDARD,
            &object.field("private_key"),
        )?);
        let peer_public_key = decode_key(
            &object.required_string("peer_public_key")?,
            &STANDARD,
            &object.field("peer_public_key"),
        )?;
        if peer_public_key == [0; 32] {
            return Err(Error::new(
                object.field("peer_public_key"),
                Reason::ZeroPeerKey,
            ));
        }
        let preshared_key = object
            .string("preshared_key")?
            .map(|text| decode_key(&text, &STANDARD, &object.field("preshared_key")).map(Secret))
            .transpose()?;
        let endpoint = Endpoint::parse(
            &object.required_string("endpoint")?,
            &object.field("endpoint"),
        )?;
        let primary = fields::local_address(
            &object.required_string("address")?,
            &object.field("address"),
        )?;
        let mut addresses = vec![primary];
        for (index, text) in object.strings("extra_addresses")?.iter().enumerate() {
            let field = format!("{}.extra_addresses[{index}]", object.path);
            let address = fields::local_address(text, &field)?;
            if addresses
                .iter()
                .any(|previous| previous.is_ipv4() == address.is_ipv4())
            {
                return Err(Error::new(field, Reason::DuplicateAddress));
            }
            addresses.push(address);
        }
        let persistent_keepalive =
            Duration::from_secs(object.number("persistent_keepalive_secs", 5, 0, 65535)?);
        let minimum = if addresses.iter().any(IpAddr::is_ipv6) {
            1280
        } else {
            576
        };
        let inner_mtu = if object.get("inner_mtu").is_some() {
            Some(object.number("inner_mtu", 1280, minimum, 9000)? as u16)
        } else {
            None
        };
        Ok(Self {
            private_key,
            peer_public_key,
            preshared_key,
            endpoint,
            addresses,
            persistent_keepalive,
            inner_mtu,
        })
    }
}

fn decode_key(
    text: &str,
    engine: &base64::engine::GeneralPurpose,
    field: &str,
) -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    match engine.decode_slice(text, &mut bytes) {
        Ok(32) => Ok(bytes),
        _ => Err(Error::new(field, Reason::InvalidKey)),
    }
}

// Credential usernames and source paths are sensitive too. Keep Debug safe even
// when a caller logs one backend or credential source rather than the root.
macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => {$(
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($type), "(<redacted>)"))
            }
        }
    )+};
}

redacted_debug!(
    Backend,
    BackendSettings,
    PasswordSource,
    Authentication,
    Trust,
    Ssh,
    Socks5,
    WireGuard
);
