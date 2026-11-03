// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded link observations for conflict and journal ownership inspection.
//! Names, indices and aliases alone do not establish an owned generation.

use super::{QueryError as Error, netlink};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage},
};
use std::{fmt, num::NonZeroU32};
use warper_core::transport::Request;

#[derive(Clone, Copy)]
pub enum Query<'a> {
    Name(&'a str),
    Index(NonZeroU32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Loopback,
    Ethernet,
    Veth,
    Tun,
    Other,
}

/// Retains at most 15 name bytes and 255 alias bytes; Debug omits native values.
/// Kind::Other makes no assertion that an interface is physical or usable.
#[derive(Clone, Eq, PartialEq)]
pub struct Observation {
    pub index: NonZeroU32,
    pub name: String,
    pub alias: Option<String>,
    pub kind: Kind,
    pub layer_type: u16,
    pub mtu: NonZeroU32,
    pub flags: u32,
}
impl fmt::Debug for Observation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LinkObservation(<native link metadata>)")
    }
}

/// A single current-namespace query, using the same bounded transport and total
/// deadline as route lookup. No interface is created, renamed or modified.
pub async fn lookup(query: Query<'_>, request: Request) -> Result<Observation, Error> {
    netlink::bounded(request, async {
        let mut message = LinkMessage::default();
        match query {
            Query::Name(name) if valid_name(name) => {
                message
                    .attributes
                    .push(LinkAttribute::IfName(name.to_owned()));
            }
            Query::Index(index) if index.get() <= i32::MAX as u32 => {
                message.header.index = index.get()
            }
            _ => return Err(Error::InvalidInput),
        }
        match netlink::exchange(RouteNetlinkMessage::GetLink(message)).await? {
            RouteNetlinkMessage::NewLink(message) => observation(message, query),
            _ => Err(Error::InvalidReply),
        }
    })
    .await
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.is_ascii()
        && !matches!(name, "." | "..")
        && !name
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, 0 | b'/' | b':'))
}

fn observation(message: LinkMessage, query: Query<'_>) -> Result<Observation, Error> {
    let index = NonZeroU32::new(message.header.index).ok_or(Error::InvalidReply)?;
    let mut name = None;
    let mut alias = None;
    let mut mtu = None;
    let mut info = None;
    for attribute in message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => once(&mut name, value)?,
            LinkAttribute::IfAlias(value) => once(&mut alias, value)?,
            LinkAttribute::Mtu(value) => once(&mut mtu, value)?,
            LinkAttribute::LinkInfo(value) => once(&mut info, value)?,
            // Other attributes are not used as an identity or permission. The
            // shared receive bound limits their transient parse allocations.
            _ => {}
        }
    }
    let name = name
        .filter(|value| valid_name(value))
        .ok_or(Error::UnsupportedLink)?;
    if alias
        .as_ref()
        .is_some_and(|value| value.len() > 255 || value.contains('\0'))
    {
        return Err(Error::UnsupportedLink);
    }
    if match query {
        Query::Name(expected) => name != expected,
        Query::Index(expected) => index != expected,
    } {
        return Err(Error::InvalidReply);
    }
    let mut info_kind = None;
    for info in info.unwrap_or_default() {
        if let LinkInfo::Kind(kind) = info {
            once(&mut info_kind, kind)?;
        }
    }
    let kind = match (message.header.link_layer_type, info_kind) {
        (LinkLayerType::Loopback, None) if message.header.flags.contains(LinkFlags::Loopback) => {
            Kind::Loopback
        }
        (LinkLayerType::Ether, None) => Kind::Ethernet,
        (LinkLayerType::Ether, Some(InfoKind::Veth)) => Kind::Veth,
        (LinkLayerType::None, Some(InfoKind::Tun)) => Kind::Tun,
        (LinkLayerType::Loopback, _) | (_, Some(InfoKind::Tun)) => {
            return Err(Error::UnsupportedLink);
        }
        _ => Kind::Other,
    };
    Ok(Observation {
        index,
        name,
        alias,
        kind,
        layer_type: message.header.link_layer_type.into(),
        mtu: mtu
            .and_then(NonZeroU32::new)
            .ok_or(Error::UnsupportedLink)?,
        flags: message.header.flags.bits(),
    })
}

fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::InvalidReply);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{sync::watch, time::Instant};

    fn sample() -> LinkMessage {
        let mut message = LinkMessage::default();
        message.header.index = 9;
        message.header.link_layer_type = LinkLayerType::None;
        message.attributes = vec![
            LinkAttribute::IfName("warper-test".into()),
            LinkAttribute::Mtu(1280),
            LinkAttribute::IfAlias("warper:invented-owner".into()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Tun)]),
        ];
        message
    }
    fn index() -> Query<'static> {
        Query::Index(NonZeroU32::new(9).unwrap())
    }
    fn request() -> (watch::Sender<bool>, Request) {
        let (owner, cancellation) = watch::channel(false);
        (
            owner,
            Request {
                deadline: Instant::now() + Duration::from_secs(2),
                cancellation,
            },
        )
    }

    #[test]
    fn observations_preserve_owner_comparison_fields_without_debug_disclosure() {
        let observed = observation(sample(), index()).unwrap();
        assert_eq!(observed.name, "warper-test");
        assert_eq!(observed.alias.as_deref(), Some("warper:invented-owner"));
        assert_eq!(observed.kind, Kind::Tun);
        assert_eq!(observed.mtu.get(), 1280);
        assert_eq!(
            format!("{observed:?}"),
            "LinkObservation(<native link metadata>)"
        );
        assert_eq!(
            observation(sample(), Query::Name("warper-test")).unwrap(),
            observed
        );
        assert_eq!(
            observation(sample(), Query::Name("another-name")),
            Err(Error::InvalidReply)
        );
        assert_eq!(
            observation(sample(), Query::Index(NonZeroU32::new(10).unwrap())),
            Err(Error::InvalidReply)
        );
        let mut other = sample();
        other.header.link_layer_type = LinkLayerType::Ether;
        assert_eq!(
            observation(other.clone(), index()),
            Err(Error::UnsupportedLink),
            "a TAP must not become a TUN"
        );
        other
            .attributes
            .retain(|attribute| !matches!(attribute, LinkAttribute::LinkInfo(_)));
        assert_eq!(
            observation(other.clone(), index()).unwrap().kind,
            Kind::Ethernet
        );
        other
            .attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Veth,
            )]));
        assert_eq!(
            observation(other.clone(), index()).unwrap().kind,
            Kind::Veth
        );
        other
            .attributes
            .retain(|attribute| !matches!(attribute, LinkAttribute::LinkInfo(_)));
        other
            .attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Bridge,
            )]));
        assert_eq!(observation(other, index()).unwrap().kind, Kind::Other);
    }

    #[test]
    fn ambiguous_or_unbounded_link_metadata_is_rejected() {
        for attribute in sample().attributes {
            let mut changed = sample();
            changed.attributes.push(attribute);
            assert_eq!(observation(changed, index()), Err(Error::InvalidReply));
        }
        for name in [
            "",
            ".",
            "..",
            "bad/name",
            "bad:name",
            "bad name",
            "bad\0name",
            "échantillon",
            "1234567890123456",
        ] {
            assert!(!valid_name(name), "name validation case");
            let mut changed = sample();
            changed.attributes[0] = LinkAttribute::IfName(name.into());
            assert_eq!(observation(changed, index()), Err(Error::UnsupportedLink));
        }
        for alias in ["x".repeat(256), "bad\0alias".into()] {
            let mut changed = sample();
            changed.attributes[2] = LinkAttribute::IfAlias(alias);
            assert_eq!(observation(changed, index()), Err(Error::UnsupportedLink));
        }
        let mut changed = sample();
        changed.header.index = 0;
        assert_eq!(observation(changed, index()), Err(Error::InvalidReply));
        let mut changed = sample();
        changed.attributes[1] = LinkAttribute::Mtu(0);
        assert_eq!(observation(changed, index()), Err(Error::UnsupportedLink));
        let mut changed = sample();
        changed.attributes[3] = LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Tun),
            LinkInfo::Kind(InfoKind::Tun),
        ]);
        assert_eq!(observation(changed, index()), Err(Error::InvalidReply));
        let mut changed = sample();
        changed
            .attributes
            .retain(|attribute| !matches!(attribute, LinkAttribute::IfName(_)));
        assert_eq!(observation(changed, index()), Err(Error::UnsupportedLink));
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_link_queries_and_expired_requests_fail_before_socket_io() {
        for query in [
            Query::Name("bad/name"),
            Query::Index(NonZeroU32::new(u32::MAX).unwrap()),
        ] {
            let (_owner, request) = request();
            assert_eq!(lookup(query, request).await, Err(Error::InvalidInput));
        }
        let (_owner, mut request) = request();
        request.deadline = Instant::now();
        assert_eq!(
            lookup(Query::Name("lo"), request).await,
            Err(Error::Timeout)
        );
    }

    #[tokio::test]
    async fn native_loopback_link_is_correlated_by_name_and_index() {
        let (_owner, request) = request();
        let named = lookup(Query::Name("lo"), request).await.unwrap();
        assert_eq!(named.kind, Kind::Loopback);
        assert_eq!(named.name, "lo");
        let (_owner, request) = self::request();
        let indexed = lookup(Query::Index(named.index), request).await.unwrap();
        assert_eq!(named, indexed);
    }

    #[tokio::test]
    #[ignore = "controlled release workload"]
    async fn native_loopback_link_workload() {
        fn cpu_ns() -> i128 {
            let time = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
            i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec)
        }
        let (owner, _) = watch::channel(false);
        let started = Instant::now();
        let cpu = cpu_ns();
        let mut latencies = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let before = Instant::now();
            let observed = lookup(
                Query::Name("lo"),
                Request {
                    deadline: before + Duration::from_secs(2),
                    cancellation: owner.subscribe(),
                },
            )
            .await
            .unwrap();
            assert_eq!(observed.kind, Kind::Loopback);
            latencies.push(before.elapsed().as_nanos());
        }
        let elapsed_ns = started.elapsed().as_nanos();
        let cpu_ns = cpu_ns() - cpu;
        latencies.sort_unstable();
        let memory = std::fs::read_to_string("/proc/self/status").unwrap();
        let peak = memory
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .unwrap();
        let mut message = LinkMessage::default();
        message.attributes.push(LinkAttribute::IfName("lo".into()));
        let request_bytes = netlink::request_packet(RouteNetlinkMessage::GetLink(message), 7, 42)
            .unwrap()
            .len()
            * 1000;
        println!(
            "iterations=1000 concurrency=1 elapsed_ns={elapsed_ns} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} netlink_request_bytes={request_bytes} app_bytes=0 failures=0 lost_replies=0 {peak}",
            latencies[499], latencies[949], latencies[989]
        );
    }

    #[test]
    fn shared_transport_rejects_mutation_and_oversized_requests() {
        assert_eq!(
            netlink::request_packet(RouteNetlinkMessage::NewLink(sample()), 7, 42),
            Err(Error::InvalidInput)
        );
        let mut oversized = sample();
        oversized
            .attributes
            .push(LinkAttribute::IfAlias("x".repeat(128)));
        assert_eq!(
            netlink::request_packet(RouteNetlinkMessage::GetLink(oversized), 7, 42),
            Err(Error::ResourceLimit)
        );
    }
}
