// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One bounded IPv4 TCP route lookup, without host mutation or cached authority.
//! Every call owns its socket; cancellation/drop closes it without a detached task.

use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU32,
    sync::atomic::{AtomicU32, Ordering},
};

use super::netlink::{self, MAX_DATAGRAM};
use netlink_packet_core::{
    NLM_F_MULTIPART, NLM_F_REQUEST, NetlinkBuffer, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteType},
};
use netlink_sys::{AsyncSocket, SocketAddr as NetlinkAddr};
use nix::errno::Errno;
use tokio::time::sleep_until;
use warper_core::transport::Request;

const MAX_REQUEST: usize = 128;
// IPv4's rtmsg also reports RTCF_LOCAL from linux/in_route.h. This is not an
// unknown link-health flag; accept it only together with the Local route kind.
const RTCF_LOCAL: u32 = 0x80000000;
// Port IDs can be reused after close. Never reuse a sequence within this process.
static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInput,
    ResourceLimit,
    Cancelled,
    Timeout,
    Socket(Errno),
    Io(io::ErrorKind),
    UnexpectedSender,
    InvalidReply,
    Lost,
    UnsupportedRoute,
    Kernel(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "InvalidConfig: invalid IPv4 TCP route query",
            Self::ResourceLimit => "ResourceLimit: native route lookup capacity exhausted",
            Self::Cancelled => "Cancelled: native route lookup cancelled",
            Self::Timeout => "Timeout: native route lookup deadline expired",
            Self::Socket(_) | Self::Io(_) => "NativeIo: route lookup failed",
            Self::UnexpectedSender => "NativeProtocol: route reply is not from the kernel",
            Self::InvalidReply => "NativeProtocol: invalid or uncorrelated route reply",
            Self::Lost => "NativeUncertain: route reply lost or truncated",
            Self::UnsupportedRoute => "UnsupportedIntegration: route lookup cannot be represented",
            Self::Kernel(_) => "NativeRejected: kernel rejected route lookup",
        })
    }
}
impl std::error::Error for Error {}

/// The tuple must describe the prospective service socket, including its actual
/// source port when available. UID is taken from this process, never the caller.
#[derive(Clone, Copy)]
pub struct Query {
    pub destination: SocketAddrV4,
    pub source: Option<SocketAddrV4>,
    pub interface: Option<NonZeroU32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Unicast,
    Local,
}

/// A single kernel observation. It neither authorizes a send nor proves a
/// physical interface identity, exemption, snapshot consistency or route lifetime.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Observation {
    pub interface: NonZeroU32,
    pub source: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub table: NonZeroU32,
    pub kind: Kind,
}
impl fmt::Debug for Observation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Observation(<native route metadata>)")
    }
}

/// No process, network mutation, name resolution, subscription or background task
/// is created. The caller must bound concurrent lookups and retain their futures.
pub async fn lookup(query: Query, request: Request) -> Result<Observation, Error> {
    bounded(request, exchange(query)).await
}

async fn bounded<T>(
    mut request: Request,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    tokio::select! { biased;
        _ = request.cancellation.wait_for(|cancelled| *cancelled) => Err(Error::Cancelled),
        () = sleep_until(request.deadline) => Err(Error::Timeout),
        result = operation => result,
    }
}

async fn exchange(query: Query) -> Result<Observation, Error> {
    validate(query)?;
    let sequence = NEXT_SEQUENCE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| Error::ResourceLimit)?;
    let (socket, port) = netlink::socket(0).map_err(|error| match error {
        netlink::Error::Io(error) => socket_error(error),
        netlink::Error::ResourceLimit => Error::ResourceLimit,
        netlink::Error::InvalidSocket => Error::InvalidReply,
    })?;
    let packet = request_packet(query, sequence, port)?;
    let length = poll_fn(|context| socket.poll_send_to(context, &packet, &NetlinkAddr::new(0, 0)))
        .await
        .map_err(socket_error)?;
    if length != packet.len() {
        return Err(Error::InvalidReply);
    }
    // A fixed slice cannot grow through BufMut. The extra byte makes every
    // oversized/truncated datagram fail closed, even if its prefix is valid.
    let mut buffer = [0; MAX_DATAGRAM + 1];
    let mut remaining = &mut buffer[..];
    let sender = poll_fn(|context| socket.poll_recv_from(context, &mut remaining))
        .await
        .map_err(socket_error)?;
    let length = MAX_DATAGRAM + 1 - remaining.len();
    decode(&buffer[..length], Some(sender), sequence, port, query)
}

fn validate(query: Query) -> Result<(), Error> {
    fn unicast(address: &Ipv4Addr) -> bool {
        !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
    }
    if !unicast(query.destination.ip())
        || query.destination.port() == 0
        || query
            .source
            .is_some_and(|source| !unicast(source.ip()) || source.port() == 0)
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn request_packet(query: Query, sequence: u32, port: u32) -> Result<Vec<u8>, Error> {
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.destination_prefix_length = 32;
    route.header.flags = RouteFlags::LookupTable;
    route.attributes = vec![
        RouteAttribute::Destination(RouteAddress::Inet(*query.destination.ip())),
        RouteAttribute::Uid(rustix::process::geteuid().as_raw()),
        RouteAttribute::IpProto(6),
        RouteAttribute::Dport(query.destination.port()),
    ];
    if let Some(source) = query.source {
        route.header.source_prefix_length = 32;
        route
            .attributes
            .push(RouteAttribute::Source(RouteAddress::Inet(*source.ip())));
        route.attributes.push(RouteAttribute::Sport(source.port()));
    }
    if let Some(interface) = query.interface {
        route.attributes.push(RouteAttribute::Oif(interface.get()));
    }
    let mut packet = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    packet.header.flags = NLM_F_REQUEST;
    packet.header.sequence_number = sequence;
    packet.header.port_number = port;
    packet.finalize();
    if packet.buffer_len() > MAX_REQUEST {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = vec![0; packet.buffer_len()];
    packet.serialize(&mut bytes);
    Ok(bytes)
}

fn socket_error(error: io::Error) -> Error {
    match error.raw_os_error() {
        Some(code) if code == Errno::ENOBUFS as i32 => Error::Lost,
        Some(code) => Error::Socket(Errno::from_raw(code)),
        None => Error::Io(error.kind()),
    }
}

fn decode(
    bytes: &[u8],
    sender: Option<NetlinkAddr>,
    sequence: u32,
    port: u32,
    query: Query,
) -> Result<Observation, Error> {
    if sender.is_none_or(|sender| sender.port_number() != 0 || sender.multicast_groups() != 0) {
        return Err(Error::UnexpectedSender);
    }
    if bytes.len() > MAX_DATAGRAM {
        return Err(Error::Lost);
    }
    let buffer = NetlinkBuffer::new_checked(bytes).map_err(|_| Error::InvalidReply)?;
    // A unicast GETROUTE reply must contain exactly one complete message. Do not
    // accept a valid prefix while ignoring another message or untrusted tail.
    if buffer.length() as usize != bytes.len() {
        return Err(Error::InvalidReply);
    }
    let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
        .map_err(|_| Error::InvalidReply)?;
    if message.header.sequence_number != sequence
        || message.header.port_number != port
        || message.header.flags & NLM_F_MULTIPART != 0
    {
        return Err(Error::InvalidReply);
    }
    match message.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
            observation(route, query)
        }
        NetlinkPayload::Error(error) => match error.raw_code() {
            code if code < 0 && code != i32::MIN => Err(Error::Kernel(-code)),
            _ => Err(Error::InvalidReply),
        },
        NetlinkPayload::Overrun(_) => Err(Error::Lost),
        _ => Err(Error::InvalidReply),
    }
}

fn observation(route: RouteMessage, query: Query) -> Result<Observation, Error> {
    if route.header.address_family != AddressFamily::Inet
        || route.header.destination_prefix_length != 32
        || !matches!(route.header.source_prefix_length, 0 | 32)
        || !(route.header.flags - RouteFlags::Cloned - RouteFlags::from_bits_retain(RTCF_LOCAL))
            .is_empty()
    {
        return Err(Error::UnsupportedRoute);
    }
    let kind = match route.header.kind {
        RouteType::Unicast => Kind::Unicast,
        RouteType::Local => Kind::Local,
        _ => return Err(Error::UnsupportedRoute),
    };
    if route.header.flags.bits() & RTCF_LOCAL != 0 && kind != Kind::Local {
        return Err(Error::UnsupportedRoute);
    }
    let mut destination = None;
    let mut source = None;
    let mut preferred = None;
    let mut interface = None;
    let mut gateway = None;
    let mut table = None;
    let mut uid = None;
    let mut protocol = None;
    let mut source_port = None;
    let mut destination_port = None;
    for attribute in route.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(value)) => {
                once(&mut destination, value)?
            }
            RouteAttribute::Source(RouteAddress::Inet(value)) => once(&mut source, value)?,
            RouteAttribute::PrefSource(RouteAddress::Inet(value)) => once(&mut preferred, value)?,
            RouteAttribute::Gateway(RouteAddress::Inet(value)) => once(&mut gateway, value)?,
            RouteAttribute::Oif(value) => once(&mut interface, value)?,
            RouteAttribute::Table(value) => once(&mut table, value)?,
            RouteAttribute::Uid(value) => once(&mut uid, value)?,
            RouteAttribute::IpProto(value) => once(&mut protocol, value)?,
            RouteAttribute::Sport(value) => once(&mut source_port, value)?,
            RouteAttribute::Dport(value) => once(&mut destination_port, value)?,
            RouteAttribute::CacheInfo(_)
            | RouteAttribute::Priority(_)
            | RouteAttribute::Metrics(_) => {}
            _ => return Err(Error::UnsupportedRoute),
        }
    }
    if uid.is_some_and(|value| value != rustix::process::geteuid().as_raw())
        || protocol.is_some_and(|value| value != 6)
        || source_port.is_some_and(|value| query.source.is_none_or(|source| value != source.port()))
        || destination_port.is_some_and(|value| value != query.destination.port())
        || destination != Some(*query.destination.ip())
        || source.is_some_and(|source| query.source.is_none_or(|expected| *expected.ip() != source))
        || query
            .source
            .is_some_and(|expected| preferred.is_some_and(|value| value != *expected.ip()))
        || (route.header.source_prefix_length == 32) != source.is_some()
    {
        return Err(Error::InvalidReply);
    }
    let interface = interface
        .and_then(NonZeroU32::new)
        .ok_or(Error::UnsupportedRoute)?;
    if query
        .interface
        .is_some_and(|expected| interface != expected)
    {
        return Err(Error::InvalidReply);
    }
    let source = query
        .source
        .map(|source| *source.ip())
        .or(preferred)
        .ok_or(Error::UnsupportedRoute)?;
    let table = table.unwrap_or(u32::from(route.header.table));
    if source.is_unspecified()
        || source.is_multicast()
        || source.is_broadcast()
        || gateway.is_some_and(|value| {
            value.is_unspecified() || value.is_multicast() || value.is_broadcast()
        })
        || (route.header.table != 0 && table != u32::from(route.header.table))
    {
        return Err(Error::UnsupportedRoute);
    }
    Ok(Observation {
        interface,
        source,
        gateway,
        table: NonZeroU32::new(table).ok_or(Error::UnsupportedRoute)?,
        kind,
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
    use netlink_packet_core::{ErrorMessage, NetlinkHeader};
    use std::{cell::Cell, future::pending, num::NonZeroI32, time::Duration};
    use tokio::{sync::watch, time::Instant};

    fn query() -> Query {
        Query {
            destination: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080),
            source: None,
            interface: None,
        }
    }
    fn route() -> RouteMessage {
        let mut route = RouteMessage::default();
        route.header.address_family = AddressFamily::Inet;
        route.header.destination_prefix_length = 32;
        route.header.kind = RouteType::Local;
        route.header.table = 255;
        route.header.flags = RouteFlags::Cloned;
        route.attributes = vec![
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::LOCALHOST)),
            RouteAttribute::PrefSource(RouteAddress::Inet(Ipv4Addr::LOCALHOST)),
            RouteAttribute::Oif(1),
            RouteAttribute::Table(255),
        ];
        route
    }
    fn packet(payload: NetlinkPayload<RouteNetlinkMessage>) -> Vec<u8> {
        let mut message = NetlinkMessage::new(NetlinkHeader::default(), payload);
        message.header.sequence_number = 7;
        message.header.port_number = 42;
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        bytes
    }
    fn response(route: RouteMessage) -> Vec<u8> {
        packet(NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(
            route,
        )))
    }
    fn parse(bytes: &[u8]) -> Result<Observation, Error> {
        decode(bytes, Some(NetlinkAddr::new(0, 0)), 7, 42, query())
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
    fn request_preserves_tuple_and_process_identity_without_dump_or_ack() {
        let query = Query {
            source: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            interface: NonZeroU32::new(1),
            ..query()
        };
        let bytes = request_packet(query, 7, 42).unwrap();
        assert!(bytes.len() <= MAX_REQUEST);
        let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes).unwrap();
        assert_eq!(message.header.flags, NLM_F_REQUEST);
        assert_eq!(message.header.sequence_number, 7);
        assert_eq!(message.header.port_number, 42);
        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(route)) = message.payload
        else {
            panic!("query must be a read-only route lookup");
        };
        assert_eq!(route.header.source_prefix_length, 32);
        assert_eq!(route.header.flags, RouteFlags::LookupTable);
        for attribute in [
            RouteAttribute::Uid(rustix::process::geteuid().as_raw()),
            RouteAttribute::Source(RouteAddress::Inet(Ipv4Addr::LOCALHOST)),
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::LOCALHOST)),
            RouteAttribute::Oif(1),
            RouteAttribute::IpProto(6),
            RouteAttribute::Sport(12345),
            RouteAttribute::Dport(1080),
        ] {
            assert!(
                route.attributes.contains(&attribute),
                "missing tuple or UID attribute"
            );
        }
    }

    #[test]
    fn route_reply_requires_kernel_sender_exact_envelope_and_correlation() {
        let bytes = response(route());
        for sender in [
            None,
            Some(NetlinkAddr::new(1, 0)),
            Some(NetlinkAddr::new(0, 1)),
        ] {
            assert_eq!(
                decode(&bytes, sender, 7, 42, query()),
                Err(Error::UnexpectedSender)
            );
        }
        for end in 0..bytes.len() {
            assert_eq!(
                parse(&bytes[..end]),
                Err(Error::InvalidReply),
                "truncated length {end}"
            );
        }
        let mut extra = bytes.clone();
        extra.extend_from_slice(&bytes);
        assert_eq!(parse(&extra), Err(Error::InvalidReply));
        assert_eq!(parse(&vec![0; MAX_DATAGRAM + 1]), Err(Error::Lost));
        for (offset, value) in [(4, 0xffffu32), (8, 8), (12, 43)] {
            let mut changed = bytes.clone();
            changed[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            assert_eq!(parse(&changed), Err(Error::InvalidReply));
        }
        let mut multipart = bytes;
        multipart[6..8].copy_from_slice(&NLM_F_MULTIPART.to_ne_bytes());
        assert_eq!(parse(&multipart), Err(Error::InvalidReply));
    }

    #[test]
    fn kernel_rejections_are_typed_and_ack_is_not_route_success() {
        for code in [-19, -101, 0, 1, i32::MIN] {
            let mut error = ErrorMessage::default();
            error.code = NonZeroI32::new(code);
            let expected = if code < 0 && code != i32::MIN {
                Error::Kernel(-code)
            } else {
                Error::InvalidReply
            };
            assert_eq!(parse(&packet(NetlinkPayload::Error(error))), Err(expected));
        }
        assert_eq!(
            parse(&packet(NetlinkPayload::Noop)),
            Err(Error::InvalidReply)
        );
        assert_eq!(
            parse(&packet(NetlinkPayload::Overrun(vec![]))),
            Err(Error::Lost)
        );
        assert_eq!(
            parse(&packet(NetlinkPayload::Done(Default::default()))),
            Err(Error::InvalidReply)
        );
    }

    #[test]
    fn unsupported_and_ambiguous_routes_never_become_observations() {
        let expected = Observation {
            interface: NonZeroU32::new(1).unwrap(),
            source: Ipv4Addr::LOCALHOST,
            gateway: None,
            table: NonZeroU32::new(255).unwrap(),
            kind: Kind::Local,
        };
        assert_eq!(parse(&response(route())), Ok(expected));
        for attribute in route().attributes {
            let mut changed = route();
            changed.attributes.push(attribute);
            assert_eq!(parse(&response(changed)), Err(Error::InvalidReply));
        }
        for attribute in [RouteAttribute::NhId(1), RouteAttribute::Mark(1)] {
            let mut changed = route();
            changed.attributes.push(attribute);
            assert_eq!(parse(&response(changed)), Err(Error::UnsupportedRoute));
        }
        let mut changed = route();
        changed.header.flags |= RouteFlags::Linkdown;
        assert_eq!(parse(&response(changed)), Err(Error::UnsupportedRoute));
        let mut changed = route();
        changed.header.kind = RouteType::BlackHole;
        assert_eq!(parse(&response(changed)), Err(Error::UnsupportedRoute));
        let mut changed = route();
        changed
            .attributes
            .retain(|attribute| !matches!(attribute, RouteAttribute::Oif(_)));
        assert_eq!(parse(&response(changed)), Err(Error::UnsupportedRoute));
        let mut changed = route();
        changed.header.table = 254;
        assert_eq!(parse(&response(changed)), Err(Error::UnsupportedRoute));
        let mut changed = route();
        changed.attributes[0] =
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(parse(&response(changed)), Err(Error::InvalidReply));
        assert_eq!(
            decode(
                &response(route()),
                Some(NetlinkAddr::new(0, 0)),
                7,
                42,
                Query {
                    interface: NonZeroU32::new(2),
                    ..query()
                }
            ),
            Err(Error::InvalidReply)
        );
    }

    #[test]
    fn source_and_gateway_validation_preserves_the_requested_tuple() {
        let mut sample = route();
        sample.header.source_prefix_length = 32;
        sample
            .attributes
            .push(RouteAttribute::Source(RouteAddress::Inet(
                Ipv4Addr::LOCALHOST,
            )));
        let query = Query {
            source: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            ..query()
        };
        let bytes = response(sample.clone());
        assert!(decode(&bytes, Some(NetlinkAddr::new(0, 0)), 7, 42, query).is_ok());
        assert_eq!(parse(&bytes), Err(Error::InvalidReply));
        sample
            .attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(
                Ipv4Addr::BROADCAST,
            )));
        assert_eq!(
            decode(
                &response(sample),
                Some(NetlinkAddr::new(0, 0)),
                7,
                42,
                query
            ),
            Err(Error::UnsupportedRoute)
        );
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert_eq!(
                validate(Query {
                    destination: SocketAddrV4::new(address, 1080),
                    ..query
                }),
                Err(Error::InvalidInput)
            );
            assert_eq!(
                validate(Query {
                    source: Some(SocketAddrV4::new(address, 12345)),
                    ..query
                }),
                Err(Error::InvalidInput)
            );
        }
        assert_eq!(
            validate(Query {
                destination: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                ..query
            }),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn unicast_gateway_and_returned_tuple_require_consistent_metadata() {
        let query = Query {
            destination: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 1080),
            source: Some(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 12345)),
            interface: NonZeroU32::new(2),
        };
        let mut sample = route();
        sample.header.kind = RouteType::Unicast;
        sample.header.table = 254;
        sample.attributes = vec![
            RouteAttribute::Destination(RouteAddress::Inet(*query.destination.ip())),
            RouteAttribute::PrefSource(RouteAddress::Inet(*query.source.unwrap().ip())),
            RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(192, 0, 2, 1))),
            RouteAttribute::Oif(2),
            RouteAttribute::Table(254),
            RouteAttribute::Uid(rustix::process::geteuid().as_raw()),
            RouteAttribute::IpProto(6),
            RouteAttribute::Sport(12345),
            RouteAttribute::Dport(1080),
        ];
        let parse = |route| decode(&response(route), Some(NetlinkAddr::new(0, 0)), 7, 42, query);
        let observed = parse(sample.clone()).unwrap();
        assert_eq!(observed.kind, Kind::Unicast);
        assert_eq!(observed.gateway, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(observed.source, *query.source.unwrap().ip());
        assert_eq!(
            format!("{observed:?}"),
            "Observation(<native route metadata>)"
        );
        for attribute in [
            RouteAttribute::IpProto(17),
            RouteAttribute::Sport(12346),
            RouteAttribute::Dport(1081),
        ] {
            let mut changed = sample.clone();
            changed.attributes.retain(|value| {
                std::mem::discriminant(value) != std::mem::discriminant(&attribute)
            });
            changed.attributes.push(attribute);
            assert_eq!(parse(changed), Err(Error::InvalidReply));
        }
        for attribute in &sample.attributes {
            let mut changed = sample.clone();
            changed.attributes.push(attribute.clone());
            assert_eq!(parse(changed), Err(Error::InvalidReply));
        }
        sample.header.flags |= RouteFlags::from_bits_retain(RTCF_LOCAL);
        assert_eq!(parse(sample), Err(Error::UnsupportedRoute));
        assert_eq!(
            socket_error(io::Error::from_raw_os_error(Errno::ENOBUFS as i32)),
            Error::Lost
        );
        assert_eq!(
            socket_error(io::Error::from_raw_os_error(Errno::EPERM as i32)),
            Error::Socket(Errno::EPERM)
        );
        assert_eq!(
            socket_error(io::Error::from(io::ErrorKind::Other)),
            Error::Io(io::ErrorKind::Other)
        );
        assert!(!Error::InvalidReply.to_string().contains("203.0.113"));
    }

    #[tokio::test]
    #[ignore = "controlled release workload"]
    async fn native_loopback_lookup_workload() {
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
                query(),
                Request {
                    deadline: before + Duration::from_secs(2),
                    cancellation: owner.subscribe(),
                },
            )
            .await
            .unwrap();
            assert_eq!(observed.kind, Kind::Local);
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
        println!(
            "iterations=1000 concurrency=1 elapsed_ns={elapsed_ns} cpu_ns={cpu_ns} p50_ns={} p95_ns={} p99_ns={} netlink_request_bytes={} app_bytes=0 failures=0 lost_replies=0 {peak}",
            latencies[499],
            latencies[949],
            latencies[989],
            request_packet(query(), 7, 42).unwrap().len() * 1000
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_cancellation_and_owner_loss_do_not_start_io() {
        let (_owner, mut request) = request();
        request.deadline = Instant::now();
        let polled = Cell::new(false);
        assert_eq!(
            bounded(request, async {
                polled.set(true);
                Ok(())
            })
            .await,
            Err(Error::Timeout)
        );
        assert!(!polled.get());
        let (owner, request) = self::request();
        owner.send(true).unwrap();
        assert_eq!(
            bounded(request, async {
                polled.set(true);
                Ok(())
            })
            .await,
            Err(Error::Cancelled)
        );
        assert!(!polled.get());
        let (owner, request) = self::request();
        drop(owner);
        assert_eq!(
            bounded(request, pending::<Result<(), Error>>()).await,
            Err(Error::Cancelled)
        );
        let (_owner, request) = self::request();
        assert_eq!(
            bounded(request, pending::<Result<(), Error>>()).await,
            Err(Error::Timeout)
        );
    }

    #[tokio::test]
    async fn native_loopback_lookup_and_bound_tuple_use_real_kernel_replies() {
        let (_owner, request) = request();
        let observed = lookup(query(), request).await.unwrap();
        assert_eq!(observed.source, Ipv4Addr::LOCALHOST);
        assert_eq!(observed.kind, Kind::Local);
        assert_eq!(observed.gateway, None);
        let (_owner, request) = self::request();
        let constrained = lookup(
            Query {
                source: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
                interface: Some(observed.interface),
                ..query()
            },
            request,
        )
        .await
        .unwrap();
        assert_eq!(observed, constrained);
        let (_owner, request) = self::request();
        assert_eq!(
            lookup(
                Query {
                    interface: NonZeroU32::new(u32::MAX),
                    ..query()
                },
                request
            )
            .await,
            Err(Error::Kernel(Errno::ENODEV as i32))
        );
    }
}
