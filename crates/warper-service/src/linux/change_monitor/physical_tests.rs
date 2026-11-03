// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::{
    tests::{event, kernel, packet},
    *,
};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{
    AddressFamily,
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteProtocol, RouteScope, RouteType},
    rule::RuleMessage,
};

fn physical() -> PhysicalPath {
    PhysicalPath {
        capture_interface: NonZeroU32::new(9).unwrap(),
        endpoint: Ipv4Addr::new(192, 0, 2, 2),
        source: Ipv4Addr::new(192, 0, 2, 1),
        gateway: Some(Ipv4Addr::new(192, 0, 2, 254)),
    }
}
fn capture() -> RouteMessage {
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.destination_prefix_length = 32;
    route.header.table = 254;
    route.header.protocol = RouteProtocol::Static;
    route.header.scope = RouteScope::Link;
    route.header.kind = RouteType::Unicast;
    route.attributes = vec![
        RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(203, 0, 113, 9))),
        RouteAttribute::Oif(9),
        RouteAttribute::Priority(0x80000001),
    ];
    route
}
fn classify_route(route: RouteMessage) -> Result<(), Invalidation> {
    classify(
        &event(RouteNetlinkMessage::NewRoute(route)),
        kernel(),
        Some(physical()),
    )
}

#[test]
fn disjoint_capture_host_additions_and_deletions_preserve_only_scoped_monitors() {
    let mut route = capture();
    for explicit_table in [false, true] {
        if explicit_table {
            route.attributes.push(RouteAttribute::Table(254));
        }
        for message in [
            RouteNetlinkMessage::NewRoute(route.clone()),
            RouteNetlinkMessage::DelRoute(route.clone()),
        ] {
            let bytes = event(message);
            assert_eq!(classify(&bytes, kernel(), Some(physical())), Ok(()));
            assert_eq!(
                classify(&bytes, kernel(), None),
                Err(Invalidation::NetworkChanged)
            );
        }
    }
}

#[test]
fn broader_ambiguous_or_different_routes_still_invalidate_physical_paths() {
    struct Case {
        id: &'static str,
        change: fn(&mut RouteMessage),
    }
    let cases = [
        Case {
            id: "broader prefix",
            change: |route| route.header.destination_prefix_length = 24,
        },
        Case {
            id: "another family",
            change: |route| route.header.address_family = AddressFamily::Inet6,
        },
        Case {
            id: "source selector",
            change: |route| route.header.source_prefix_length = 1,
        },
        Case {
            id: "tos selector",
            change: |route| route.header.tos = 1,
        },
        Case {
            id: "route flags",
            change: |route| route.header.flags = RouteFlags::from_bits_retain(1),
        },
        Case {
            id: "another table",
            change: |route| route.header.table = 253,
        },
        Case {
            id: "different protocol",
            change: |route| route.header.protocol = RouteProtocol::Kernel,
        },
        Case {
            id: "different scope",
            change: |route| route.header.scope = RouteScope::Universe,
        },
        Case {
            id: "different kind",
            change: |route| route.header.kind = RouteType::BlackHole,
        },
        Case {
            id: "missing destination",
            change: |route| {
                route.attributes.remove(0);
            },
        },
        Case {
            id: "duplicate destination",
            change: |route| route.attributes.push(route.attributes[0].clone()),
        },
        Case {
            id: "another interface",
            change: |route| route.attributes[1] = RouteAttribute::Oif(10),
        },
        Case {
            id: "zero interface",
            change: |route| route.attributes[1] = RouteAttribute::Oif(0),
        },
        Case {
            id: "missing interface",
            change: |route| {
                route.attributes.remove(1);
            },
        },
        Case {
            id: "duplicate interface",
            change: |route| route.attributes.push(RouteAttribute::Oif(9)),
        },
        Case {
            id: "foreign metric",
            change: |route| route.attributes[2] = RouteAttribute::Priority(1),
        },
        Case {
            id: "missing metric",
            change: |route| {
                route.attributes.pop();
            },
        },
        Case {
            id: "duplicate metric",
            change: |route| route.attributes.push(RouteAttribute::Priority(0x80000001)),
        },
        Case {
            id: "conflicting table",
            change: |route| route.attributes.push(RouteAttribute::Table(253)),
        },
        Case {
            id: "duplicate table",
            change: |route| {
                route
                    .attributes
                    .extend([RouteAttribute::Table(254), RouteAttribute::Table(254)])
            },
        },
        Case {
            id: "preferred source",
            change: |route| {
                route
                    .attributes
                    .push(RouteAttribute::PrefSource(RouteAddress::Inet(
                        physical().source,
                    )))
            },
        },
        Case {
            id: "gateway",
            change: |route| {
                route
                    .attributes
                    .push(RouteAttribute::Gateway(RouteAddress::Inet(
                        physical().gateway.unwrap(),
                    )))
            },
        },
        Case {
            id: "unknown routing metadata",
            change: |route| route.attributes.push(RouteAttribute::Metrics(vec![])),
        },
    ];
    for case in cases {
        let mut route = capture();
        (case.change)(&mut route);
        assert!(classify_route(route).is_err(), "{}", case.id);
    }
}

#[test]
fn capture_targets_cannot_replace_any_physical_path_address() {
    let path = physical();
    for address in [path.endpoint, path.source, path.gateway.unwrap()] {
        let mut route = capture();
        route.attributes[0] = RouteAttribute::Destination(RouteAddress::Inet(address));
        assert_eq!(classify_route(route), Err(Invalidation::NetworkChanged));
    }
    let path = PhysicalPath {
        gateway: None,
        ..path
    };
    assert_eq!(
        classify(
            &event(RouteNetlinkMessage::NewRoute(capture())),
            kernel(),
            Some(path)
        ),
        Ok(())
    );
}

#[test]
fn ignored_prefix_never_hides_relevant_malformed_or_lost_batch_tail() {
    let bytes = event(RouteNetlinkMessage::NewRoute(capture()));
    for count in [1, 2, MAX_MESSAGES] {
        assert_eq!(
            classify(&bytes.repeat(count), kernel(), Some(physical())),
            Ok(())
        );
    }
    assert_eq!(
        classify(&bytes.repeat(MAX_MESSAGES + 1), kernel(), Some(physical())),
        Err(Invalidation::NotificationLost)
    );
    let tails = [
        (
            event(RouteNetlinkMessage::NewRule(RuleMessage::default())),
            Invalidation::NetworkChanged,
        ),
        (vec![0], Invalidation::InvalidMessage),
        (
            packet(NetlinkPayload::Overrun(vec![])),
            Invalidation::NotificationLost,
        ),
    ];
    for (tail, expected) in tails {
        let mut batch = bytes.clone();
        batch.extend(tail);
        assert_eq!(classify(&batch, kernel(), Some(physical())), Err(expected));
    }
    assert_eq!(
        classify(&bytes, SocketAddr::new(1, 0), Some(physical())),
        Err(Invalidation::UnexpectedSender)
    );
    for end in 0..bytes.len() {
        assert!(
            classify(&bytes[..end], kernel(), Some(physical())).is_err(),
            "short input {end}"
        );
    }
}
