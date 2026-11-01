// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use netlink_packet_route::route::{RouteFlags, RouteProtocol, RouteScope, RouteType};
use std::time::Duration;
use tokio::{sync::watch, time::Instant};

fn sample() -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = AddressFamily::Inet;
    message.header.destination_prefix_length = 24;
    message.header.table = 254;
    message.header.protocol = RouteProtocol::Static;
    message.header.scope = RouteScope::Link;
    message.header.kind = RouteType::Unicast;
    message.attributes = vec![
        RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(192, 0, 2, 0))),
        RouteAttribute::Table(254),
        RouteAttribute::Oif(9),
        RouteAttribute::Priority(123),
    ];
    message
}

#[test]
fn compact_routes_preserve_exact_metadata_and_default_and_large_tables() {
    let mut message = sample();
    message.attributes.extend([
        RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(198, 51, 100, 1))),
        RouteAttribute::PrefSource(RouteAddress::Inet(Ipv4Addr::new(198, 51, 100, 2))),
    ]);
    let observed = entry(message).unwrap();
    assert_eq!(
        observed,
        Entry {
            network: Ipv4Addr::new(192, 0, 2, 0),
            prefix_len: 24,
            table: NonZeroU32::new(254).unwrap(),
            interface: NonZeroU32::new(9),
            metric: Some(123),
            preferred_source: Some(Ipv4Addr::new(198, 51, 100, 2)),
            gateway: Some(Ipv4Addr::new(198, 51, 100, 1)),
            protocol: 4,
            scope: 253,
            kind: 1,
            exact: true,
        }
    );
    assert_eq!(format!("{observed:?}"), "Entry(<native route metadata>)");
    let mut message = sample();
    message.header.destination_prefix_length = 0;
    message.header.table = 0;
    message.attributes = vec![RouteAttribute::Table(1000)];
    let observed = entry(message).unwrap();
    assert_eq!(observed.network, Ipv4Addr::UNSPECIFIED);
    assert_eq!(observed.prefix_len, 0);
    assert_eq!(observed.table.get(), 1000);
    assert_eq!(observed.interface, None);
    assert!(observed.exact);
}

#[test]
fn extra_route_semantics_remain_visible_but_prevent_exact_comparison() {
    for attribute in [
        RouteAttribute::Mark(1),
        RouteAttribute::NhId(4),
        RouteAttribute::Metrics(vec![]),
        RouteAttribute::MultiPath(vec![]),
    ] {
        let mut message = sample();
        message.attributes.push(attribute);
        let observed = entry(message).unwrap();
        assert_eq!(observed.network, Ipv4Addr::new(192, 0, 2, 0));
        assert!(!observed.exact);
    }
    let mut message = sample();
    message.header.flags = RouteFlags::Linkdown;
    assert!(!entry(message).unwrap().exact);
    let mut message = sample();
    message.header.source_prefix_length = 24;
    assert!(!entry(message).unwrap().exact);
    let mut message = sample();
    message.header.tos = 1;
    assert!(!entry(message).unwrap().exact);
}

#[test]
fn ambiguous_or_unrepresentable_keys_never_become_a_partial_inventory() {
    for attribute in sample().attributes {
        let mut message = sample();
        message.attributes.push(attribute);
        assert_eq!(entry(message), Err(Cause::Protocol));
    }
    for attributes in [
        vec![],
        vec![RouteAttribute::Destination(RouteAddress::Inet(
            Ipv4Addr::new(192, 0, 2, 1),
        ))],
        vec![RouteAttribute::Destination(RouteAddress::Inet6(
            std::net::Ipv6Addr::LOCALHOST,
        ))],
    ] {
        let mut message = sample();
        message.attributes = attributes;
        assert_eq!(entry(message), Err(Cause::Protocol));
    }
    let mut message = sample();
    message.attributes[1] = RouteAttribute::Table(1000);
    assert_eq!(entry(message), Err(Cause::Protocol));
    let mut message = sample();
    message.attributes[2] = RouteAttribute::Oif(0);
    assert_eq!(entry(message), Err(Cause::Protocol));
    let mut message = sample();
    message.header.destination_prefix_length = 33;
    assert_eq!(entry(message), Err(Cause::Protocol));
    let mut message = sample();
    message.header.address_family = AddressFamily::Inet6;
    assert_eq!(entry(message), Err(Cause::Protocol));
    let mut message = sample();
    message.header.table = 0;
    message
        .attributes
        .retain(|attribute| !matches!(attribute, RouteAttribute::Table(_)));
    assert_eq!(entry(message), Err(Cause::Protocol));
}

#[test]
fn read_only_native_dump_includes_loopback_and_no_external_traffic() {
    let (_owner, cancellation) = watch::channel(false);
    let inventory = inspect(Request {
        deadline: Instant::now() + Duration::from_secs(2),
        cancellation,
    })
    .unwrap();
    assert!(inventory.entries().len() <= MAX_ROUTES);
    assert!(
        inventory
            .entries()
            .iter()
            .any(|route| route.table.get() == 255
                && route.kind == 2
                && route.network == Ipv4Addr::LOCALHOST
                && route.prefix_len == 32)
    );
    assert_eq!(
        format!("{inventory:?}"),
        "Inventory(<native route metadata>)"
    );
}

#[test]
fn expired_cancelled_and_lost_owner_requests_fail_before_opening_socket() {
    let (owner, cancellation) = watch::channel(false);
    assert_eq!(
        inspect(Request {
            deadline: Instant::now(),
            cancellation: cancellation.clone()
        }),
        Err(Error::Timeout)
    );
    assert_eq!(
        inspect(Request {
            deadline: Instant::now() + Duration::from_secs(31),
            cancellation: cancellation.clone()
        }),
        Err(Error::InvalidInput)
    );
    owner.send(true).unwrap();
    assert_eq!(
        inspect(Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation
        }),
        Err(Error::Cancelled)
    );
    let (owner, cancellation) = watch::channel(false);
    drop(owner);
    assert_eq!(
        inspect(Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation
        }),
        Err(Error::Cancelled)
    );
}

#[test]
fn full_inventory_refuses_more_entries_and_unexpected_messages() {
    let mut inventory = Inventory {
        entries: Vec::new(),
    };
    assert_eq!(
        inventory.observe(RouteNetlinkMessage::GetRoute(sample())),
        Err(Cause::Protocol)
    );
    for _ in 0..MAX_ROUTES {
        inventory
            .observe(RouteNetlinkMessage::NewRoute(sample()))
            .unwrap();
    }
    assert_eq!(
        inventory.observe(RouteNetlinkMessage::NewRoute(sample())),
        Err(Cause::ResourceLimit)
    );
    assert_eq!(inventory.entries().len(), MAX_ROUTES);
}

#[test]
#[ignore = "controlled release workload"]
fn native_inventory_workload() {
    fn cpu_ns() -> i128 {
        let value = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec)
    }
    let (owner, _) = watch::channel(false);
    let started = Instant::now();
    let cpu = cpu_ns();
    let mut latencies = Vec::with_capacity(100);
    let mut entries = 0;
    for _ in 0..100 {
        let before = Instant::now();
        let inventory = inspect(Request {
            deadline: before + Duration::from_secs(2),
            cancellation: owner.subscribe(),
        })
        .unwrap();
        entries += inventory.entries().len();
        latencies.push(before.elapsed().as_nanos());
    }
    let elapsed = started.elapsed().as_nanos();
    let cpu = cpu_ns() - cpu;
    latencies.sort_unstable();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let peak = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .unwrap();
    println!(
        "iterations=100 concurrency=1 observed_entries={entries} elapsed_ns={elapsed} cpu_ns={cpu} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 kernel_drops=unmeasured {peak}",
        latencies[49], latencies[94], latencies[98]
    );
}
