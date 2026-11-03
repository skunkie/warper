// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use netlink_packet_route::{route::RouteProtocol, rule::RuleFlags};
use std::time::Duration;
use tokio::{sync::watch, time::Instant};

fn sample(priority: u32, table: u8) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.table = table;
    message.header.action = RuleAction::ToTable;
    message.attributes = vec![
        RuleAttribute::Priority(priority),
        RuleAttribute::Table(u32::from(table)),
        RuleAttribute::SuppressPrefixLen(u32::MAX),
        RuleAttribute::Protocol(RouteProtocol::Kernel),
    ];
    message
}
fn empty() -> Inventory {
    Inventory {
        rules: 0,
        tables: 0,
        unsupported: false,
    }
}
fn observe(inventory: &mut Inventory, priority: u32, table: u8) {
    inventory
        .observe(RouteNetlinkMessage::NewRule(sample(priority, table)))
        .unwrap();
}

#[test]
fn only_exactly_three_unconditional_rules_admit_the_default_layout() {
    let mut inventory = empty();
    assert!(!inventory.is_default_layout());
    observe(&mut inventory, 32767, 253);
    observe(&mut inventory, 0, 255);
    assert!(!inventory.is_default_layout());
    observe(&mut inventory, 32766, 254);
    assert_eq!(inventory.rules(), 3);
    assert!(inventory.is_default_layout());
    observe(&mut inventory, 0, 255);
    assert!(!inventory.is_default_layout());
    let mut duplicate = empty();
    observe(&mut duplicate, 0, 255);
    observe(&mut duplicate, 0, 255);
    observe(&mut duplicate, 32767, 253);
    assert!(!duplicate.is_default_layout());
    assert_eq!(
        format!("{duplicate:?}"),
        "Inventory { rules: 3, tables: 5, unsupported: true }"
    );
    let mut local = sample(0, 255);
    local.attributes.clear();
    assert_eq!(table_bit(local), Ok(Some(1)));
    let mut large_table = sample(0, 0);
    large_table.attributes = vec![RuleAttribute::Table(1000)];
    assert_eq!(table_bit(large_table), Ok(None));
    assert_eq!(table_bit(sample(0, 0)), Ok(None));
    assert_eq!(table_bit(sample(1, 255)), Ok(None));
}

#[test]
fn selectors_suppression_and_non_lookup_actions_are_observed_as_unsupported() {
    for attribute in [
        RuleAttribute::FwMark(1),
        RuleAttribute::FwMask(1),
        RuleAttribute::Iifname("fixture".into()),
        RuleAttribute::Oifname("fixture".into()),
        RuleAttribute::Source(std::net::Ipv4Addr::LOCALHOST.into()),
        RuleAttribute::Destination(std::net::Ipv4Addr::LOCALHOST.into()),
        RuleAttribute::L3MDev(false),
        RuleAttribute::Goto(32766),
        RuleAttribute::SuppressIfGroup(u32::MAX),
    ] {
        let mut message = sample(32766, 254);
        message.attributes.push(attribute);
        assert_eq!(table_bit(message), Ok(None));
    }
    let mut message = sample(32766, 254);
    message
        .attributes
        .retain(|attribute| !matches!(attribute, RuleAttribute::SuppressPrefixLen(_)));
    message.attributes.push(RuleAttribute::SuppressPrefixLen(0));
    assert_eq!(table_bit(message), Ok(None));
    for action in [
        RuleAction::Blackhole,
        RuleAction::Goto,
        RuleAction::Unreachable,
        RuleAction::Nop,
    ] {
        let mut message = sample(32766, 254);
        message.header.action = action;
        assert_eq!(table_bit(message), Ok(None));
    }
    for field in 0..4 {
        let mut message = sample(32766, 254);
        match field {
            0 => message.header.dst_len = 24,
            1 => message.header.src_len = 24,
            2 => message.header.tos = 1,
            _ => message.header.flags = RuleFlags::Invert,
        }
        assert_eq!(table_bit(message), Ok(None));
    }
    let mut inventory = empty();
    observe(&mut inventory, 0, 255);
    observe(&mut inventory, 32766, 254);
    observe(&mut inventory, 32767, 253);
    observe(&mut inventory, 1, 100);
    assert!(!inventory.is_default_layout());
}

#[test]
fn duplicate_and_malformed_comparison_fields_reject_the_dump() {
    for attribute in sample(0, 255).attributes {
        let mut message = sample(0, 255);
        message.attributes.push(attribute);
        assert_eq!(table_bit(message), Err(Cause::Protocol));
    }
    for field in 0..4 {
        let mut message = sample(0, 255);
        match field {
            0 => message.header.family = AddressFamily::Inet6,
            1 => message.header.dst_len = 33,
            2 => message.header.src_len = 33,
            _ => message.header.table = 254,
        }
        assert_eq!(table_bit(message), Err(Cause::Protocol));
    }
    let mut inventory = empty();
    assert_eq!(
        inventory.observe(RouteNetlinkMessage::GetRule(sample(0, 255))),
        Err(Cause::Protocol)
    );
    for _ in 0..MAX_RULES {
        observe(&mut inventory, 0, 255);
    }
    assert_eq!(inventory.rules(), MAX_RULES);
    assert_eq!(
        inventory.observe(RouteNetlinkMessage::NewRule(sample(0, 255))),
        Err(Cause::ResourceLimit)
    );
}

#[test]
fn native_rule_dump_is_read_only_and_custom_host_layout_is_not_assumed() {
    let (_owner, cancellation) = watch::channel(false);
    let inventory = inspect(Request {
        deadline: Instant::now() + Duration::from_secs(2),
        cancellation,
    })
    .unwrap();
    assert!(inventory.rules() > 0 && inventory.rules() <= MAX_RULES);
    if inventory.is_default_layout() {
        assert_eq!(inventory.rules(), 3);
    }
}

#[test]
fn expired_and_lost_owner_requests_fail_before_rule_inspection() {
    let (owner, cancellation) = watch::channel(false);
    assert_eq!(
        inspect(Request {
            deadline: Instant::now(),
            cancellation: cancellation.clone()
        }),
        Err(Error::Timeout)
    );
    owner.send(true).unwrap();
    assert_eq!(
        inspect(Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation: cancellation.clone()
        }),
        Err(Error::Cancelled)
    );
    drop(owner);
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
#[ignore = "controlled release workload"]
fn native_rule_inventory_workload() {
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
        entries += inventory.rules();
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
        "iterations=100 concurrency=1 observed_rules={entries} elapsed_ns={elapsed} cpu_ns={cpu} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 kernel_drops=unmeasured {peak}",
        latencies[49], latencies[94], latencies[98]
    );
}
