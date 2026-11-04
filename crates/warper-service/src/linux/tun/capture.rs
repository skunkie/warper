// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Exclusive capture metadata, conflict inspection and kernel requests.

use super::{
    Error,
    transaction::{self, Wait},
};
use crate::linux::{route_inventory, rule_inventory};
use netlink_packet_core::{NLM_F_CREATE, NLM_F_EXCL};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
};
use warper_core::transport::Request;
use warper_stack::runtime::Publication;

pub(super) const MAX_PREFIXES: usize = crate::preflight::MAX_CAPTURE_ROUTES;
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Prefix {
    pub(super) network: Ipv4Addr,
    pub(super) length: u8,
}
#[derive(Clone, Eq, PartialEq)]
pub(super) struct Plan {
    pub(super) prefixes: Vec<Prefix>,
    pub(super) metric: u32,
}
impl Plan {
    pub(super) fn extend_host(
        previous: Option<&Self>,
        address: Ipv4Addr,
        metric: u32,
    ) -> Result<(Self, bool), Error> {
        if !super::record::valid_address(address) {
            return Err(Error::InvalidCapturePolicy);
        }
        if let Some(previous) = previous {
            previous.validate()?;
            if previous.metric != metric {
                return Err(Error::Conflict);
            }
            if previous
                .prefixes
                .iter()
                .any(|prefix| u32::from(address) & mask(prefix.length) == u32::from(prefix.network))
            {
                return Ok((previous.clone(), false));
            }
            if previous.prefixes.len() == MAX_PREFIXES {
                return Err(Error::InvalidCapturePolicy);
            }
        }
        let mut prefixes = previous.map_or_else(Vec::new, |plan| plan.prefixes.clone());
        prefixes.push(Prefix {
            network: address,
            length: 32,
        });
        prefixes.sort_unstable_by(|first, second| {
            second
                .length
                .cmp(&first.length)
                .then_with(|| first.network.cmp(&second.network))
        });
        let plan = Self { prefixes, metric };
        plan.validate()?;
        Ok((plan, true))
    }
    pub(super) fn new(publication: &Publication, metric: u32) -> Result<Self, Error> {
        if !publication.is_published() || publication.is_quiescent() {
            return Err(Error::InvalidState);
        }
        let entries = publication.entries();
        if entries.is_empty() || entries.len() > MAX_PREFIXES {
            return Err(Error::InvalidCapturePolicy);
        }
        let prefixes = entries
            .iter()
            .map(|entry| match entry.network {
                IpAddr::V4(network) => Ok(Prefix {
                    network,
                    length: entry.prefix_len,
                }),
                IpAddr::V6(_) => Err(Error::InvalidCapturePolicy),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let plan = Self { prefixes, metric };
        plan.validate()?;
        Ok(plan)
    }
    pub(super) fn without_host(&self, address: Ipv4Addr) -> Result<(Option<Self>, bool), Error> {
        self.validate()?;
        if !super::record::valid_address(address) {
            return Err(Error::InvalidCapturePolicy);
        }
        let mut remaining = self.clone();
        let position = remaining
            .prefixes
            .iter()
            .position(|prefix| prefix.length == 32 && prefix.network == address);
        let Some(position) = position else {
            return Ok((Some(remaining), false));
        };
        remaining.prefixes.remove(position);
        Ok(((!remaining.prefixes.is_empty()).then_some(remaining), true))
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.prefixes.is_empty()
            || self.prefixes.len() > MAX_PREFIXES
            || self.metric & 0x80000000 == 0
        {
            return Err(Error::InvalidCapturePolicy);
        }
        for prefix in &self.prefixes {
            if prefix.length > 32
                || u32::from(prefix.network) & mask(prefix.length) != u32::from(prefix.network)
            {
                return Err(Error::InvalidCapturePolicy);
            }
        }
        if self.prefixes.windows(2).any(|pair| {
            pair[0].length < pair[1].length
                || (pair[0].length == pair[1].length && pair[0].network >= pair[1].network)
        }) {
            return Err(Error::InvalidCapturePolicy);
        }
        Ok(())
    }
    pub(super) fn inspect(
        &self,
        index: u32,
        request: Request,
        committed: bool,
    ) -> Result<(), Error> {
        let wait = Wait::new(request.clone()).map_err(super::capture_cause)?;
        if !rule_inventory::inspect(request.clone())
            .map_err(Error::RouteInspection)?
            .is_default_layout()
        {
            return Err(Error::UnsupportedRules);
        }
        let inventory = route_inventory::inspect(request).map_err(Error::RouteInspection)?;
        self.verify_entries(index, inventory.entries(), committed, &wait)
    }
    pub(super) fn inspect_absence(&self, request: Request) -> Result<(), Error> {
        let inventory = route_inventory::inspect(request).map_err(Error::RouteInspection)?;
        self.verify_absence(inventory.entries())
    }
    fn verify_absence(&self, entries: &[route_inventory::Entry]) -> Result<(), Error> {
        if self.prefixes.iter().any(|prefix| {
            entries.iter().any(|entry| {
                entry.table.get() == 254
                    && entry.network == prefix.network
                    && entry.prefix_len == prefix.length
                    && entry.metric == Some(self.metric)
            })
        }) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn verify_entries(
        &self,
        index: u32,
        entries: &[route_inventory::Entry],
        committed: bool,
        wait: &Wait,
    ) -> Result<(), Error> {
        let mut counts = vec![0u8; self.prefixes.len()];
        for entry in entries {
            wait.check().map_err(super::capture_cause)?;
            if committed
                && let Ok(position) = self.prefixes.binary_search_by(|prefix| {
                    entry
                        .prefix_len
                        .cmp(&prefix.length)
                        .then_with(|| prefix.network.cmp(&entry.network))
                })
                && exact(self.prefixes[position], self.metric, index, entry)
            {
                if counts[position] != 0 {
                    return Err(Error::Conflict);
                }
                counts[position] = 1;
                continue;
            }
            for prefix in &self.prefixes {
                let overlaps = u32::from(prefix.network)
                    & mask(prefix.length.min(entry.prefix_len))
                    == u32::from(entry.network) & mask(prefix.length.min(entry.prefix_len));
                if overlaps
                    && (entry.table.get() == 255
                        || (matches!(entry.table.get(), 253 | 254)
                            && entry.prefix_len >= prefix.length))
                {
                    return Err(Error::Conflict);
                }
            }
        }
        if committed && counts.contains(&0) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
fn mask(length: u8) -> u32 {
    u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0)
}
fn exact(prefix: Prefix, metric: u32, index: u32, entry: &route_inventory::Entry) -> bool {
    entry.network == prefix.network
        && entry.prefix_len == prefix.length
        && entry.table.get() == 254
        && entry.interface == NonZeroU32::new(index)
        && entry.metric == Some(metric)
        && entry.preferred_source.is_none()
        && entry.gateway.is_none()
        && entry.protocol == 4
        && entry.scope == 253
        && entry.kind == 1
        && entry.exact
}
fn message(prefix: Prefix, metric: u32, index: u32, add: bool) -> RouteNetlinkMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = AddressFamily::Inet;
    message.header.destination_prefix_length = prefix.length;
    message.header.table = 254;
    message.header.protocol = RouteProtocol::Static;
    message.header.scope = RouteScope::Link;
    message.header.kind = RouteType::Unicast;
    message.attributes = vec![
        RouteAttribute::Destination(RouteAddress::Inet(prefix.network)),
        RouteAttribute::Oif(index),
        RouteAttribute::Priority(metric),
    ];
    if add {
        RouteNetlinkMessage::NewRoute(message)
    } else {
        RouteNetlinkMessage::DelRoute(message)
    }
}
pub(super) fn add(prefix: Prefix, metric: u32, index: u32, wait: &Wait) -> Result<(), Error> {
    transaction::mutate(
        message(prefix, metric, index, true),
        NLM_F_CREATE | NLM_F_EXCL,
        wait,
    )
    .map_err(Error::Capture)
}
pub(super) fn remove(
    plan: &Plan,
    index: u32,
    request: Request,
    wait: &Wait,
    check_owner: impl Fn() -> Result<(), Error>,
) -> Result<(), Error> {
    for prefix in &plan.prefixes {
        wait.check().map_err(super::capture_cause)?;
        check_owner()?;
        let mut changes =
            crate::linux::change_monitor::Monitor::subscribe().map_err(Error::CaptureMonitor)?;
        let inventory =
            route_inventory::inspect(request.clone()).map_err(Error::RouteInspection)?;
        let mut owned = 0;
        for entry in inventory.entries().iter().filter(|entry| {
            entry.table.get() == 254
                && entry.network == prefix.network
                && entry.prefix_len == prefix.length
                && entry.metric == Some(plan.metric)
        }) {
            if !exact(*prefix, plan.metric, index, entry) {
                return Err(Error::Conflict);
            }
            owned += 1;
        }
        match owned {
            0 => {}
            1 => {
                check_owner()?;
                changes.check_pending().map_err(Error::CaptureChanged)?;
                transaction::mutate(message(*prefix, plan.metric, index, false), 0, wait)
                    .map_err(Error::Capture)?;
            }
            _ => return Err(Error::Conflict),
        }
    }
    plan.inspect_absence(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{sync::watch, time::Instant};

    fn plan() -> Plan {
        Plan {
            prefixes: vec![
                Prefix {
                    network: Ipv4Addr::new(198, 18, 0, 2),
                    length: 32,
                },
                Prefix {
                    network: Ipv4Addr::new(198, 18, 0, 0),
                    length: 24,
                },
            ],
            metric: 0x80000001,
        }
    }
    fn owned(prefix: Prefix) -> route_inventory::Entry {
        route_inventory::Entry {
            network: prefix.network,
            prefix_len: prefix.length,
            table: NonZeroU32::new(254).unwrap(),
            interface: NonZeroU32::new(9),
            metric: Some(plan().metric),
            preferred_source: None,
            gateway: None,
            protocol: 4,
            scope: 253,
            kind: 1,
            exact: true,
        }
    }
    fn verify(
        plan: &Plan,
        entries: &[route_inventory::Entry],
        committed: bool,
    ) -> Result<(), Error> {
        let (_owner, cancellation) = watch::channel(false);
        let wait = Wait::new(Request {
            deadline: Instant::now() + Duration::from_secs(2),
            cancellation,
        })
        .unwrap();
        plan.verify_entries(9, entries, committed, &wait)
    }
    #[test]
    fn host_extensions_reuse_owned_coverage_and_preserve_canonical_batch_order() {
        let previous = plan();
        let covered = Ipv4Addr::new(198, 18, 0, 9);
        let (reused, added) = Plan::extend_host(Some(&previous), covered, previous.metric).unwrap();
        assert!(!added);
        assert!(reused == previous);
        let outside = Ipv4Addr::new(192, 0, 2, 9);
        let (extended, added) =
            Plan::extend_host(Some(&previous), outside, previous.metric).unwrap();
        assert!(added);
        assert_eq!(extended.prefixes.len(), 3);
        assert_eq!(extended.prefixes[0].network, outside);
        assert!(extended.prefixes[1..] == previous.prefixes);
        let (reused, added) = Plan::extend_host(Some(&extended), outside, previous.metric).unwrap();
        assert!(!added);
        assert!(reused == extended);
        let (initial, added) = Plan::extend_host(None, outside, previous.metric).unwrap();
        assert!(added);
        assert_eq!(initial.prefixes.len(), 1);
        assert_eq!(initial.prefixes[0].length, 32);
    }
    #[test]
    fn host_extensions_fail_before_overflow_or_changed_ownership() {
        let previous = plan();
        assert!(matches!(
            Plan::extend_host(None, Ipv4Addr::new(192, 0, 2, 9), 1),
            Err(Error::InvalidCapturePolicy)
        ));
        assert!(matches!(
            Plan::extend_host(
                Some(&previous),
                Ipv4Addr::new(192, 0, 2, 9),
                previous.metric + 1
            ),
            Err(Error::Conflict)
        ));
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(matches!(
                Plan::extend_host(None, address, previous.metric),
                Err(Error::InvalidCapturePolicy)
            ));
        }
        let full = Plan {
            prefixes: (0..MAX_PREFIXES)
                .map(|index| Prefix {
                    network: Ipv4Addr::from(0xc6120000 + index as u32),
                    length: 32,
                })
                .collect(),
            metric: previous.metric,
        };
        assert!(matches!(
            Plan::extend_host(Some(&full), Ipv4Addr::new(192, 0, 2, 9), full.metric),
            Err(Error::InvalidCapturePolicy)
        ));
        assert!(
            !Plan::extend_host(Some(&full), full.prefixes[0].network, full.metric)
                .unwrap()
                .1
        );
        let mut malformed = previous.clone();
        malformed.prefixes.reverse();
        assert!(matches!(
            Plan::extend_host(
                Some(&malformed),
                Ipv4Addr::new(192, 0, 2, 9),
                malformed.metric
            ),
            Err(Error::InvalidCapturePolicy)
        ));
    }
    #[test]
    fn individual_host_removal_preserves_other_prefixes_and_clears_the_last_batch() {
        let previous = plan();
        let (remaining, removed) = previous.without_host(previous.prefixes[0].network).unwrap();
        assert!(removed);
        let remaining = remaining.unwrap();
        assert!(remaining.prefixes == previous.prefixes[1..]);
        assert_eq!(remaining.metric, previous.metric);
        remaining.validate().unwrap();
        let (unchanged, removed) = remaining
            .without_host(Ipv4Addr::new(198, 18, 0, 9))
            .unwrap();
        assert!(!removed, "broader owned coverage must remain intact");
        assert!(unchanged.unwrap() == remaining);
        let (single, _) =
            Plan::extend_host(None, Ipv4Addr::new(192, 0, 2, 9), previous.metric).unwrap();
        let (empty, removed) = single.without_host(single.prefixes[0].network).unwrap();
        assert!(removed);
        assert!(empty.is_none());
        assert!(matches!(
            single.without_host(Ipv4Addr::UNSPECIFIED),
            Err(Error::InvalidCapturePolicy)
        ));
        let mut invalid = previous;
        invalid.prefixes.reverse();
        assert!(matches!(
            invalid.without_host(Ipv4Addr::new(192, 0, 2, 9)),
            Err(Error::InvalidCapturePolicy)
        ));
    }
    #[test]
    fn conflicts_preserve_local_and_equally_or_more_specific_foreign_routes() {
        let plan = plan();
        assert_eq!(verify(&plan, &[], false), Ok(()));
        let mut default = owned(Prefix {
            network: Ipv4Addr::UNSPECIFIED,
            length: 0,
        });
        default.metric = None;
        assert_eq!(verify(&plan, &[default], false), Ok(()));
        let mut local = default;
        local.table = NonZeroU32::new(255).unwrap();
        assert_eq!(verify(&plan, &[local], false), Err(Error::Conflict));
        let own: Vec<_> = plan.prefixes.iter().map(|prefix| owned(*prefix)).collect();
        assert_eq!(verify(&plan, &own, false), Err(Error::Conflict));
        assert_eq!(
            verify(&plan, &own, true),
            Ok(()),
            "nested owned prefixes must not conflict with each other"
        );
        assert_eq!(verify(&plan, &own[..1], true), Err(Error::Conflict));
        let mut duplicate = own.clone();
        duplicate.push(own[0]);
        assert_eq!(verify(&plan, &duplicate, true), Err(Error::Conflict));
        for field in 0..9 {
            let mut changed = own.clone();
            match field {
                0 => changed[0].exact = false,
                1 => changed[0].interface = NonZeroU32::new(10),
                2 => changed[0].metric = None,
                3 => changed[0].protocol = 3,
                4 => changed[0].scope = 0,
                5 => changed[0].kind = 2,
                6 => changed[0].gateway = Some(Ipv4Addr::LOCALHOST),
                7 => changed[0].preferred_source = Some(Ipv4Addr::LOCALHOST),
                _ => changed[0].table = NonZeroU32::new(253).unwrap(),
            }
            assert_eq!(
                verify(&plan, &changed, true),
                Err(Error::Conflict),
                "changed comparison field {field}"
            );
        }
    }
    #[test]
    fn invalid_batches_and_request_shapes_cannot_replace_foreign_routes() {
        let plan = plan();
        plan.validate().unwrap();
        let mut changed = plan.clone();
        changed.prefixes.reverse();
        assert!(matches!(
            changed.validate(),
            Err(Error::InvalidCapturePolicy)
        ));
        let mut changed = plan.clone();
        changed.prefixes[0].length = 33;
        assert!(matches!(
            changed.validate(),
            Err(Error::InvalidCapturePolicy)
        ));
        let mut changed = plan.clone();
        changed.prefixes[1].network = Ipv4Addr::new(198, 18, 0, 1);
        assert!(matches!(
            changed.validate(),
            Err(Error::InvalidCapturePolicy)
        ));
        let mut changed = plan.clone();
        changed.metric = 1;
        assert!(matches!(
            changed.validate(),
            Err(Error::InvalidCapturePolicy)
        ));
        let mut changed = plan.clone();
        changed.prefixes.clear();
        assert!(matches!(
            changed.validate(),
            Err(Error::InvalidCapturePolicy)
        ));
        let mut changed = plan.clone();
        changed.prefixes = vec![plan.prefixes[0]; MAX_PREFIXES + 1];
        assert!(matches!(
            changed.validate(),
            Err(Error::InvalidCapturePolicy)
        ));
        let mut changed = plan.clone();
        changed.prefixes = vec![plan.prefixes[0]; 2];
        assert!(matches!(
            changed.validate(),
            Err(Error::InvalidCapturePolicy)
        ));
        let RouteNetlinkMessage::NewRoute(route) = message(plan.prefixes[0], plan.metric, 9, true)
        else {
            unreachable!()
        };
        assert_eq!(route.header.table, 254);
        assert_eq!(route.header.protocol, RouteProtocol::Static);
        assert_eq!(route.header.scope, RouteScope::Link);
        assert_eq!(route.header.kind, RouteType::Unicast);
        assert_eq!(
            route.attributes,
            vec![
                RouteAttribute::Destination(RouteAddress::Inet(plan.prefixes[0].network)),
                RouteAttribute::Oif(9),
                RouteAttribute::Priority(plan.metric)
            ]
        );
        assert!(
            matches!(message(plan.prefixes[0], plan.metric, 9, false), RouteNetlinkMessage::DelRoute(value) if value == route)
        );
    }
    #[test]
    fn recovery_requires_recorded_keys_absent_even_when_their_interface_or_metadata_changed() {
        let plan = plan();
        assert_eq!(plan.verify_absence(&[]), Ok(()));
        let mut route = owned(plan.prefixes[0]);
        route.interface = NonZeroU32::new(77);
        route.exact = false;
        assert_eq!(plan.verify_absence(&[route]), Err(Error::Conflict));
        route.metric = Some(plan.metric + 1);
        assert_eq!(plan.verify_absence(&[route]), Ok(()));
    }
}
