// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Exclusive static capture metadata, conflict inspection and kernel requests.

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
    let inventory = route_inventory::inspect(request).map_err(Error::RouteInspection)?;
    if plan.prefixes.iter().any(|prefix| {
        inventory.entries().iter().any(|entry| {
            entry.table.get() == 254
                && entry.network == prefix.network
                && entry.prefix_len == prefix.length
                && entry.metric == Some(plan.metric)
        })
    }) {
        return Err(Error::Conflict);
    }
    Ok(())
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
}
