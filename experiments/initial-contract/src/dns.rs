// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded lease/cache contract model with explicit response handoff.
//!
//! Fixed name/provenance storage and bounded linear indexes avoid hidden map
//! capacity and stale timer nodes. This is a policy model, not a DNS parser.

use std::{
    mem::size_of,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::routes::{BackendId, Route, Transaction};

const MAX_ENDPOINTS: usize = 8;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Name {
    bytes: [u8; 253],
    length: u8,
}

impl Name {
    /// Input is already IDNA-normalized ASCII; normalization belongs to config.
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty() || value.len() > 253 || value.ends_with('.') {
            return Err(Error::InvalidName);
        }
        for label in value.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(Error::InvalidName);
            }
        }
        let mut bytes = [0; 253];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            length: value.len() as u8,
        })
    }

    pub fn is_within(&self, domain: &Self) -> bool {
        let name = &self.bytes[..usize::from(self.length)];
        let suffix = &domain.bytes[..usize::from(domain.length)];
        name == suffix
            || (name.len() > suffix.len()
                && name.ends_with(suffix)
                && name[name.len() - suffix.len() - 1] == b'.')
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseKey {
    pub backend: BackendId,
    pub question: Name,
    pub record_type: u16,
    pub class: u16,
    pub address: IpAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub key: LeaseKey,
    pub target: Name,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidName,
    InvalidLimits,
    ResourceLimit,
    InvalidHandle,
    InvalidTime,
    BackendMismatch,
    DomainMismatch,
    RouteNotCommitted,
}

/// A consumed request handle cannot be used to renew/cancel another response.
#[derive(Debug, Eq, PartialEq)]
pub struct Response {
    owner: u64,
    id: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Flow {
    owner: u64,
    slot: usize,
    active: bool,
}

struct Lease {
    key: LeaseKey,
    provenance: Name,
    pending: usize,
    flows: usize,
    retain_until: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheKey {
    pub backend: BackendId,
    pub question: Name,
    pub record_type: u16,
    pub class: u16,
}

struct Cache {
    key: CacheKey,
    expires: Duration,
    negative: bool,
}

struct Pending {
    id: u64,
    slots: [usize; MAX_ENDPOINTS],
    length: usize,
}

/// All indexes and request storage are charged at creation; each retained
/// lease/cache allocation is charged at its full fixed size before admission.
/// No eviction of lease or flow ownership is used to admit new names.
///
/// Allocator bookkeeping is outside this logical byte budget, like stack and
/// OS socket memory; production accounting must record that additional cost.
pub struct Ledger<const N: usize> {
    owner: u64,
    leases: [Option<Box<Lease>>; N],
    cache: [Option<Box<Cache>>; N],
    pending: [Option<Pending>; N],
    next_id: u64,
    now: Duration,
    lease_limit: usize,
    cache_limit: usize,
    byte_limit: usize,
    bytes: usize,
}

impl<const N: usize> Ledger<N> {
    pub fn new(lease_limit: usize, cache_limit: usize, byte_limit: usize) -> Result<Self, Error> {
        if N == 0
            || lease_limit == 0
            || lease_limit > N
            || cache_limit > N
            || byte_limit < size_of::<Self>()
        {
            return Err(Error::InvalidLimits);
        }
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |owner| {
                owner.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?;
        Ok(Self {
            owner,
            leases: std::array::from_fn(|_| None),
            cache: std::array::from_fn(|_| None),
            pending: std::array::from_fn(|_| None),
            next_id: 1,
            now: Duration::ZERO,
            lease_limit,
            cache_limit,
            byte_limit,
            bytes: size_of::<Self>(),
        })
    }

    /// Reserve the complete endpoint set atomically before any route mutation.
    /// Duplicate endpoints in one response and same-key renewals coalesce.
    pub fn reserve(&mut self, endpoints: &[Endpoint]) -> Result<Response, Error> {
        if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS {
            return Err(Error::ResourceLimit);
        }
        let request_slot = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ResourceLimit)?;
        let next_id = self.next_id.checked_add(1).ok_or(Error::ResourceLimit)?;
        let mut request = Pending {
            id: self.next_id,
            slots: [0; MAX_ENDPOINTS],
            length: 0,
        };
        for endpoint in endpoints {
            let existing = self
                .leases
                .iter()
                .position(|slot| slot.as_ref().is_some_and(|lease| lease.key == endpoint.key));
            let slot = match existing {
                Some(slot) => slot,
                None => {
                    if self.lease_count() >= self.lease_limit
                        || self
                            .bytes
                            .checked_add(size_of::<Lease>())
                            .is_none_or(|bytes| bytes > self.byte_limit)
                    {
                        self.release_pending(&request);
                        return Err(Error::ResourceLimit);
                    }
                    let Some(slot) = self.leases.iter().position(Option::is_none) else {
                        self.release_pending(&request);
                        return Err(Error::ResourceLimit);
                    };
                    self.leases[slot] = Some(Box::new(Lease {
                        key: endpoint.key,
                        provenance: endpoint.target,
                        pending: 0,
                        flows: 0,
                        retain_until: None,
                    }));
                    self.bytes += size_of::<Lease>();
                    slot
                }
            };
            if !request.slots[..request.length].contains(&slot) {
                // At most N requests can reserve any one lease.
                self.leases[slot]
                    .as_mut()
                    .ok_or(Error::InvalidHandle)?
                    .pending += 1;
                request.slots[request.length] = slot;
                request.length += 1;
            }
        }
        let response = Response {
            owner: self.owner,
            id: self.next_id,
        };
        self.next_id = next_id;
        self.pending[request_slot] = Some(request);
        Ok(response)
    }

    /// Handoff is the instant output becomes visible, not queue insertion.
    /// Each endpoint's aged dependency TTL must be reflected in `remaining_ttl`.
    /// A partial write keeps the response pending until final handoff/cancel.
    pub fn handoff(
        &mut self,
        response: &Response,
        remaining_ttl: Duration,
        grace: Duration,
    ) -> Result<(), Error> {
        let until = self
            .now
            .checked_add(remaining_ttl.max(grace))
            .ok_or(Error::InvalidTime)?;
        let index = self.request_index(response)?;
        let request = self.pending[index].take().ok_or(Error::InvalidHandle)?;
        for slot in &request.slots[..request.length] {
            let lease = self.leases[*slot].as_mut().ok_or(Error::InvalidHandle)?;
            lease.retain_until = Some(
                lease
                    .retain_until
                    .map_or(until, |previous| previous.max(until)),
            );
        }
        self.release_pending(&request);
        Ok(())
    }

    pub fn cancel(&mut self, response: &Response) -> Result<(), Error> {
        let index = self.request_index(response)?;
        let request = self.pending[index].take().ok_or(Error::InvalidHandle)?;
        self.release_pending(&request);
        Ok(())
    }

    /// The route manager admits a flow under the same serialization as expiry.
    pub fn acquire_flow(&mut self, key: LeaseKey) -> Result<Flow, Error> {
        let index = self
            .leases
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|lease| lease.key == key))
            .ok_or(Error::InvalidHandle)?;
        let lease = self.leases[index].as_mut().ok_or(Error::InvalidHandle)?;
        lease.flows = lease.flows.checked_add(1).ok_or(Error::ResourceLimit)?;
        Ok(Flow {
            owner: self.owner,
            slot: index,
            active: true,
        })
    }

    pub fn release_flow(&mut self, flow: &mut Flow) -> Result<(), Error> {
        if flow.owner != self.owner || !flow.active {
            return Err(Error::InvalidHandle);
        }
        let lease = self
            .leases
            .get_mut(flow.slot)
            .and_then(Option::as_mut)
            .ok_or(Error::InvalidHandle)?;
        lease.flows = lease.flows.checked_sub(1).ok_or(Error::InvalidHandle)?;
        flow.active = false;
        self.reclaim();
        Ok(())
    }

    pub fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::InvalidTime);
        }
        self.now = now;
        self.reclaim();
        for slot in &mut self.cache {
            if slot.as_ref().is_some_and(|cache| cache.expires <= now) {
                *slot = None;
                self.bytes -= size_of::<Cache>();
            }
        }
        Ok(())
    }

    /// Optional positive/negative cache insertion can fail without losing routes.
    /// Zero TTL bypasses cache allocation and does not change route grace.
    pub fn cache(&mut self, key: CacheKey, ttl: Duration, negative: bool) -> Result<(), Error> {
        if ttl.is_zero() {
            return Ok(());
        }
        let expires = self.now.checked_add(ttl).ok_or(Error::InvalidTime)?;
        if let Some(cache) = self
            .cache
            .iter_mut()
            .flatten()
            .find(|cache| cache.key == key)
        {
            cache.expires = expires;
            cache.negative = negative;
            return Ok(());
        }
        if self.cache_count() >= self.cache_limit
            || self
                .bytes
                .checked_add(size_of::<Cache>())
                .is_none_or(|bytes| bytes > self.byte_limit)
        {
            return Err(Error::ResourceLimit);
        }
        let slot = self
            .cache
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(Error::ResourceLimit)?;
        *slot = Some(Box::new(Cache {
            key,
            expires,
            negative,
        }));
        self.bytes += size_of::<Cache>();
        Ok(())
    }

    pub fn evict_cache(&mut self) {
        for slot in &mut self.cache {
            if slot.take().is_some() {
                self.bytes -= size_of::<Cache>();
            }
        }
    }

    pub fn lease_count(&self) -> usize {
        self.leases.iter().flatten().count()
    }
    pub fn cache_count(&self) -> usize {
        self.cache.iter().flatten().count()
    }
    pub fn retained_bytes(&self) -> usize {
        self.bytes
    }
    pub fn provenance(&self, key: LeaseKey) -> Option<Name> {
        self.leases
            .iter()
            .flatten()
            .find(|lease| lease.key == key)
            .map(|lease| lease.provenance)
    }

    fn request_index(&self, response: &Response) -> Result<usize, Error> {
        if response.owner != self.owner {
            return Err(Error::InvalidHandle);
        }
        self.pending
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|request| request.id == response.id)
            })
            .ok_or(Error::InvalidHandle)
    }

    fn release_pending(&mut self, request: &Pending) {
        for slot in &request.slots[..request.length] {
            if let Some(lease) = &mut self.leases[*slot] {
                lease.pending -= 1;
            }
        }
        self.reclaim();
    }

    fn reclaim(&mut self) {
        for slot in &mut self.leases {
            if slot.as_ref().is_some_and(|lease| {
                lease.pending == 0
                    && lease.flows == 0
                    && lease.retain_until.is_none_or(|until| until <= self.now)
            }) {
                *slot = None;
                self.bytes -= size_of::<Lease>();
            }
        }
    }
}

/// Every reachable service endpoint must pass this gate before handoff. The
/// caller resolves dependencies through the already selected backend and
/// supplies the winning domain policy, including more-specific exclusions.
/// This function does not parse records or perform dependency resolution.
pub fn validate_endpoints(
    endpoints: &[Endpoint],
    selected: BackendId,
    winning_backend: impl Fn(&Name) -> Option<BackendId>,
    routes: &[Transaction],
) -> Result<(), Error> {
    if endpoints.is_empty() || endpoints.len() > MAX_ENDPOINTS {
        return Err(Error::ResourceLimit);
    }
    for endpoint in endpoints {
        if endpoint.key.backend != selected {
            return Err(Error::BackendMismatch);
        }
        if winning_backend(&endpoint.target) != Some(selected) {
            return Err(Error::DomainMismatch);
        }
        if !routes.iter().any(|transaction| {
            transaction.route()
                == Route {
                    address: endpoint.key.address,
                    prefix_len: if endpoint.key.address.is_ipv4() {
                        32
                    } else {
                        128
                    },
                    backend: selected,
                }
                && transaction.can_release_answer()
        }) {
            return Err(Error::RouteNotCommitted);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{Ack, Command, OperationId};

    fn endpoint(name: &str) -> Endpoint {
        let name = Name::new(name).unwrap();
        Endpoint {
            key: LeaseKey {
                backend: BackendId(1),
                question: name,
                record_type: 1,
                class: 1,
                address: "192.0.2.1".parse().unwrap(),
            },
            target: name,
        }
    }

    fn ledger() -> Ledger<4> {
        Ledger::new(4, 4, usize::MAX).unwrap()
    }

    #[test]
    fn handles_cannot_release_another_instances_ownership() {
        let mut first = ledger();
        let mut second = ledger();
        let endpoint = endpoint("one.example");
        let first_response = first.reserve(&[endpoint]).unwrap();
        let second_response = second.reserve(&[endpoint]).unwrap();
        assert_eq!(second.cancel(&first_response), Err(Error::InvalidHandle));
        assert_eq!(
            second.handoff(&first_response, Duration::ZERO, Duration::ZERO),
            Err(Error::InvalidHandle)
        );
        let mut flow = first.acquire_flow(endpoint.key).unwrap();
        assert_eq!(second.release_flow(&mut flow), Err(Error::InvalidHandle));
        assert_eq!(first.lease_count(), 1);
        assert_eq!(second.lease_count(), 1);
        first.cancel(&first_response).unwrap();
        second.cancel(&second_response).unwrap();
        assert_eq!(second.lease_count(), 0);
        first.release_flow(&mut flow).unwrap();
        assert_eq!(first.lease_count(), 0);
        assert_eq!(first.release_flow(&mut flow), Err(Error::InvalidHandle));
    }

    #[test]
    fn failed_cache_admission_and_unrepresentable_deadlines_preserve_reservations() {
        let mut ledger = Ledger::<4>::new(4, 0, usize::MAX).unwrap();
        let endpoint = endpoint("one.example");
        let response = ledger.reserve(&[endpoint]).unwrap();
        assert_eq!(
            ledger.cache(
                CacheKey {
                    backend: BackendId(1),
                    question: endpoint.target,
                    record_type: 1,
                    class: 1
                },
                Duration::from_secs(1),
                true
            ),
            Err(Error::ResourceLimit)
        );
        ledger.advance(Duration::from_secs(1)).unwrap();
        assert_eq!(
            ledger.handoff(&response, Duration::MAX, Duration::ZERO),
            Err(Error::InvalidTime)
        );
        assert_eq!(ledger.lease_count(), 1);
        ledger.cancel(&response).unwrap();
        assert_eq!(ledger.lease_count(), 0);
        assert_eq!(ledger.advance(Duration::ZERO), Err(Error::InvalidTime));
    }

    #[test]
    fn pending_output_and_zero_ttl_grace_outlive_cache_freshness() {
        let mut ledger = ledger();
        let endpoint = endpoint("one.example");
        let response = ledger.reserve(&[endpoint]).unwrap();
        ledger.advance(Duration::from_secs(10)).unwrap();
        assert_eq!(
            ledger.lease_count(),
            1,
            "queued or partial output pins routes"
        );
        ledger
            .cache(
                CacheKey {
                    backend: BackendId(1),
                    question: endpoint.key.question,
                    record_type: 1,
                    class: 1,
                },
                Duration::ZERO,
                false,
            )
            .unwrap();
        assert_eq!(ledger.cache_count(), 0);
        ledger
            .handoff(&response, Duration::ZERO, Duration::from_secs(2))
            .unwrap();
        assert_eq!(ledger.cancel(&response), Err(Error::InvalidHandle));
        ledger.advance(Duration::from_secs(11)).unwrap();
        let mut flow = ledger.acquire_flow(endpoint.key).unwrap();
        ledger.advance(Duration::from_secs(12)).unwrap();
        assert_eq!(ledger.lease_count(), 1, "active flow survives grace expiry");
        ledger.release_flow(&mut flow).unwrap();
        assert_eq!(ledger.lease_count(), 0);
    }

    #[test]
    fn cancellation_does_not_renew_an_existing_lease() {
        let mut ledger = ledger();
        let endpoint = endpoint("one.example");
        let first = ledger.reserve(&[endpoint]).unwrap();
        ledger
            .handoff(&first, Duration::from_secs(2), Duration::ZERO)
            .unwrap();
        let second = ledger.reserve(&[endpoint]).unwrap();
        ledger.advance(Duration::from_secs(1)).unwrap();
        ledger.cancel(&second).unwrap();
        ledger.advance(Duration::from_secs(2)).unwrap();
        assert_eq!(ledger.lease_count(), 0);
    }

    #[test]
    fn concurrent_renewals_coalesce_without_timer_or_index_growth() {
        let mut ledger = ledger();
        let endpoint = endpoint("one.example");
        for second in 0..100 {
            ledger.advance(Duration::from_secs(second)).unwrap();
            let first = ledger.reserve(&[endpoint, endpoint]).unwrap();
            let second = ledger.reserve(&[endpoint]).unwrap();
            ledger
                .handoff(&first, Duration::from_secs(2), Duration::ZERO)
                .unwrap();
            ledger.cancel(&second).unwrap();
            assert_eq!(ledger.lease_count(), 1);
            assert_eq!(
                ledger.retained_bytes(),
                size_of::<Ledger<4>>() + size_of::<Lease>()
            );
        }
        ledger.advance(Duration::from_secs(101)).unwrap();
        assert_eq!(ledger.lease_count(), 0);
    }

    #[test]
    fn count_and_byte_exhaustion_roll_back_only_new_reservations() {
        for byte_limit in [usize::MAX, size_of::<Ledger<4>>() + size_of::<Lease>()] {
            let mut ledger =
                Ledger::<4>::new(if byte_limit == usize::MAX { 1 } else { 4 }, 0, byte_limit)
                    .unwrap();
            let one = endpoint("one.example");
            let two = endpoint("two.example");
            let first = ledger.reserve(&[one]).unwrap();
            let before = ledger.retained_bytes();
            assert_eq!(ledger.reserve(&[one, two]), Err(Error::ResourceLimit));
            assert_eq!(ledger.retained_bytes(), before);
            assert_eq!(
                ledger.lease_count(),
                1,
                "same IP cannot bypass name accounting"
            );
            ledger.cancel(&first).unwrap();
            assert_eq!(ledger.lease_count(), 0);
            assert_eq!(ledger.retained_bytes(), size_of::<Ledger<4>>());
            let next = ledger.reserve(&[two]).unwrap();
            ledger.cancel(&next).unwrap();
        }
        let mut ledger = Ledger::<4>::new(1, 0, usize::MAX).unwrap();
        assert_eq!(
            ledger.reserve(&[endpoint("one.example"), endpoint("two.example")]),
            Err(Error::ResourceLimit)
        );
        assert_eq!(ledger.lease_count(), 0, "partial allocation must roll back");
    }

    #[test]
    fn positive_and_negative_cache_eviction_never_releases_routes() {
        let mut ledger = ledger();
        let endpoint = endpoint("one.example");
        let pending = ledger.reserve(&[endpoint]).unwrap();
        ledger
            .handoff(&pending, Duration::from_secs(20), Duration::ZERO)
            .unwrap();
        for (name, negative) in [("one.example", false), ("absent.example", true)] {
            ledger
                .cache(
                    CacheKey {
                        backend: BackendId(1),
                        question: Name::new(name).unwrap(),
                        record_type: 1,
                        class: 1,
                    },
                    Duration::from_secs(1),
                    negative,
                )
                .unwrap();
        }
        assert_eq!(ledger.cache_count(), 2);
        ledger.advance(Duration::from_secs(1)).unwrap();
        assert_eq!(ledger.cache_count(), 0);
        assert_eq!(ledger.lease_count(), 1);
        ledger.evict_cache();
        assert_eq!(ledger.provenance(endpoint.key), Some(endpoint.target));
    }

    #[test]
    fn entire_endpoint_set_waits_for_commit_and_winning_domain_policy() {
        let one = endpoint("one.example");
        let mut two = endpoint("two.example");
        two.key.address = "192.0.2.2".parse().unwrap();
        let mut routes = [one, two].map(|endpoint| {
            Transaction::new(
                OperationId(1),
                Route {
                    address: endpoint.key.address,
                    prefix_len: if endpoint.key.address.is_ipv4() {
                        32
                    } else {
                        128
                    },
                    backend: BackendId(1),
                },
            )
            .unwrap()
        });
        let policy = |_: &Name| Some(BackendId(1));
        for route in &mut routes {
            for _ in 0..3 {
                route
                    .complete(OperationId(1), route.command(), Ack::Applied)
                    .unwrap();
            }
        }
        assert_eq!(
            validate_endpoints(&[one, two], BackendId(1), policy, &routes),
            Err(Error::RouteNotCommitted)
        );
        routes[0]
            .complete(OperationId(1), Command::PersistOwnership, Ack::Applied)
            .unwrap();
        assert_eq!(
            validate_endpoints(&[one, two], BackendId(1), policy, &routes),
            Err(Error::RouteNotCommitted)
        );
        routes[1]
            .complete(OperationId(1), Command::PersistOwnership, Ack::Applied)
            .unwrap();
        assert_eq!(
            validate_endpoints(&[one, two], BackendId(1), policy, &routes),
            Ok(())
        );
        assert_eq!(
            validate_endpoints(
                &[one, two],
                BackendId(1),
                |name| if *name == two.target {
                    Some(BackendId(2))
                } else {
                    policy(name)
                },
                &routes
            ),
            Err(Error::DomainMismatch)
        );
        two.key.backend = BackendId(2);
        assert_eq!(
            validate_endpoints(&[one, two], BackendId(1), policy, &routes),
            Err(Error::BackendMismatch)
        );
        routes[0].cancel();
        assert_eq!(
            validate_endpoints(&[one], BackendId(1), policy, &routes),
            Err(Error::RouteNotCommitted)
        );
    }

    #[test]
    fn canonical_names_preserve_domain_label_boundaries() {
        let domain = Name::new("example.test").unwrap();
        assert!(Name::new("a.example.test").unwrap().is_within(&domain));
        assert!(domain.is_within(&domain));
        assert!(!Name::new("badexample.test").unwrap().is_within(&domain));
        for value in [
            "",
            "Example.test",
            "example.test.",
            "a..test",
            "-a.test",
            "a-.test",
            "é.test",
        ] {
            assert_eq!(Name::new(value), Err(Error::InvalidName), "{value}");
        }
    }
}
