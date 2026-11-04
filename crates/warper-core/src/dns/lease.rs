// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded DNS lease, pending-output and flow ownership with explicit route ACKs.

use std::{
    collections::hash_map::RandomState,
    fmt,
    hash::BuildHasher,
    mem::{align_of, size_of, size_of_val},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::sync::Notify;

use super::Name;
use crate::BackendId;

mod index;
use index::Index;

const MAX_CONTRIBUTIONS: usize = 65536;
const FREE: usize = usize::MAX;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    ResourceLimit,
    InvalidHandle,
    InvalidTime,
    Expired,
    Closed,
    Conflict,
    NotCommitted,
    Referenced,
    Retiring,
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "invalid DNS lease ledger limits",
            Self::ResourceLimit => "DNS lease or reference admission exhausted",
            Self::InvalidHandle => "invalid DNS lease ledger handle",
            Self::InvalidTime => "invalid monotonic DNS lease time",
            Self::Expired => "DNS response deadline expired",
            Self::Closed => "DNS lease ledger admission is closed",
            Self::Conflict => "DNS address belongs to another backend",
            Self::NotCommitted => "DNS route publication is not committed",
            Self::Referenced => "DNS route still has protected references",
            Self::Retiring => "DNS route retirement requires reconciliation",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub lease_entries: usize,
    pub route_entries: usize,
    pub response_entries: usize,
    pub flow_entries: usize,
    pub addresses_per_response: usize,
    pub bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuestionKey {
    pub backend: BackendId,
    pub name: Name,
    pub record_type: u16,
    pub class: u16,
}
#[derive(Clone, Copy)]
pub struct Contribution {
    pub address: IpAddr,
    pub expires_at: Duration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteKey {
    pub backend: BackendId,
    pub address: IpAddr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Publication {
    Preparing,
    Committed,
    Uncertain,
    Retiring,
}
/// Identity only; native operation results belong to the serialized service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    owner: u64,
    slot: usize,
    generation: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct RouteInfo {
    pub key: RouteKey,
    pub publication: Publication,
    pub leases: usize,
    pub flows: usize,
}
/// Metadata slots, including preparing/retiring owners; not a kernel inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stats {
    pub lease_capacity: usize,
    pub route_capacity: usize,
    pub leases: usize,
    pub routes: usize,
    pub responses: usize,
    pub flows: usize,
    pub reserved_bytes: usize,
}

struct Control {
    dirty: AtomicBool,
    observer: AtomicBool,
    markers: Vec<AtomicU64>,
    notify: Notify,
}
struct Handle {
    control: Arc<Control>,
    slot: usize,
    id: u64,
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.id != 0
            && self.control.markers[self.slot]
                .compare_exchange(self.id, self.id | 1, Ordering::Release, Ordering::Relaxed)
                .is_ok()
        {
            self.control.dirty.store(true, Ordering::Release);
            self.control.notify.notify_one();
        }
    }
}
#[must_use = "retain through output, then hand off or cancel; Drop schedules cancellation"]
pub struct Response(Handle);
/// Authorization minted before output starts. Its pending references remain
/// live until completed delivery is finalized or the destroyed I/O is cancelled.
#[must_use = "retain through actual output I/O and finalize successful delivery"]
pub struct Output(Handle);
#[must_use = "retain until the actual flow is destroyed; Drop schedules release"]
pub struct Flow(Handle);
impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Response([redacted])")
    }
}
impl fmt::Debug for Output {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Output([redacted])")
    }
}
impl fmt::Debug for Flow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Flow([redacted])")
    }
}

/// The sole owned notification waiter. No ledger borrow or mutex guard is
/// retained while waiting; a mutable borrow prevents concurrent waits.
pub struct Changes {
    control: Arc<Control>,
}
impl Changes {
    pub fn wait(&mut self) -> impl Future<Output = ()> + '_ {
        self.control.notify.notified()
    }
}
impl Drop for Changes {
    fn drop(&mut self) {
        self.control.observer.store(false, Ordering::Release);
    }
}
impl fmt::Debug for Changes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Changes([redacted])")
    }
}

struct Lease {
    question: QuestionKey,
    address: IpAddr,
    route: usize,
    pending: usize,
    retain_until: Option<Duration>,
}
struct Owner {
    key: RouteKey,
    generation: u64,
    publication: Publication,
    leases: usize,
    flows: usize,
}
#[derive(Clone, Copy)]
struct Pending {
    id: u64,
    count: usize,
    deadline: Duration,
}
#[derive(Clone, Copy)]
struct PendingEntry {
    lease: usize,
    route: usize,
    address: IpAddr,
    expires_at: Duration,
}
impl PendingEntry {
    const EMPTY: Self = Self {
        lease: FREE,
        route: FREE,
        address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        expires_at: Duration::ZERO,
    };
}
#[derive(Clone, Copy)]
struct ActiveFlow {
    id: u64,
    route: usize,
}

pub struct Ledger {
    control: Arc<Control>,
    leases: Vec<Option<Lease>>,
    owners: Vec<Option<Owner>>,
    lease_index: Index,
    owner_index: Index,
    free_leases: Vec<usize>,
    free_owners: Vec<usize>,
    pending: Vec<Option<Pending>>,
    entries: Vec<PendingEntry>,
    flows: Vec<Option<ActiveFlow>>,
    hash: RandomState,
    owner: u64,
    next_id: u64,
    now: Duration,
    closed: bool,
    next_expiry: Option<Duration>,
    limits: Limits,
    reserved_bytes: usize,
}

impl Ledger {
    pub fn new(limits: Limits) -> Result<Self, Error> {
        validate_limits(limits)?;
        let mut low = 0;
        let mut high = limits.lease_entries;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if required_bytes(limits, middle).is_ok_and(|bytes| bytes <= limits.bytes) {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        if low == 0 {
            return Err(Error::ResourceLimit);
        }
        let route_capacity = route_capacity(limits, low)?;
        let marker_count = limits
            .response_entries
            .checked_add(limits.flow_entries)
            .ok_or(Error::InvalidLimits)?;
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |owner| {
                owner.checked_add(1)
            })
            .map_err(|_| Error::ResourceLimit)?;
        let mut ledger = Self {
            control: Arc::new(Control {
                dirty: AtomicBool::new(false),
                observer: AtomicBool::new(false),
                markers: allocate(marker_count, || AtomicU64::new(0))?,
                notify: Notify::new(),
            }),
            leases: allocate(low, || None)?,
            owners: allocate(route_capacity, || None)?,
            lease_index: Index::new(low)?,
            owner_index: Index::new(route_capacity)?,
            free_leases: free_slots(low)?,
            free_owners: free_slots(route_capacity)?,
            pending: allocate(limits.response_entries, || None)?,
            entries: allocate(
                limits
                    .response_entries
                    .checked_mul(limits.addresses_per_response)
                    .ok_or(Error::InvalidLimits)?,
                || PendingEntry::EMPTY,
            )?,
            flows: allocate(limits.flow_entries, || None)?,
            hash: RandomState::new(),
            owner,
            next_id: 2,
            now: Duration::ZERO,
            closed: false,
            next_expiry: None,
            limits,
            reserved_bytes: 0,
        };
        ledger.reserved_bytes = ledger.allocation_bytes()?;
        if ledger.reserved_bytes > limits.bytes {
            return Err(Error::ResourceLimit);
        }
        Ok(ledger)
    }

    pub fn reserve(
        &mut self,
        now: Duration,
        question: QuestionKey,
        contributions: &[Contribution],
        deadline: Duration,
    ) -> Result<Response, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if contributions.is_empty() || contributions.len() > MAX_CONTRIBUTIONS {
            return Err(Error::ResourceLimit);
        }
        self.advance(now)?;
        if deadline <= now {
            return Err(Error::Expired);
        }
        let slot = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ResourceLimit)?;
        let start = slot * self.limits.addresses_per_response;
        let result = self.prepare(start, question, contributions);
        let count = match result {
            Ok(count) => count,
            Err(error) => {
                self.entries[start..start + self.limits.addresses_per_response]
                    .fill(PendingEntry::EMPTY);
                return Err(error);
            }
        };
        let id = self.id()?;
        for offset in 0..count {
            let entry = self.entries[start + offset];
            if self.owners[entry.route].is_none() {
                let generation = self.id()?;
                self.owners[entry.route] = Some(Owner {
                    key: RouteKey {
                        backend: question.backend,
                        address: entry.address,
                    },
                    generation,
                    publication: Publication::Preparing,
                    leases: 0,
                    flows: 0,
                });
                self.free_owners.pop().ok_or(Error::InvalidHandle)?;
                self.owner_index
                    .insert(self.address_hash(entry.address), entry.route)?;
            }
            if self.leases[entry.lease].is_none() {
                self.leases[entry.lease] = Some(Lease {
                    question,
                    address: entry.address,
                    route: entry.route,
                    pending: 0,
                    retain_until: None,
                });
                self.free_leases.pop().ok_or(Error::InvalidHandle)?;
                self.lease_index
                    .insert(self.lease_hash(question, entry.address), entry.lease)?;
                self.owners[entry.route]
                    .as_mut()
                    .ok_or(Error::InvalidHandle)?
                    .leases += 1;
            }
            self.leases[entry.lease]
                .as_mut()
                .ok_or(Error::InvalidHandle)?
                .pending += 1;
        }
        self.pending[slot] = Some(Pending {
            id,
            count,
            deadline,
        });
        self.control.markers[slot].store(id, Ordering::Release);
        Ok(Response(Handle {
            control: self.control.clone(),
            slot,
            id,
        }))
    }

    pub fn response_len(&self, response: &Response) -> Result<usize, Error> {
        Ok(self.response(response)?.count)
    }
    pub fn response_route(&self, response: &Response, index: usize) -> Result<Route, Error> {
        let pending = self.response(response)?;
        if index >= pending.count {
            return Err(Error::InvalidHandle);
        }
        self.route(self.entries[response.0.slot * self.limits.addresses_per_response + index].route)
    }

    /// The service calls this only after handler publication, native ACK and
    /// durable ownership. This transition itself performs no native I/O.
    pub fn confirm_publication(&mut self, route: Route) -> Result<(), Error> {
        let owner = self.owner_mut(route)?;
        if owner.publication == Publication::Retiring {
            return Err(Error::Retiring);
        }
        owner.publication = Publication::Committed;
        Ok(())
    }

    /// Native uncertainty withdraws metadata readiness without discarding
    /// pending output, timed leases or active-flow ownership.
    pub fn mark_uncertain(&mut self, route: Route) -> Result<(), Error> {
        let owner = self.owner_mut(route)?;
        if owner.publication == Publication::Retiring {
            return Err(Error::Retiring);
        }
        owner.publication = Publication::Uncertain;
        Ok(())
    }

    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.control.notify.notify_one();
        }
    }

    /// The service first withdraws DNS and destroys/joins output and flow
    /// owners. This clears timed leases, while preserving routes for native
    /// withdrawal; it never declares platform cleanup successful.
    pub fn finish_drain(&mut self, now: Duration) -> Result<(), Error> {
        self.advance(now)?;
        if !self.closed
            || self.pending.iter().any(Option::is_some)
            || self.flows.iter().any(Option::is_some)
        {
            return Err(Error::Referenced);
        }
        for slot in 0..self.leases.len() {
            if let Some(lease) = &mut self.leases[slot] {
                lease.retain_until = None;
            }
            self.reclaim_slot(slot)?;
        }
        self.next_expiry = None;
        self.compact_indexes()
    }

    /// Atomic authorization and retention at one clock observation. Asynchronous
    /// output owners must use `begin_output` before I/O and `complete_output`
    /// after successful delivery instead of checking the deadline after writing.
    pub fn handoff(
        &mut self,
        now: Duration,
        response: &mut Response,
        grace: Duration,
    ) -> Result<(), Error> {
        self.authorize_output(now, &response.0)?;
        self.finish_output(now, &mut response.0, grace)
    }

    /// Authorize before any positive output bytes are written. On failure the
    /// consumed response schedules cancellation; no output may have started.
    pub fn begin_output(&mut self, now: Duration, response: Response) -> Result<Output, Error> {
        self.authorize_output(now, &response.0)?;
        Ok(Output(response.0))
    }

    /// Call only after the complete positive message has been handed to I/O.
    /// Late observation, closure or uncertainty cannot erase its grace lease.
    /// Errors leave this guard pending; retain it while surfacing the failure.
    pub fn complete_output(
        &mut self,
        now: Duration,
        output: &mut Output,
        grace: Duration,
    ) -> Result<(), Error> {
        self.finish_output(now, &mut output.0, grace)
    }

    fn authorize_output(&mut self, now: Duration, handle: &Handle) -> Result<(), Error> {
        let pending = self.pending_response(handle)?;
        self.advance(now)?;
        if self.closed {
            return Err(Error::Closed);
        }
        if now >= pending.deadline {
            return Err(Error::Expired);
        }
        let start = handle.slot * self.limits.addresses_per_response;
        for entry in &self.entries[start..start + pending.count] {
            let lease = self.leases[entry.lease]
                .as_ref()
                .ok_or(Error::InvalidHandle)?;
            if self.owners[lease.route]
                .as_ref()
                .ok_or(Error::InvalidHandle)?
                .publication
                != Publication::Committed
            {
                return Err(Error::NotCommitted);
            }
        }
        Ok(())
    }

    fn finish_output(
        &mut self,
        now: Duration,
        handle: &mut Handle,
        grace: Duration,
    ) -> Result<(), Error> {
        let pending = self.pending_response(handle)?;
        self.advance(now)?;
        let grace_until = now.checked_add(grace).ok_or(Error::InvalidTime)?;
        let start = handle.slot * self.limits.addresses_per_response;
        for entry in &self.entries[start..start + pending.count] {
            let lease = self.leases[entry.lease]
                .as_mut()
                .ok_or(Error::InvalidHandle)?;
            let until = entry.expires_at.max(grace_until);
            let retained = lease.retain_until.map_or(until, |prior| prior.max(until));
            lease.retain_until = Some(retained);
            if retained > now {
                self.next_expiry = Some(
                    self.next_expiry
                        .map_or(retained, |prior| prior.min(retained)),
                );
            }
        }
        self.release_response(handle.slot)?;
        handle.id = 0;
        self.reclaim_leases()?;
        self.control.notify.notify_one();
        Ok(())
    }

    pub fn cancel(&mut self, response: &mut Response) -> Result<(), Error> {
        self.response(response)?;
        self.release_response(response.0.slot)?;
        response.0.id = 0;
        self.reclaim_leases()?;
        self.control.notify.notify_one();
        Ok(())
    }

    pub fn acquire_flow(&mut self, now: Duration, route: Route) -> Result<Flow, Error> {
        self.owner_ref(route)?;
        self.advance(now)?;
        if self.closed {
            return Err(Error::Closed);
        }
        let owner = self.owner_ref(route)?;
        if owner.publication != Publication::Committed || owner.leases == 0 && owner.flows == 0 {
            return Err(Error::NotCommitted);
        }
        let slot = self
            .flows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ResourceLimit)?;
        let id = self.id()?;
        self.owners[route.slot]
            .as_mut()
            .ok_or(Error::InvalidHandle)?
            .flows += 1;
        self.flows[slot] = Some(ActiveFlow {
            id,
            route: route.slot,
        });
        let marker = self.limits.response_entries + slot;
        self.control.markers[marker].store(id, Ordering::Release);
        Ok(Flow(Handle {
            control: self.control.clone(),
            slot: marker,
            id,
        }))
    }

    pub fn release_flow(&mut self, flow: &mut Flow) -> Result<(), Error> {
        self.handle(&flow.0)?;
        let slot = flow
            .0
            .slot
            .checked_sub(self.limits.response_entries)
            .ok_or(Error::InvalidHandle)?;
        if self
            .flows
            .get(slot)
            .and_then(|flow| *flow)
            .is_none_or(|active| active.id != flow.0.id)
        {
            return Err(Error::InvalidHandle);
        }
        self.release_flow_slot(slot)?;
        flow.0.id = 0;
        self.control.notify.notify_one();
        Ok(())
    }

    /// Issue one owned waiter so an actor can wait without holding its ledger
    /// lock. Dropping the waiter permits a replacement after its wait ends.
    pub fn changes(&mut self) -> Result<Changes, Error> {
        self.control
            .observer
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::ResourceLimit)?;
        Ok(Changes {
            control: self.control.clone(),
        })
    }

    pub fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::InvalidTime);
        }
        self.now = now;
        if self.control.dirty.swap(false, Ordering::Acquire) {
            for slot in 0..self.pending.len() {
                if let Some(pending) = self.pending[slot]
                    && self.control.markers[slot].load(Ordering::Acquire) == (pending.id | 1)
                {
                    self.release_response(slot)?;
                }
            }
            for slot in 0..self.flows.len() {
                if let Some(flow) = self.flows[slot]
                    && self.control.markers[self.limits.response_entries + slot]
                        .load(Ordering::Acquire)
                        == (flow.id | 1)
                {
                    self.release_flow_slot(slot)?;
                }
            }
        }
        self.reclaim_leases()
    }

    pub fn route_info(&self, route: Route) -> Result<RouteInfo, Error> {
        let owner = self.owner_ref(route)?;
        Ok(RouteInfo {
            key: owner.key,
            publication: owner.publication,
            leases: owner.leases,
            flows: owner.flows,
        })
    }
    pub fn route_for(&self, address: IpAddr) -> Option<Route> {
        self.owner_slot(address)
            .and_then(|slot| self.route(slot).ok())
    }
    pub fn retirement_candidate(&self) -> Option<Route> {
        self.owners
            .iter()
            .position(|owner| {
                owner.as_ref().is_some_and(|owner| {
                    owner.leases == 0
                        && owner.flows == 0
                        && owner.publication != Publication::Retiring
                })
            })
            .and_then(|slot| self.route(slot).ok())
    }
    pub fn begin_retirement(&mut self, now: Duration, route: Route) -> Result<(), Error> {
        self.owner_ref(route)?;
        self.advance(now)?;
        let owner = self.owner_mut(route)?;
        if owner.publication == Publication::Retiring {
            return Err(Error::Retiring);
        }
        if owner.leases != 0 || owner.flows != 0 {
            return Err(Error::Referenced);
        }
        owner.publication = Publication::Retiring;
        Ok(())
    }
    /// Call only after verified native withdrawal/absence and handler retirement.
    pub fn finish_retirement(&mut self, route: Route) -> Result<(), Error> {
        let owner = self.owner_ref(route)?;
        if owner.publication != Publication::Retiring {
            return Err(Error::Retiring);
        }
        if owner.leases != 0 || owner.flows != 0 {
            return Err(Error::Referenced);
        }
        let address = owner.key.address;
        self.owner_index
            .remove(self.address_hash(address), route.slot)?;
        self.owners[route.slot] = None;
        self.free_owners.push(route.slot);
        self.compact_indexes()
    }
    /// An uncertain withdrawal must not call this. The service proves the same
    /// owned route still committed before restoring metadata availability.
    pub fn restore_committed(&mut self, route: Route) -> Result<(), Error> {
        let owner = self.owner_mut(route)?;
        if owner.publication != Publication::Retiring {
            return Err(Error::Retiring);
        }
        owner.publication = Publication::Committed;
        Ok(())
    }
    /// A conservative earliest timed expiry for one service-owned timer.
    /// Renewal can leave one early wake; advance recomputes it in place.
    pub fn next_expiry(&self) -> Option<Duration> {
        self.next_expiry
    }

    pub fn retention(&self, question: QuestionKey, address: IpAddr) -> Option<Duration> {
        self.lease_slot(question, address).and_then(|slot| {
            self.leases[slot]
                .as_ref()
                .and_then(|lease| lease.retain_until)
        })
    }
    pub fn stats(&self) -> Stats {
        Stats {
            lease_capacity: self.leases.len(),
            route_capacity: self.owners.len(),
            leases: self.leases.len() - self.free_leases.len(),
            routes: self.owners.len() - self.free_owners.len(),
            responses: self.pending.iter().flatten().count(),
            flows: self.flows.iter().flatten().count(),
            reserved_bytes: self.reserved_bytes,
        }
    }

    fn prepare(
        &mut self,
        start: usize,
        question: QuestionKey,
        contributions: &[Contribution],
    ) -> Result<usize, Error> {
        let mut count = 0;
        let mut new_leases = 0;
        let mut new_routes = 0;
        for contribution in contributions {
            if let Some(entry) = self.entries[start..start + count]
                .iter_mut()
                .find(|entry| entry.address == contribution.address)
            {
                entry.expires_at = entry.expires_at.max(contribution.expires_at);
                continue;
            }
            if count == self.limits.addresses_per_response {
                return Err(Error::ResourceLimit);
            }
            let route = if let Some(slot) = self.owner_slot(contribution.address) {
                let owner = self.owners[slot].as_ref().ok_or(Error::InvalidHandle)?;
                if owner.key.backend != question.backend {
                    return Err(Error::Conflict);
                }
                if owner.publication == Publication::Retiring {
                    return Err(Error::Retiring);
                }
                slot
            } else {
                new_routes += 1;
                let offset = self
                    .free_owners
                    .len()
                    .checked_sub(new_routes)
                    .ok_or(Error::ResourceLimit)?;
                self.free_owners[offset]
            };
            let lease = if let Some(slot) = self.lease_slot(question, contribution.address) {
                slot
            } else {
                new_leases += 1;
                let offset = self
                    .free_leases
                    .len()
                    .checked_sub(new_leases)
                    .ok_or(Error::ResourceLimit)?;
                self.free_leases[offset]
            };
            self.entries[start + count] = PendingEntry {
                lease,
                route,
                address: contribution.address,
                expires_at: contribution.expires_at,
            };
            count += 1;
        }
        // Reserve every identity before mutation, including newly owned routes.
        let identities = u64::try_from(new_routes + 1).map_err(|_| Error::ResourceLimit)?;
        self.next_id
            .checked_add(identities.checked_mul(2).ok_or(Error::ResourceLimit)?)
            .ok_or(Error::ResourceLimit)?;
        Ok(count)
    }
    fn response(&self, response: &Response) -> Result<Pending, Error> {
        self.pending_response(&response.0)
    }
    fn pending_response(&self, handle: &Handle) -> Result<Pending, Error> {
        self.handle(handle)?;
        self.pending
            .get(handle.slot)
            .and_then(|pending| *pending)
            .filter(|pending| pending.id == handle.id)
            .ok_or(Error::InvalidHandle)
    }
    fn handle(&self, handle: &Handle) -> Result<(), Error> {
        if !Arc::ptr_eq(&handle.control, &self.control)
            || handle.id == 0
            || self
                .control
                .markers
                .get(handle.slot)
                .is_none_or(|marker| marker.load(Ordering::Acquire) != handle.id)
        {
            return Err(Error::InvalidHandle);
        }
        Ok(())
    }
    fn route(&self, slot: usize) -> Result<Route, Error> {
        Ok(Route {
            owner: self.owner,
            slot,
            generation: self
                .owners
                .get(slot)
                .and_then(Option::as_ref)
                .ok_or(Error::InvalidHandle)?
                .generation,
        })
    }
    fn owner_ref(&self, route: Route) -> Result<&Owner, Error> {
        if route.owner != self.owner {
            return Err(Error::InvalidHandle);
        }
        self.owners
            .get(route.slot)
            .and_then(Option::as_ref)
            .filter(|owner| owner.generation == route.generation)
            .ok_or(Error::InvalidHandle)
    }
    fn owner_mut(&mut self, route: Route) -> Result<&mut Owner, Error> {
        self.owner_ref(route)?;
        self.owners[route.slot].as_mut().ok_or(Error::InvalidHandle)
    }
    fn release_response(&mut self, slot: usize) -> Result<(), Error> {
        let pending = self.pending[slot].take().ok_or(Error::InvalidHandle)?;
        let start = slot * self.limits.addresses_per_response;
        for offset in 0..pending.count {
            let entry = self.entries[start + offset];
            let lease = self.leases[entry.lease]
                .as_mut()
                .ok_or(Error::InvalidHandle)?;
            lease.pending = lease.pending.checked_sub(1).ok_or(Error::InvalidHandle)?;
            self.entries[start + offset] = PendingEntry::EMPTY;
            self.reclaim_slot(entry.lease)?;
        }
        self.control.markers[slot].store(0, Ordering::Release);
        Ok(())
    }
    fn release_flow_slot(&mut self, slot: usize) -> Result<(), Error> {
        let flow = self.flows[slot].take().ok_or(Error::InvalidHandle)?;
        let owner = self.owners[flow.route]
            .as_mut()
            .ok_or(Error::InvalidHandle)?;
        owner.flows = owner.flows.checked_sub(1).ok_or(Error::InvalidHandle)?;
        self.control.markers[self.limits.response_entries + slot].store(0, Ordering::Release);
        Ok(())
    }
    fn reclaim_leases(&mut self) -> Result<(), Error> {
        if self.next_expiry.is_some_and(|until| until <= self.now) {
            self.next_expiry = None;
            for slot in 0..self.leases.len() {
                self.reclaim_slot(slot)?;
                if let Some(until) = self.leases[slot]
                    .as_ref()
                    .and_then(|lease| lease.retain_until)
                    && until > self.now
                {
                    self.next_expiry =
                        Some(self.next_expiry.map_or(until, |prior| prior.min(until)));
                }
            }
        }
        self.compact_indexes()
    }

    fn reclaim_slot(&mut self, slot: usize) -> Result<(), Error> {
        let expired = self.leases[slot].as_ref().is_some_and(|lease| {
            lease.pending == 0 && lease.retain_until.is_none_or(|until| until <= self.now)
        });
        if !expired {
            return Ok(());
        }
        let lease = self.leases[slot].take().ok_or(Error::InvalidHandle)?;
        self.lease_index
            .remove(self.lease_hash(lease.question, lease.address), slot)?;
        self.owners[lease.route]
            .as_mut()
            .ok_or(Error::InvalidHandle)?
            .leases -= 1;
        self.free_leases.push(slot);
        Ok(())
    }
    fn compact_indexes(&mut self) -> Result<(), Error> {
        if self.lease_index.needs_compaction() {
            self.lease_index.clear();
            for slot in 0..self.leases.len() {
                if let Some(lease) = &self.leases[slot] {
                    self.lease_index
                        .insert(self.lease_hash(lease.question, lease.address), slot)?;
                }
            }
        }
        if self.owner_index.needs_compaction() {
            self.owner_index.clear();
            for slot in 0..self.owners.len() {
                if let Some(owner) = &self.owners[slot] {
                    self.owner_index
                        .insert(self.address_hash(owner.key.address), slot)?;
                }
            }
        }
        Ok(())
    }
    fn lease_slot(&self, question: QuestionKey, address: IpAddr) -> Option<usize> {
        self.lease_index
            .find(self.lease_hash(question, address), |slot| {
                self.leases[slot]
                    .as_ref()
                    .is_some_and(|lease| lease.question == question && lease.address == address)
            })
    }
    fn owner_slot(&self, address: IpAddr) -> Option<usize> {
        self.owner_index.find(self.address_hash(address), |slot| {
            self.owners[slot]
                .as_ref()
                .is_some_and(|owner| owner.key.address == address)
        })
    }
    fn lease_hash(&self, question: QuestionKey, address: IpAddr) -> u64 {
        self.hash.hash_one((
            question.backend.0,
            question.name.wire(),
            question.record_type,
            question.class,
            address,
        ))
    }
    fn address_hash(&self, address: IpAddr) -> u64 {
        self.hash.hash_one(address)
    }
    fn id(&mut self) -> Result<u64, Error> {
        let id = self.next_id;
        self.next_id = id.checked_add(2).ok_or(Error::ResourceLimit)?;
        Ok(id)
    }
    fn allocation_bytes(&self) -> Result<usize, Error> {
        let mut bytes = fixed_bytes(self.limits)?;
        for capacity in [
            self.leases.capacity() * size_of::<Option<Lease>>(),
            self.owners.capacity() * size_of::<Option<Owner>>(),
            self.lease_index.bytes(),
            self.owner_index.bytes(),
            self.free_leases.capacity() * size_of::<usize>(),
            self.free_owners.capacity() * size_of::<usize>(),
            self.pending.capacity() * size_of::<Option<Pending>>(),
            self.entries.capacity() * size_of::<PendingEntry>(),
            self.flows.capacity() * size_of::<Option<ActiveFlow>>(),
            self.control.markers.capacity() * size_of::<AtomicU64>(),
        ] {
            bytes = bytes.checked_add(capacity).ok_or(Error::InvalidLimits)?;
        }
        Ok(bytes)
    }
}

fn validate_limits(limits: Limits) -> Result<(), Error> {
    if limits.lease_entries == 0
        || limits.route_entries == 0
        || limits.response_entries == 0
        || limits.addresses_per_response == 0
        || limits.addresses_per_response > MAX_CONTRIBUTIONS
    {
        return Err(Error::InvalidLimits);
    }
    required_bytes(limits, 1)?;
    Ok(())
}
fn route_capacity(limits: Limits, leases: usize) -> Result<usize, Error> {
    Ok(limits.route_entries.min(
        leases
            .checked_add(limits.flow_entries)
            .ok_or(Error::InvalidLimits)?,
    ))
}
fn required_bytes(limits: Limits, leases: usize) -> Result<usize, Error> {
    let routes = route_capacity(limits, leases)?;
    let mut bytes = fixed_bytes(limits)?;
    for (count, size) in [
        (leases, size_of::<Option<Lease>>() + size_of::<usize>()),
        (routes, size_of::<Option<Owner>>() + size_of::<usize>()),
        (limits.response_entries, size_of::<Option<Pending>>()),
        (
            limits
                .response_entries
                .checked_mul(limits.addresses_per_response)
                .ok_or(Error::InvalidLimits)?,
            size_of::<PendingEntry>(),
        ),
        (limits.flow_entries, size_of::<Option<ActiveFlow>>()),
        (
            limits
                .response_entries
                .checked_add(limits.flow_entries)
                .ok_or(Error::InvalidLimits)?,
            size_of::<AtomicU64>(),
        ),
    ] {
        bytes = bytes
            .checked_add(count.checked_mul(size).ok_or(Error::InvalidLimits)?)
            .ok_or(Error::InvalidLimits)?;
    }
    bytes = bytes
        .checked_add(Index::required_bytes(leases)?)
        .ok_or(Error::InvalidLimits)?;
    bytes
        .checked_add(Index::required_bytes(routes)?)
        .ok_or(Error::InvalidLimits)
}
fn fixed_bytes(limits: Limits) -> Result<usize, Error> {
    let notify = Notify::new();
    let mut bytes = size_of::<Ledger>()
        + size_of::<Changes>()
        + size_of::<Control>()
        + 2 * size_of::<usize>()
        + align_of::<Control>()
        - 1
        + size_of_val(&notify.notified());
    for (count, size) in [
        (
            limits.response_entries,
            size_of::<Response>().max(size_of::<Output>()),
        ),
        (limits.flow_entries, size_of::<Flow>()),
    ] {
        bytes = bytes
            .checked_add(count.checked_mul(size).ok_or(Error::InvalidLimits)?)
            .ok_or(Error::InvalidLimits)?;
    }
    Ok(bytes)
}
fn allocate<T>(length: usize, mut value: impl FnMut() -> T) -> Result<Vec<T>, Error> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| Error::ResourceLimit)?;
    result.resize_with(length, &mut value);
    Ok(result)
}
fn free_slots(length: usize) -> Result<Vec<usize>, Error> {
    let mut next = length;
    allocate(length, || {
        next -= 1;
        next
    })
}

#[cfg(test)]
mod output_tests;
#[cfg(test)]
mod tests;
