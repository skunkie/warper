// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Serialized native DNS route work whose ownership survives cancelled waits.

use std::{
    fmt,
    mem::size_of,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
use warper_core::{
    BackendId,
    dns::lease::{self, Response, Route},
};
use warper_stack::runtime::Publication;

use super::tun::{self, Owner, Stage};
use crate::{
    dns::routes::{self, Controller},
    native,
};
use warper_core::transport::Request;

const MAX_ADDRESSES: usize = 65536;
const MAX_EXCLUSIONS: usize = 2 * super::egress::MAX_ENDPOINTS;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub addresses_per_response: usize,
    pub bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    InvalidState,
    ResourceLimit,
    Busy,
    Failed,
    UnsupportedFamily,
    InvalidAddress,
    ExcludedEndpoint,
    RequestCancelled,
    RequestExpired,
    WaitCancelled,
    WaitDeadline,
    Metadata(routes::Error),
    Native(tun::Error),
    Worker(native::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits | Self::ResourceLimit => {
                "ResourceLimit: DNS route coordinator admission failed"
            }
            Self::InvalidState => "Conflict: DNS route coordinator ownership is unavailable",
            Self::Busy => "ResourceLimit: DNS route coordinator already owns work",
            Self::Failed => "RecoveryRequired: DNS route coordinator requires session cleanup",
            Self::UnsupportedFamily => "UnsupportedCapability: native DNS capture requires IPv4",
            Self::InvalidAddress => "UnsupportedCapability: DNS address cannot be captured safely",
            Self::ExcludedEndpoint => {
                "Conflict: DNS answer overlaps a protected transport endpoint"
            }
            Self::RequestCancelled => "Cancelled: DNS routing request ended",
            Self::RequestExpired => "Timeout: DNS routing request expired",
            Self::WaitCancelled => {
                "Cancelled: DNS route observation ended while work remains owned"
            }
            Self::WaitDeadline => "Timeout: DNS route observation ended while work remains owned",
            Self::Metadata(_) => "SystemConfiguration: DNS routing metadata operation failed",
            Self::Native(_) => "SystemConfiguration: native DNS route operation failed",
            Self::Worker(_) => "WorkerFailed: DNS route worker failed",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub primary: Error,
    pub cleanup: [Option<Error>; 2],
}
#[derive(Debug)]
pub enum Completion {
    Committed(Response),
    Retired,
}
#[derive(Clone, Copy)]
struct Planned {
    route: Route,
    backend: BackendId,
    address: Ipv4Addr,
}
#[derive(Clone, Copy)]
enum Phase {
    Start,
    Native,
    Metadata,
}
enum Kind {
    Commit(Response),
    Retire(Route),
}
struct Work {
    kind: Kind,
    request: Request,
    phase: Phase,
    index: usize,
}
struct NativeResult {
    owner: Owner,
    result: Result<(), tun::Error>,
    unchanged: bool,
}

/// The service must retain this owner through every accepted operation, then
/// join work and drain output/flows before releasing it for native cleanup.
#[must_use = "retain accepted work through join, then release native ownership for cleanup"]
pub struct Manager {
    controller: Arc<Controller>,
    publication: Publication,
    planned: Vec<Planned>,
    exclusions: Vec<IpAddr>,
    address_limit: usize,
    reserved_bytes: usize,
    work: Option<Work>,
    job: Option<native::Task<NativeResult>>,
    owner: Option<Owner>,
    deferred: Option<Route>,
    failure: Option<Failure>,
    workers: Arc<native::Workers>,
}
impl Manager {
    /// All validation/allocation precedes taking the caller's original owner.
    pub fn new(
        controller: Arc<Controller>,
        publication: Publication,
        owner: &mut Option<Owner>,
        workers: Arc<native::Workers>,
        limits: Limits,
        exclusions: &[IpAddr],
    ) -> Result<Self, Error> {
        if !(1..=MAX_ADDRESSES).contains(&limits.addresses_per_response)
            || exclusions.len() > MAX_EXCLUSIONS
        {
            return Err(Error::InvalidLimits);
        }
        if !publication.is_published()
            || publication.is_quiescent()
            || !publication.uses_selector(&controller.selector())
            || controller.is_closed().map_err(Error::Metadata)?
            || owner
                .as_ref()
                .is_none_or(|owner| !owner.coordinator_ready(&publication))
        {
            return Err(Error::InvalidState);
        }
        let fixed = size_of::<Self>() + size_of::<NativeResult>();
        let required = reservation(fixed, limits.addresses_per_response, exclusions.len())?;
        if required > limits.bytes {
            return Err(Error::ResourceLimit);
        }
        let mut planned = Vec::new();
        planned
            .try_reserve_exact(limits.addresses_per_response)
            .map_err(|_| Error::ResourceLimit)?;
        let mut protected = Vec::new();
        protected
            .try_reserve_exact(exclusions.len())
            .map_err(|_| Error::ResourceLimit)?;
        protected.extend_from_slice(exclusions);
        protected.sort_unstable();
        protected.dedup();
        let reserved_bytes = reservation(fixed, planned.capacity(), protected.capacity())?;
        if reserved_bytes > limits.bytes {
            return Err(Error::ResourceLimit);
        }
        let owner = owner.take().ok_or(Error::InvalidState)?;
        Ok(Self {
            controller,
            publication,
            planned,
            exclusions: protected,
            address_limit: limits.addresses_per_response,
            reserved_bytes,
            work: None,
            job: None,
            owner: Some(owner),
            deferred: None,
            failure: None,
            workers,
        })
    }

    pub fn begin_commit(&mut self, response: Response, request: Request) -> Result<(), Error> {
        self.idle(false)?;
        if self.deferred.is_some() {
            return Err(Error::Busy);
        }
        check_operation(&request)?;
        if self.controller.is_closed().map_err(Error::Metadata)? {
            return Err(Error::Metadata(routes::Error::Ledger(lease::Error::Closed)));
        }
        self.planned.clear();
        let count = self
            .controller
            .response_len(&response)
            .map_err(Error::Metadata)?;
        if count == 0 || count > self.address_limit {
            return Err(Error::ResourceLimit);
        }
        for index in 0..count {
            let route = self
                .controller
                .response_route(&response, index)
                .map_err(Error::Metadata)?;
            let info = self.controller.route_info(route).map_err(Error::Metadata)?;
            let IpAddr::V4(address) = info.key.address else {
                return Err(Error::UnsupportedFamily);
            };
            if !tun::valid_capture_address(address) {
                return Err(Error::InvalidAddress);
            }
            if self.exclusions.binary_search(&info.key.address).is_ok() {
                return Err(Error::ExcludedEndpoint);
            }
            if !matches!(
                info.publication,
                lease::Publication::Preparing | lease::Publication::Committed
            ) {
                return Err(Error::Metadata(routes::Error::Ledger(
                    lease::Error::NotCommitted,
                )));
            }
            self.planned.push(Planned {
                route,
                backend: info.key.backend,
                address,
            });
        }
        self.work = Some(Work {
            kind: Kind::Commit(response),
            request,
            phase: Phase::Start,
            index: 0,
        });
        Ok(())
    }

    pub fn begin_retirement(&mut self, route: Route, request: Request) -> Result<(), Error> {
        self.idle(true)?;
        if self.deferred.is_some_and(|pending| pending != route) {
            return Err(Error::Busy);
        }
        check_operation(&request)?;
        let info = self.controller.route_info(route).map_err(Error::Metadata)?;
        let IpAddr::V4(address) = info.key.address else {
            return Err(Error::UnsupportedFamily);
        };
        let reservation = self.workers.try_reserve().map_err(Error::Worker)?;
        if info.publication != lease::Publication::Retiring {
            self.controller
                .begin_retirement(route)
                .map_err(Error::Metadata)?;
        } else if info.leases != 0 || info.flows != 0 {
            return Err(Error::Metadata(routes::Error::Ledger(
                lease::Error::Referenced,
            )));
        }
        self.planned.clear();
        self.planned.push(Planned {
            route,
            backend: info.key.backend,
            address,
        });
        self.work = Some(Work {
            kind: Kind::Retire(route),
            request,
            phase: Phase::Native,
            index: 0,
        });
        self.deferred = None;
        self.start_native(reservation, true)?;
        Ok(())
    }

    pub fn begin_next_retirement(&mut self, request: Request) -> Result<bool, Error> {
        self.idle(true)?;
        let route = match self.deferred {
            Some(route) => Some(route),
            None => self
                .controller
                .retirement_candidate()
                .map_err(Error::Metadata)?,
        };
        let Some(route) = route else {
            return Ok(false);
        };
        self.begin_retirement(route, request)?;
        Ok(true)
    }

    /// Cancelling this wait never discards the accepted operation or native job.
    /// Use a fresh observation request to join it during supervision/shutdown.
    pub async fn wait(&mut self, request: Request) -> Result<Completion, Error> {
        loop {
            check_wait(&request)?;
            if let Some(failure) = self.failure {
                if self.work.is_none() {
                    return Err(Error::Failed);
                }
                match self.controller.close() {
                    Err(routes::Error::Busy) => {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    Err(error) => {
                        if let Some(stored) = &mut self.failure {
                            stored.cleanup[1] = Some(Error::Metadata(error));
                        }
                    }
                    Ok(()) => {}
                }
                self.discard_work();
                return Err(failure.primary);
            }
            let phase = self.work.as_ref().ok_or(Error::InvalidState)?.phase;
            match phase {
                Phase::Start => {
                    let work = self.work.as_ref().ok_or(Error::InvalidState)?;
                    if let Err(error) = check_operation(&work.request) {
                        return Err(self.reject(error));
                    }
                    if !self.publication.is_published() || self.publication.is_quiescent() {
                        self.fail(Error::InvalidState, None);
                        continue;
                    }
                    match self.controller.is_closed() {
                        Ok(false) => {}
                        Ok(true) => {
                            return Err(self.reject(Error::Metadata(routes::Error::Ledger(
                                lease::Error::Closed,
                            ))));
                        }
                        Err(routes::Error::Busy) => {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        Err(error) => {
                            self.fail(Error::Metadata(error), None);
                            continue;
                        }
                    }
                    if work.index == self.planned.len() {
                        let work = self.work.take().ok_or(Error::InvalidState)?;
                        self.planned.clear();
                        return match work.kind {
                            Kind::Commit(response) => Ok(Completion::Committed(response)),
                            Kind::Retire(_) => Err(Error::InvalidState),
                        };
                    }
                    let reservation = match self.workers.try_reserve() {
                        Ok(reservation) => reservation,
                        Err(error) => return Err(self.reject(Error::Worker(error))),
                    };
                    self.start_native(reservation, false)?;
                    if let Some(work) = &mut self.work {
                        work.phase = Phase::Native;
                    }
                }
                Phase::Native => {
                    let result = self
                        .job
                        .as_mut()
                        .ok_or(Error::InvalidState)?
                        .wait(request.clone())
                        .await;
                    let result = match result {
                        Err(native::Error::WaitCancelled) => return Err(Error::WaitCancelled),
                        Err(native::Error::Deadline) => return Err(Error::WaitDeadline),
                        Err(error) => {
                            self.job.take();
                            self.fail(Error::Worker(error), None);
                            continue;
                        }
                        Ok(result) => result,
                    };
                    self.job.take();
                    self.owner = Some(result.owner);
                    match result.result {
                        Ok(()) => {
                            if let Some(work) = &mut self.work {
                                work.phase = Phase::Metadata;
                            }
                        }
                        Err(error) => {
                            if result.unchanged && request_rejection(error) {
                                match self.check_capture() {
                                    Ok(()) => return Err(self.reject(Error::Native(error))),
                                    Err(secondary) => {
                                        self.fail(Error::Native(error), Some(secondary))
                                    }
                                }
                            } else {
                                self.fail(Error::Native(error), None);
                            }
                        }
                    }
                }
                Phase::Metadata => {
                    if let Err(error) = self.check_capture() {
                        self.fail(error, None);
                        continue;
                    }
                    let work = self.work.as_ref().ok_or(Error::InvalidState)?;
                    let planned = self.planned.get(work.index).ok_or(Error::InvalidState)?;
                    let result = match work.kind {
                        Kind::Commit(_) => self.controller.confirm_publication(planned.route),
                        Kind::Retire(_) => self.controller.finish_retirement(planned.route),
                    };
                    match result {
                        Err(routes::Error::Busy) => {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        Err(error) => {
                            self.fail(Error::Metadata(error), None);
                            continue;
                        }
                        Ok(()) => {}
                    }
                    let work = self.work.as_mut().ok_or(Error::InvalidState)?;
                    match work.kind {
                        Kind::Commit(_) => {
                            work.index += 1;
                            work.phase = Phase::Start;
                        }
                        Kind::Retire(_) => {
                            self.work.take();
                            self.planned.clear();
                            return Ok(Completion::Retired);
                        }
                    }
                }
            }
        }
    }

    pub fn release(&mut self) -> Result<Owner, Error> {
        if self.work.is_some() || self.job.is_some() {
            return Err(Error::Busy);
        }
        self.owner.take().ok_or(Error::InvalidState)
    }
    pub fn capture_changes(&mut self) -> Result<&mut super::change_monitor::Monitor, Error> {
        if self.work.is_some() || self.job.is_some() {
            return Err(Error::Busy);
        }
        self.owner
            .as_mut()
            .ok_or(Error::InvalidState)?
            .capture_changes()
            .map_err(Error::Native)
    }
    pub fn has_pending(&self) -> bool {
        self.work.is_some() || self.job.is_some()
    }
    pub fn deferred_retirement(&self) -> Option<Route> {
        self.deferred
    }
    pub fn failure(&self) -> Option<Failure> {
        self.failure
    }
    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    fn idle(&self, allow_quiescent: bool) -> Result<(), Error> {
        if self.failure.is_some() {
            return Err(Error::Failed);
        }
        if self.has_pending() {
            return Err(Error::Busy);
        }
        if self.owner.is_none()
            || !self.publication.is_published()
            || (!allow_quiescent && self.publication.is_quiescent())
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }
    fn start_native(
        &mut self,
        reservation: native::Reservation,
        retire: bool,
    ) -> Result<(), Error> {
        let work = self.work.as_ref().ok_or(Error::InvalidState)?;
        let planned = *self.planned.get(work.index).ok_or(Error::InvalidState)?;
        let request = work.request.clone();
        let publication = self.publication.clone();
        let mut owner = self.owner.take().ok_or(Error::InvalidState)?;
        self.job = Some(reservation.start(move || {
            let before = owner.capture_revision();
            let result = if retire {
                owner.withdraw_host(publication, planned.address, planned.backend, request)
            } else {
                owner.publish_host(publication, planned.address, planned.backend, request)
            };
            let unchanged = before.is_some() && before == owner.capture_revision();
            NativeResult {
                owner,
                result,
                unchanged,
            }
        }));
        Ok(())
    }
    fn check_capture(&mut self) -> Result<(), Error> {
        let owner = self.owner.as_mut().ok_or(Error::InvalidState)?;
        if !owner.coordinator_ready(&self.publication) {
            return Err(Error::Native(tun::Error::RecoveryRequired));
        }
        if owner.stage() == Stage::Captured {
            owner
                .capture_changes()
                .map_err(Error::Native)?
                .check_pending()
                .map_err(|reason| Error::Native(tun::Error::CaptureChanged(reason)))?;
        }
        Ok(())
    }
    fn fail(&mut self, primary: Error, secondary: Option<Error>) {
        let closure = match self.controller.close() {
            Ok(()) | Err(routes::Error::Busy) => None,
            Err(error) => Some(Error::Metadata(error)),
        };
        self.failure = Some(Failure {
            primary,
            cleanup: [secondary, closure],
        });
    }
    fn reject(&mut self, error: Error) -> Error {
        self.discard_work();
        error
    }
    fn discard_work(&mut self) {
        if let Some(Work {
            kind: Kind::Retire(route),
            ..
        }) = self.work.take()
        {
            self.deferred = Some(route);
        }
        self.planned.clear();
    }
}
impl fmt::Debug for Manager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsRouteManager([redacted])")
    }
}

fn reservation(fixed: usize, addresses: usize, exclusions: usize) -> Result<usize, Error> {
    fixed
        .checked_add(
            addresses
                .checked_mul(size_of::<Planned>())
                .ok_or(Error::InvalidLimits)?,
        )
        .and_then(|bytes| {
            exclusions
                .checked_mul(size_of::<IpAddr>())
                .and_then(|extra| bytes.checked_add(extra))
        })
        .ok_or(Error::InvalidLimits)
}
fn check_operation(request: &Request) -> Result<(), Error> {
    if *request.cancellation.borrow() || request.cancellation.has_changed().is_err() {
        return Err(Error::RequestCancelled);
    }
    if Instant::now() >= request.deadline {
        return Err(Error::RequestExpired);
    }
    if request.deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(30) {
        return Err(Error::InvalidLimits);
    }
    Ok(())
}
fn check_wait(request: &Request) -> Result<(), Error> {
    match check_operation(request) {
        Err(Error::RequestCancelled) => Err(Error::WaitCancelled),
        Err(Error::RequestExpired) => Err(Error::WaitDeadline),
        result => result,
    }
}
fn request_rejection(error: tun::Error) -> bool {
    matches!(
        error,
        tun::Error::Conflict
            | tun::Error::InvalidCapturePolicy
            | tun::Error::UnsupportedRules
            | tun::Error::RouteInspection(_)
            | tun::Error::Capture(tun::NativeFailure {
                delivery: tun::NativeDelivery::NotSent,
                ..
            })
    )
}
