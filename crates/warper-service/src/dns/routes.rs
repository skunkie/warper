// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Serialized live routing selection and DNS ownership, without native I/O.

use std::{
    fmt,
    mem::{align_of, size_of},
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::Duration,
};

use tokio::time::Instant;
use warper_config::schema::RoutingMode;
use warper_core::{
    BackendId,
    dns::lease::{self, Contribution, Ledger, QuestionKey, Response, Route, RouteInfo, Stats},
    routing::{FlowSelector, Policy, Selection, SelectionError},
};

const MAX_CONTRIBUTIONS: usize = 65536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidClock,
    Busy,
    Unavailable,
    StaticConflict,
    MissingStaticCoverage,
    Ledger(lease::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidClock => "invalid live routing clock",
            Self::Busy => "live routing owner is busy",
            Self::Unavailable => "live routing owner is unavailable",
            Self::StaticConflict => "DNS endpoint conflicts with the winning static backend",
            Self::MissingStaticCoverage => "DNS endpoint lacks selected static coverage",
            Self::Ledger(_) => "DNS routing ownership operation failed",
        })
    }
}
impl std::error::Error for Error {}

struct Owned {
    ledger: Ledger,
    scratch: Vec<IpAddr>,
    closed: bool,
}
struct LiveRoutes {
    policy: Arc<Policy>,
    owner: Mutex<Owned>,
    origin: Instant,
}

pub struct Controller {
    routes: Arc<LiveRoutes>,
    overhead: usize,
}
impl Controller {
    pub fn new(
        policy: Arc<Policy>,
        mut limits: lease::Limits,
        origin: Instant,
    ) -> Result<Self, Error> {
        if origin > Instant::now() {
            return Err(Error::InvalidClock);
        }
        if limits.addresses_per_response == 0 || limits.addresses_per_response > MAX_CONTRIBUTIONS {
            return Err(Error::Ledger(lease::Error::InvalidLimits));
        }
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.addresses_per_response)
            .map_err(|_| Error::Ledger(lease::Error::ResourceLimit))?;
        let overhead = (size_of::<LiveRoutes>() - size_of::<Ledger>()
            + 2 * size_of::<usize>()
            + align_of::<LiveRoutes>()
            - 1
            + size_of::<Controller>()
            + 2 * size_of::<Arc<dyn FlowSelector>>())
        .checked_add(
            scratch
                .capacity()
                .checked_mul(size_of::<IpAddr>())
                .ok_or(Error::Ledger(lease::Error::InvalidLimits))?,
        )
        .ok_or(Error::Ledger(lease::Error::InvalidLimits))?;
        limits.bytes = limits
            .bytes
            .checked_sub(overhead)
            .ok_or(Error::Ledger(lease::Error::ResourceLimit))?;
        let ledger = Ledger::new(limits).map_err(Error::Ledger)?;
        Ok(Self {
            routes: Arc::new(LiveRoutes {
                policy,
                owner: Mutex::new(Owned {
                    ledger,
                    scratch,
                    closed: false,
                }),
                origin,
            }),
            overhead,
        })
    }

    pub fn selector(&self) -> Arc<dyn FlowSelector> {
        self.routes.clone()
    }
    pub fn elapsed(&self, instant: Instant) -> Duration {
        instant.saturating_duration_since(self.routes.origin)
    }

    pub fn reserve(
        &self,
        mode: RoutingMode,
        question: QuestionKey,
        contributions: &[Contribution],
        deadline: Instant,
    ) -> Result<Response, Error> {
        if contributions.is_empty() || contributions.len() > MAX_CONTRIBUTIONS {
            return Err(Error::Ledger(lease::Error::ResourceLimit));
        }
        let mut owner = self.routes.lock()?;
        owner.scratch.clear();
        for contribution in contributions {
            if owner.scratch.contains(&contribution.address) {
                continue;
            }
            if owner.scratch.len() == owner.scratch.capacity() {
                return Err(Error::Ledger(lease::Error::ResourceLimit));
            }
            match self.routes.policy.select(contribution.address) {
                Some(backend) if backend != question.backend => return Err(Error::StaticConflict),
                None if mode == RoutingMode::Static => return Err(Error::MissingStaticCoverage),
                _ => {}
            }
            owner.scratch.push(contribution.address);
        }
        owner
            .ledger
            .reserve(
                self.routes.now()?,
                question,
                contributions,
                self.elapsed(deadline),
            )
            .map_err(Error::Ledger)
    }
    pub fn response_len(&self, response: &Response) -> Result<usize, Error> {
        self.routes
            .lock()?
            .ledger
            .response_len(response)
            .map_err(Error::Ledger)
    }
    pub fn response_route(&self, response: &Response, index: usize) -> Result<Route, Error> {
        self.routes
            .lock()?
            .ledger
            .response_route(response, index)
            .map_err(Error::Ledger)
    }
    pub fn confirm_publication(&self, route: Route) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .confirm_publication(route)
            .map_err(Error::Ledger)
    }
    pub fn mark_uncertain(&self, route: Route) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .mark_uncertain(route)
            .map_err(Error::Ledger)
    }
    pub fn handoff(&self, response: &mut Response, grace: Duration) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .handoff(self.routes.now()?, response, grace)
            .map_err(Error::Ledger)
    }
    pub fn cancel(&self, response: &mut Response) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .cancel(response)
            .map_err(Error::Ledger)
    }
    pub fn changes(&self) -> Result<lease::Changes, Error> {
        self.routes.lock()?.ledger.changes().map_err(Error::Ledger)
    }
    pub fn next_expiry(&self) -> Result<Option<Instant>, Error> {
        self.routes
            .lock()?
            .ledger
            .next_expiry()
            .map(|elapsed| {
                self.routes
                    .origin
                    .checked_add(elapsed)
                    .ok_or(Error::InvalidClock)
            })
            .transpose()
    }
    pub fn advance(&self) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .advance(self.routes.now()?)
            .map_err(Error::Ledger)
    }
    pub fn route_info(&self, route: Route) -> Result<RouteInfo, Error> {
        self.routes
            .lock()?
            .ledger
            .route_info(route)
            .map_err(Error::Ledger)
    }
    pub fn retirement_candidate(&self) -> Result<Option<Route>, Error> {
        let mut owner = self.routes.lock()?;
        owner
            .ledger
            .advance(self.routes.now()?)
            .map_err(Error::Ledger)?;
        Ok(owner.ledger.retirement_candidate())
    }
    pub fn begin_retirement(&self, route: Route) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .begin_retirement(self.routes.now()?, route)
            .map_err(Error::Ledger)
    }
    pub fn finish_retirement(&self, route: Route) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .finish_retirement(route)
            .map_err(Error::Ledger)
    }
    pub fn restore_committed(&self, route: Route) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .restore_committed(route)
            .map_err(Error::Ledger)
    }
    pub fn close(&self) -> Result<(), Error> {
        let mut owner = self.routes.lock()?;
        owner.closed = true;
        owner.ledger.close();
        Ok(())
    }
    pub fn finish_drain(&self) -> Result<(), Error> {
        self.routes
            .lock()?
            .ledger
            .finish_drain(self.routes.now()?)
            .map_err(Error::Ledger)
    }
    pub fn stats(&self) -> Result<Stats, Error> {
        Ok(self.routes.lock()?.ledger.stats())
    }
    pub fn reserved_bytes(&self) -> Result<usize, Error> {
        Ok(self.stats()?.reserved_bytes + self.overhead)
    }
}

impl LiveRoutes {
    fn now(&self) -> Result<Duration, Error> {
        Instant::now()
            .checked_duration_since(self.origin)
            .ok_or(Error::InvalidClock)
    }
    fn lock(&self) -> Result<MutexGuard<'_, Owned>, Error> {
        self.owner.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => Error::Busy,
            TryLockError::Poisoned(_) => Error::Unavailable,
        })
    }
    fn selection_lock(&self) -> Result<MutexGuard<'_, Owned>, SelectionError> {
        self.lock().map_err(|error| match error {
            Error::Busy => SelectionError::Busy,
            _ => SelectionError::Unavailable,
        })
    }
}
impl FlowSelector for LiveRoutes {
    fn static_policy(&self) -> &Policy {
        &self.policy
    }
    fn lookup(&self, destination: IpAddr) -> Result<BackendId, SelectionError> {
        let owner = self.selection_lock()?;
        if let Some(route) = owner.ledger.route_for(destination) {
            let backend = owner
                .ledger
                .route_info(route)
                .map_err(|_| SelectionError::Unavailable)?
                .key
                .backend;
            if self
                .policy
                .select(destination)
                .is_some_and(|static_backend| static_backend != backend)
            {
                return Err(SelectionError::Unavailable);
            }
            return Ok(backend);
        }
        self.policy
            .select(destination)
            .ok_or(SelectionError::Unselected)
    }
    fn select_flow(&self, destination: IpAddr) -> Result<Selection, SelectionError> {
        let mut owner = self.selection_lock()?;
        if owner.closed {
            return Err(SelectionError::Unready);
        }
        owner
            .ledger
            .advance(self.now().map_err(|_| SelectionError::Unavailable)?)
            .map_err(|_| SelectionError::Unavailable)?;
        let static_backend = self.policy.select(destination);
        let Some(route) = owner.ledger.route_for(destination) else {
            return static_backend
                .map(Selection::static_route)
                .ok_or(SelectionError::Unselected);
        };
        let info = owner
            .ledger
            .route_info(route)
            .map_err(|_| SelectionError::Unavailable)?;
        if static_backend.is_some_and(|backend| backend != info.key.backend) {
            return Err(SelectionError::Unavailable);
        }
        if info.publication != lease::Publication::Committed {
            return Err(SelectionError::Unready);
        }
        match owner
            .ledger
            .acquire_flow(self.now().map_err(|_| SelectionError::Unavailable)?, route)
        {
            Ok(pin) => Ok(Selection::leased(info.key.backend, pin)),
            Err(lease::Error::NotCommitted) if static_backend == Some(info.key.backend) => {
                Ok(Selection::static_route(info.key.backend))
            }
            Err(lease::Error::ResourceLimit) => Err(SelectionError::Busy),
            Err(lease::Error::NotCommitted | lease::Error::Retiring | lease::Error::Closed) => {
                Err(SelectionError::Unready)
            }
            Err(_) => Err(SelectionError::Unavailable),
        }
    }
    fn verify_retirement(
        &self,
        destination: IpAddr,
        backend: BackendId,
    ) -> Result<(), SelectionError> {
        let owner = self.selection_lock()?;
        let route = owner
            .ledger
            .route_for(destination)
            .ok_or(SelectionError::Unready)?;
        let info = owner
            .ledger
            .route_info(route)
            .map_err(|_| SelectionError::Unavailable)?;
        if info.key.backend != backend
            || info.publication != lease::Publication::Retiring
            || info.leases != 0
            || info.flows != 0
        {
            return Err(SelectionError::Unready);
        }
        if self
            .policy
            .select(destination)
            .is_some_and(|selected| selected != backend)
        {
            return Err(SelectionError::Unavailable);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
