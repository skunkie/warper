// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled live selector backed by the production lease ledger.

use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use warper_core::{
    BackendId,
    dns::{
        Name,
        lease::{self, Contribution, Ledger, QuestionKey, Route},
    },
    routing::{FlowSelector, Policy, Selection, SelectionError},
};

pub(crate) struct LeaseRoutes {
    policy: Policy,
    pub(crate) ledger: Mutex<Ledger>,
    pub(crate) route: Route,
    pub(crate) behavior: AtomicU8,
    clock: AtomicU64,
}
impl LeaseRoutes {
    pub(crate) fn new(destination: IpAddr) -> Arc<Self> {
        let mut ledger = Ledger::new(lease::Limits {
            lease_entries: 4,
            route_entries: 4,
            response_entries: 2,
            flow_entries: 8,
            addresses_per_response: 4,
            bytes: 64 * 1024,
        })
        .unwrap();
        let mut response = ledger
            .reserve(
                Duration::ZERO,
                QuestionKey {
                    backend: BackendId(70000),
                    name: Name::from_ascii("fixture.example.test").unwrap(),
                    record_type: 65,
                    class: 1,
                },
                &[Contribution {
                    address: destination,
                    expires_at: Duration::from_secs(1),
                }],
                Duration::from_secs(100),
            )
            .unwrap();
        let route = ledger.response_route(&response, 0).unwrap();
        ledger.confirm_publication(route).unwrap();
        ledger
            .handoff(Duration::ZERO, &mut response, Duration::ZERO)
            .unwrap();
        Arc::new(Self {
            policy: Policy::new(&[], 1).unwrap(),
            ledger: Mutex::new(ledger),
            route,
            behavior: AtomicU8::new(0),
            clock: AtomicU64::new(0),
        })
    }
    pub(crate) fn advance(&self, seconds: u64) {
        self.clock.store(seconds, Ordering::Release);
        self.ledger
            .lock()
            .unwrap()
            .advance(Duration::from_secs(seconds))
            .unwrap();
    }
    fn check(&self) -> Result<(), SelectionError> {
        match self.behavior.load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(SelectionError::Busy),
            2 => Err(SelectionError::Unready),
            _ => Err(SelectionError::Unavailable),
        }
    }
}
impl FlowSelector for LeaseRoutes {
    fn static_policy(&self) -> &Policy {
        &self.policy
    }
    fn lookup(&self, destination: IpAddr) -> Result<BackendId, SelectionError> {
        self.check()?;
        let ledger = self.ledger.lock().unwrap();
        let route = ledger
            .route_for(destination)
            .ok_or(SelectionError::Unselected)?;
        Ok(ledger.route_info(route).unwrap().key.backend)
    }
    fn select_flow(&self, destination: IpAddr) -> Result<Selection, SelectionError> {
        self.check()?;
        let mut ledger = self.ledger.lock().unwrap();
        let route = ledger
            .route_for(destination)
            .ok_or(SelectionError::Unselected)?;
        let backend = ledger.route_info(route).unwrap().key.backend;
        let pin = ledger
            .acquire_flow(
                Duration::from_secs(self.clock.load(Ordering::Acquire)),
                route,
            )
            .map_err(|error| match error {
                lease::Error::ResourceLimit => SelectionError::Busy,
                lease::Error::NotCommitted | lease::Error::Retiring => SelectionError::Unready,
                _ => SelectionError::Unavailable,
            })?;
        Ok(Selection::leased(backend, pin))
    }
}
