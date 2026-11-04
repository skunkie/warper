// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Runtime-created mapping and lifetime observation, without native authority.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Semaphore, mpsc};
use warper_core::{
    BackendId,
    routing::{Entry, FlowSelector, SelectionError},
};

#[derive(Clone)]
pub struct Publication {
    policy: Arc<dyn FlowSelector>,
    input: mpsc::WeakSender<Vec<u8>>,
    lifetimes: Arc<Semaphore>,
    limit: usize,
    quiescent: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
}
impl Publication {
    pub(super) fn new(
        policy: Arc<dyn FlowSelector>,
        input: mpsc::Sender<Vec<u8>>,
        lifetimes: Arc<Semaphore>,
        limit: usize,
        quiescent: Arc<AtomicBool>,
        stopped: Arc<AtomicBool>,
    ) -> Self {
        Self {
            policy,
            input: input.downgrade(),
            lifetimes,
            limit,
            quiescent,
            stopped,
        }
    }
    pub fn entries(&self) -> &[Entry] {
        self.policy.static_policy().entries()
    }
    /// Provider identity only, without granting native readiness or authority.
    pub fn uses_selector(&self, selector: &Arc<dyn FlowSelector>) -> bool {
        Arc::ptr_eq(&self.policy, selector)
    }
    /// Observe this runtime's live mapping without admitting a flow. This is
    /// handler identity, not native publication or network readiness.
    pub fn selected_backend(&self, address: std::net::IpAddr) -> Result<BackendId, SelectionError> {
        if !self.is_published() || self.is_quiescent() {
            return Err(SelectionError::Unavailable);
        }
        self.policy.lookup(address)
    }
    /// Observe unreferenced retirement in this runtime's own selector. The
    /// caller must keep that owner retiring through joined native withdrawal.
    pub fn verify_retirement(
        &self,
        address: std::net::IpAddr,
        backend: BackendId,
    ) -> Result<(), SelectionError> {
        if !self.is_published() {
            return Err(SelectionError::Unavailable);
        }
        self.policy.verify_retirement(address, backend)
    }

    /// Allocated ingress/mapping publication, not task or network readiness.
    pub fn is_published(&self) -> bool {
        !self.stopped.load(Ordering::Acquire)
            && self.input.upgrade().is_some_and(|input| !input.is_closed())
    }
    pub fn is_quiescent(&self) -> bool {
        self.quiescent.load(Ordering::Acquire) || self.stopped.load(Ordering::Acquire)
    }
    pub fn retained_flows(&self) -> usize {
        // The pool is private; only original flow permits can return capacity.
        self.limit - self.lifetimes.available_permits()
    }
    pub fn same_runtime(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.quiescent, &other.quiescent)
    }
}
impl fmt::Debug for Publication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapturePublication(<redacted>)")
    }
}
