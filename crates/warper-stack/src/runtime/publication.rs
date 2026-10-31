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
use warper_core::routing::{Entry, Policy};

#[derive(Clone)]
pub struct Publication {
    policy: Arc<Policy>,
    input: mpsc::WeakSender<Vec<u8>>,
    lifetimes: Arc<Semaphore>,
    limit: usize,
    quiescent: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
}
impl Publication {
    pub(super) fn new(
        policy: Arc<Policy>,
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
        self.policy.entries()
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
