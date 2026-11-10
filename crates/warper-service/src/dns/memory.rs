// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Shared, nonwaiting reservations for service-owned DNS storage.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimit,
    Full,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "InvalidConfig: DNS storage budget is invalid",
            Self::Full => "ResourceLimit: DNS storage budget is full",
        })
    }
}
impl std::error::Error for Error {}

struct Shared {
    limit: usize,
    used: AtomicUsize,
}

#[derive(Clone)]
pub struct Budget(Arc<Shared>);
impl Budget {
    pub fn new(limit: usize) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Error::InvalidLimit);
        }
        Ok(Self(Arc::new(Shared {
            limit,
            used: AtomicUsize::new(0),
        })))
    }

    pub fn reserve(&self, bytes: usize) -> Result<Reservation, Error> {
        self.0
            .used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|sum| *sum <= self.0.limit)
            })
            .map_err(|_| Error::Full)?;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
        })
    }

    pub fn limit(&self) -> usize {
        self.0.limit
    }

    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::Relaxed)
    }
}

#[must_use = "retain the reservation until the admitted storage is released"]
pub struct Reservation {
    budget: Budget,
    bytes: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        // Reservations cannot be cloned or released twice. Every increment
        // succeeds before construction, so subtraction cannot underflow.
        self.budget.0.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn exact_exhaustion_overflow_and_release_preserve_the_budget() {
        assert!(matches!(Budget::new(0), Err(Error::InvalidLimit)));
        let budget = Budget::new(usize::MAX).unwrap();
        let reservation = budget.reserve(usize::MAX).unwrap();
        assert_eq!(budget.used(), budget.limit());
        assert!(matches!(budget.reserve(1), Err(Error::Full)));
        assert_eq!(budget.used(), usize::MAX);
        drop(reservation);
        assert_eq!(budget.used(), 0);
        let reservation = budget.reserve(1).unwrap();
        drop(budget);
        drop(reservation);
    }

    #[test]
    fn concurrent_owners_share_one_limit_and_release_only_their_own_bytes() {
        let budget = Budget::new(21).unwrap();
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let budget = budget.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let reservation = budget.reserve(7);
                barrier.wait();
                barrier.wait();
                reservation.is_ok()
            }));
        }
        barrier.wait();
        assert_eq!(budget.used(), 21);
        barrier.wait();
        let successes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 3);
        assert_eq!(budget.used(), 0);
    }
}
