// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One parent request's nonrefundable upstream attempt budget.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::ExchangeError;

pub struct QueryBudget {
    limit: usize,
    remaining: AtomicUsize,
}

impl QueryBudget {
    pub fn new(limit: usize) -> Result<Self, ExchangeError> {
        if limit == 0 {
            return Err(ExchangeError::InvalidAdmission);
        }
        Ok(Self {
            limit,
            remaining: AtomicUsize::new(limit),
        })
    }

    pub fn used(&self) -> usize {
        self.limit - self.remaining.load(Ordering::Relaxed)
    }

    pub(super) fn charge(&self) -> Result<(), ExchangeError> {
        self.remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .map(|_| ())
            .map_err(|_| ExchangeError::ResourceLimit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn exhaustion_never_refunds_or_underflows() {
        assert!(matches!(
            QueryBudget::new(0),
            Err(ExchangeError::InvalidAdmission)
        ));
        let budget = QueryBudget::new(1).unwrap();
        assert_eq!(budget.used(), 0);
        budget.charge().unwrap();
        for _ in 0..3 {
            assert_eq!(budget.charge(), Err(ExchangeError::ResourceLimit));
        }
        assert_eq!(budget.used(), 1);
        let large = QueryBudget::new(usize::MAX).unwrap();
        large.charge().unwrap();
        assert_eq!(large.used(), 1);
    }

    #[test]
    fn concurrent_dependencies_share_one_attempt_count() {
        let budget = Arc::new(QueryBudget::new(17).unwrap());
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let budget = budget.clone();
                std::thread::spawn(move || (0..8).filter(|_| budget.charge().is_ok()).count())
            })
            .collect();
        let successes: usize = tasks.into_iter().map(|task| task.join().unwrap()).sum();
        assert_eq!(successes, 17);
        assert_eq!(budget.used(), 17);
    }
}
