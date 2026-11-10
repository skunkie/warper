// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Shared, nonwaiting reservations for service-owned DNS storage.

use std::{
    fmt,
    ops::Deref,
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
        self.charge(bytes)?;
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
    fn charge(&self, bytes: usize) -> Result<(), Error> {
        self.0
            .used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|sum| *sum <= self.0.limit)
            })
            .map(|_| ())
            .map_err(|_| Error::Full)
    }
}

#[must_use = "retain the reservation until the admitted storage is released"]
pub struct Reservation {
    budget: Budget,
    bytes: usize,
}
impl Reservation {
    pub(super) fn grow(&mut self, bytes: usize) -> Result<(), Error> {
        let total = self.bytes.checked_add(bytes).ok_or(Error::Full)?;
        self.budget.charge(bytes)?;
        self.bytes = total;
        Ok(())
    }
    pub(super) fn budget(&self) -> &Budget {
        &self.budget
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl fmt::Debug for Reservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Reservation([redacted])")
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // Reservations cannot be cloned or released twice. Every increment
        // succeeds before construction, so subtraction cannot underflow.
        self.budget.0.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// Owned result storage whose reservation follows the original vector and its
/// iterator. Values may be borrowed or copied; new caller allocations need
/// their own admission. The underlying vector cannot be extracted or grown.
pub struct Stored<T> {
    values: Vec<T>,
    storage: Option<Arc<Reservation>>,
}
impl<T> Stored<T> {
    pub(super) fn new(values: Vec<T>, storage: Option<Arc<Reservation>>) -> Self {
        Self { values, storage }
    }
}
impl<T> Deref for Stored<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T: fmt::Debug> fmt::Debug for Stored<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.values.fmt(f)
    }
}
impl<'a, T> IntoIterator for &'a Stored<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}
impl<T> IntoIterator for Stored<T> {
    type Item = T;
    type IntoIter = StoredIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        StoredIter {
            values: self.values.into_iter(),
            _storage: self.storage,
        }
    }
}
pub struct StoredIter<T> {
    values: std::vec::IntoIter<T>,
    _storage: Option<Arc<Reservation>>,
}
impl<T> Iterator for StoredIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl<T> ExactSizeIterator for StoredIter<T> {}

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
    #[test]
    fn growing_reservations_preserve_the_owner_on_exhaustion_and_overflow() {
        let budget = Budget::new(10).unwrap();
        let mut storage = budget.reserve(4).unwrap();
        storage.grow(3).unwrap();
        assert_eq!(budget.used(), 7);
        assert_eq!(storage.grow(4), Err(Error::Full));
        assert_eq!(storage.bytes(), 7);
        assert_eq!(budget.used(), 7);
        drop(storage);
        assert_eq!(budget.used(), 0);
        let budget = Budget::new(usize::MAX).unwrap();
        let mut storage = budget.reserve(usize::MAX - 1).unwrap();
        assert_eq!(storage.grow(2), Err(Error::Full));
        assert_eq!(budget.used(), usize::MAX - 1);
        storage.grow(1).unwrap();
        assert_eq!(budget.used(), usize::MAX);
        drop(storage);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn moved_result_iterators_retain_storage_even_after_exhaustion() {
        let budget = Budget::new(42).unwrap();
        let values = Stored::new(vec![1, 2, 3], Some(Arc::new(budget.reserve(42).unwrap())));
        assert_eq!(&*values, &[1, 2, 3]);
        assert_eq!((&values).into_iter().copied().sum::<u32>(), 6);
        let mut values = values.into_iter();
        assert_eq!(values.len(), 3);
        assert_eq!(values.next(), Some(1));
        assert_eq!(values.size_hint(), (2, Some(2)));
        assert_eq!(budget.used(), 42);
        assert_eq!(values.next(), Some(2));
        assert_eq!(values.next(), Some(3));
        assert_eq!(values.next(), None);
        assert_eq!(values.len(), 0);
        assert_eq!(budget.used(), 42);
        drop(values);
        assert_eq!(budget.used(), 0);
    }
}
