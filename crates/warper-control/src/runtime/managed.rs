// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed protected managed bytes; service validation and authorization are separate.

pub use super::storage::{Error, PendingInspection, Snapshot};
use super::{RuntimeLease, storage::FixedStore};
pub const MAX_PAYLOAD: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    Runtime(super::Error),
    Busy,
}
impl std::fmt::Display for ClaimError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => std::fmt::Display::fmt(error, formatter),
            Self::Busy => formatter.write_str("Busy: approved configuration ownership is retained"),
        }
    }
}
impl std::error::Error for ClaimError {}

/// One approved-configuration manager per exclusive runtime. Share an Arc of
/// this guard with approved leases so manager drop cannot bypass their fence.
pub struct Ownership {
    lease: std::sync::Arc<RuntimeLease>,
}
impl Ownership {
    pub fn acquire(lease: std::sync::Arc<RuntimeLease>) -> Result<Self, ClaimError> {
        use std::sync::atomic::Ordering;

        lease.revalidate().map_err(ClaimError::Runtime)?;
        lease
            .managed_claim
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ClaimError::Busy)?;
        Ok(Self { lease })
    }
}
impl Drop for Ownership {
    fn drop(&mut self) {
        self.lease
            .managed_claim
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Synchronous storage under a retained runtime lease. No caller path exists.
/// Callers retain/join blocking workers, including after observer timeout.
///
/// ```compile_fail
/// use warper_control::runtime::managed::ManagedStore;
/// let store = ManagedStore::open("/tmp/claimed-state");
/// ```
pub struct ManagedStore(FixedStore);
impl ManagedStore {
    pub fn open(lease: &RuntimeLease) -> Result<Self, Error> {
        FixedStore::open_managed(lease).map(Self)
    }
    pub fn read(&self, lease: &RuntimeLease) -> Result<Option<Snapshot>, Error> {
        self.0.read(lease)
    }
    pub fn inspect(&self, lease: &RuntimeLease) -> Result<Option<Snapshot>, Error> {
        self.0.inspect(lease)
    }
    pub fn replace(
        &mut self,
        lease: &RuntimeLease,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<Snapshot, Error> {
        self.0.replace(lease, expected_revision, payload)
    }
    pub fn resync(&mut self, lease: &RuntimeLease) -> Result<(), Error> {
        self.0.resync(lease)
    }
    pub fn inspect_pending(
        &self,
        lease: &RuntimeLease,
    ) -> Result<Option<PendingInspection>, Error> {
        self.0.inspect_pending(lease)
    }
    pub fn discard_pending(
        &mut self,
        lease: &RuntimeLease,
        token: PendingInspection,
    ) -> Result<(), Error> {
        self.0.discard_pending(lease, token)
    }
}
impl std::fmt::Debug for ManagedStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ManagedStore(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::Fixture;
    use std::sync::Arc;

    #[test]
    fn retained_configuration_ownership_blocks_reclaim_and_keeps_runtime_locked() {
        let fixture = Fixture::new();
        let lease = Arc::new(fixture.acquire().unwrap());
        let weak = Arc::downgrade(&lease);
        let ownership = Arc::new(Ownership::acquire(lease.clone()).unwrap());
        assert!(matches!(
            Ownership::acquire(lease.clone()),
            Err(ClaimError::Busy)
        ));
        let retained = ownership.clone();
        drop(ownership);
        assert!(matches!(
            Ownership::acquire(lease.clone()),
            Err(ClaimError::Busy)
        ));
        drop(retained);
        let reclaimed = Ownership::acquire(lease.clone()).unwrap();
        drop(lease);
        assert!(matches!(
            fixture.acquire(),
            Err(super::super::Error::AlreadyRunning)
        ));
        drop(reclaimed);
        assert!(weak.upgrade().is_none());
        drop(fixture.acquire().unwrap());
    }
}
