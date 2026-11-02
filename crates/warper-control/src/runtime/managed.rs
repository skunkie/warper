// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed protected managed bytes; service validation and authorization are separate.

pub use super::storage::{Error, PendingInspection, Snapshot};
use super::{RuntimeLease, storage::FixedStore};
pub const MAX_PAYLOAD: usize = 1_048_576;

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
