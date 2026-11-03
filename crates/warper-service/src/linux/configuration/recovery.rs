// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use warper_control::runtime::managed::{PendingInspection, Snapshot as Stored};

pub(crate) struct RecoveryPlan {
    pending: Option<PendingInspection>,
    stored: Option<Stored>,
    snapshot: Option<Snapshot>,
    pub(crate) required: bool,
}
impl RecoveryPlan {
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(crate) fn config(&self) -> Option<&Config> {
        self.snapshot.as_ref().map(Snapshot::config)
    }
}
impl Configurations {
    pub(crate) fn retained(&self) -> bool {
        self.approved
            .as_ref()
            .is_some_and(|approved| Arc::strong_count(approved) != 1)
    }
    pub(crate) fn prepare_recovery(&self, peer: &UnixStream) -> Result<RecoveryPlan, Error> {
        self.context.revalidate().map_err(Error::Context)?;
        authorize_admin(peer)?;
        let pending = self
            .store
            .inspect_pending(self.context.runtime())
            .map_err(Error::Storage)?;
        let stored = if let Some(token) = &pending {
            token.committed().cloned()
        } else {
            self.store
                .inspect(self.context.runtime())
                .map_err(Error::Storage)?
        };
        let snapshot = stored
            .as_ref()
            .map(|stored| validate(stored.payload()))
            .transpose()?;
        let required = if pending.is_some() {
            true
        } else {
            match self.status() {
                Ok(_) => false,
                Err(Error::Conflict | Error::Storage(StorageError::RecoveryRequired)) => true,
                Err(error) => return Err(error),
            }
        };
        Ok(RecoveryPlan {
            pending,
            stored,
            snapshot,
            required,
        })
    }

    pub(crate) fn recover(
        &mut self,
        peer: &UnixStream,
        prepared: RecoveryPlan,
    ) -> Result<(), Error> {
        self.context.revalidate().map_err(Error::Context)?;
        authorize_admin(peer)?;
        if self.retained() {
            return Err(Error::Busy);
        }
        if let Some(token) = prepared.pending {
            self.store
                .discard_pending(self.context.runtime(), token)
                .map_err(Error::Storage)?;
        }
        self.store
            .resync(self.context.runtime())
            .map_err(Error::Storage)?;
        let current = self
            .store
            .read(self.context.runtime())
            .map_err(Error::Storage)?;
        if current != prepared.stored {
            return Err(Error::Conflict);
        }
        self.approved = match (current, prepared.snapshot) {
            (None, None) => None,
            (Some(stored), Some(snapshot)) => Some(Arc::new(Approved {
                generation: stored.revision(),
                snapshot,
                context: self.context.clone(),
                _ownership: self.ownership.clone(),
            })),
            _ => return Err(Error::Conflict),
        };
        Ok(())
    }
}
