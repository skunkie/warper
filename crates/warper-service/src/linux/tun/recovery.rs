// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Retire proven-ended initial ownership without deleting any kernel object.

use super::{Context, Error, Record, Stage, ensure_index_absent, transaction::Wait};
use crate::linux::context::ProcessState;
use warper_control::runtime::journal::NetworkJournal;
use warper_core::transport::Request;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    NoRecord,
    AlreadyRetired,
    Retired,
}

/// Synchronous protected reconciliation, for a retained native worker. Stored
/// names/indices never authorize a delete, adoption or a new ready state.
pub fn recover_abandoned(context: &Context, request: Request) -> Result<RecoveryOutcome, Error> {
    let wait = Wait::new(request.clone()).map_err(Error::RecoveryWait)?;
    context.revalidate().map_err(Error::Context)?;
    let mut journal = NetworkJournal::open(context.runtime()).map_err(Error::Storage)?;
    let Some(snapshot) = journal.read(context.runtime()).map_err(Error::Storage)? else {
        wait.check().map_err(Error::RecoveryWait)?;
        return Ok(RecoveryOutcome::NoRecord);
    };
    let mut record = Record::decode(snapshot.payload())?;
    if record.stage == Stage::Retired {
        wait.check().map_err(Error::RecoveryWait)?;
        return Ok(RecoveryOutcome::AlreadyRetired);
    }
    match context
        .owner_process(&record.owner)
        .map_err(Error::Context)?
    {
        ProcessState::Alive => return Err(Error::OwnerAlive),
        ProcessState::Exited | ProcessState::Reused => {
            if let Some(identity) = &record.identity {
                ensure_index_absent(identity.index)?;
            }
            if let Some(plan) = &record.capture {
                plan.inspect_absence(request)?;
            }
        }
        // Kernel resources cannot survive a boot. Matching current names or
        // indices are foreign; no destructive query is authorized by history.
        ProcessState::PreviousBoot => {}
    }
    context.revalidate().map_err(Error::Context)?;
    wait.check().map_err(Error::RecoveryWait)?;
    record.stage = Stage::Retired;
    journal
        .replace(context.runtime(), snapshot.revision(), &record.encode())
        .map_err(Error::Storage)?;
    Ok(RecoveryOutcome::Retired)
}
