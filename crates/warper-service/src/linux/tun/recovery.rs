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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryInspection {
    NoRecord,
    Retired,
    Retirable,
}

/// Synchronous protected reconciliation, for a retained native worker. Stored
/// names/indices never authorize a delete, adoption or a new ready state.
pub fn recover_abandoned(context: &Context, request: Request) -> Result<RecoveryOutcome, Error> {
    Wait::new(request.clone()).map_err(Error::RecoveryWait)?;
    context.revalidate().map_err(Error::Context)?;
    let mut journal = NetworkJournal::open(context.runtime()).map_err(Error::Storage)?;
    let snapshot = journal.read(context.runtime()).map_err(Error::Storage)?;
    match inspect_snapshot(context, snapshot.as_ref(), request.clone())? {
        RecoveryInspection::NoRecord => return Ok(RecoveryOutcome::NoRecord),
        RecoveryInspection::Retired => return Ok(RecoveryOutcome::AlreadyRetired),
        RecoveryInspection::Retirable => {}
    }
    let snapshot = snapshot.ok_or(Error::InvalidState)?;
    let mut record = Record::decode(snapshot.payload())?;
    context.revalidate().map_err(Error::Context)?;
    Wait::new(request)
        .map_err(Error::RecoveryWait)?
        .check()
        .map_err(Error::RecoveryWait)?;
    record.stage = Stage::Retired;
    journal
        .replace(context.runtime(), snapshot.revision(), &record.encode())
        .map_err(Error::Storage)?;
    Ok(RecoveryOutcome::Retired)
}

/// Classify protected recovery state without changing the journal or kernel.
pub fn inspect_abandoned(context: &Context, request: Request) -> Result<RecoveryInspection, Error> {
    Wait::new(request.clone()).map_err(Error::RecoveryWait)?;
    context.revalidate().map_err(Error::Context)?;
    let journal = NetworkJournal::open(context.runtime()).map_err(Error::Storage)?;
    let snapshot = journal.read(context.runtime()).map_err(Error::Storage)?;
    inspect_snapshot(context, snapshot.as_ref(), request)
}

/// The offline coordinator can inspect committed bytes pinned by a pending
/// token. This observation never authorizes a later write or kernel deletion.
pub(crate) fn inspect_snapshot(
    context: &Context,
    snapshot: Option<&warper_control::runtime::journal::Snapshot>,
    request: Request,
) -> Result<RecoveryInspection, Error> {
    let wait = Wait::new(request.clone()).map_err(Error::RecoveryWait)?;
    context.revalidate().map_err(Error::Context)?;
    let Some(snapshot) = snapshot else {
        wait.check().map_err(Error::RecoveryWait)?;
        return Ok(RecoveryInspection::NoRecord);
    };
    let record = Record::decode(snapshot.payload())?;
    if record.stage == Stage::Retired {
        wait.check().map_err(Error::RecoveryWait)?;
        return Ok(RecoveryInspection::Retired);
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
    Ok(RecoveryInspection::Retirable)
}
