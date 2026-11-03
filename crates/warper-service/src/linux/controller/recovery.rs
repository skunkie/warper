// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use std::time::Duration;
use warper_control::{message::Recovery, runtime::journal::NetworkJournal};

struct Prepared {
    owner: Option<enrollment::PendingInspection>,
    configuration: configuration::RecoveryPlan,
    connection: Option<connection::PendingInspection>,
    network: Option<warper_control::runtime::journal::PendingInspection>,
    journal: NetworkJournal,
    report: Recovery,
    request: Request,
    _owner: tokio::sync::watch::Sender<bool>,
}
impl Controller {
    pub(super) fn handle_recovery(
        &mut self,
        peer: &UnixStream,
        frame: &Frame,
    ) -> Result<(Frame, Effect), Error> {
        // A diagnostic failure can leave stopping set without a network owner.
        // Only actual pending/retained ownership blocks explicit repair.
        let busy =
            self.active.is_some() || self.pending.is_some() || self.configurations.retained();
        if busy && frame.kind() == Kind::Recover {
            return Err(Error::Rejected(Code::Busy));
        }
        let prepared = self.prepare_recovery(peer, busy)?;
        if frame.kind() == Kind::InspectRecovery {
            return Ok((prepared.report.frame(frame.request_id())?, Effect::None));
        }
        let limits = prepared.configuration.config().map(|config| &config.limits);
        let history = self
            .history
            .resized(limits.map_or(256, |limits| limits.max_control_operations))
            .map_err(history_error)?;
        let admission = plan(limits)?;
        let reply = Frame::new(Kind::Recovered, frame.request_id(), vec![])?;
        // All stores, ownership and replacement budgets are validated above.
        // Failure after this point remains explicit uncertainty, never a replay.
        self.intent_uncertain = true;
        self.state = SessionState::RecoveryRequired;
        if let Some(token) = prepared.owner {
            self.owners
                .discard_pending(self.context.runtime(), peer, token)
                .map_err(|error| Error::Enrollment(error.into()))?;
        }
        self.owners
            .resync(self.context.runtime(), peer)
            .map_err(Error::Owner)?;
        if let Some(token) = prepared.connection {
            self.connection
                .discard_pending(self.context.runtime(), token)
                .map_err(|error| Error::Connection(error.into()))?;
        }
        self.connection
            .resync(self.context.runtime())
            .map_err(|error| Error::Connection(error.into()))?;
        let mut journal = prepared.journal;
        if let Some(token) = prepared.network {
            journal
                .discard_pending(self.context.runtime(), token)
                .map_err(storage_error)?;
        }
        journal
            .resync(self.context.runtime())
            .map_err(storage_error)?;
        tun::recover_abandoned(&self.context, prepared.request).map_err(Error::Recovery)?;
        // Publish refreshed approval only after every other fallible repair.
        // Its admission effect must accompany any new in-memory generation.
        self.configurations
            .recover(peer, prepared.configuration)
            .map_err(Error::Configuration)?;
        self.history = history;
        self.intent_uncertain = false;
        self.stopping = false;
        self.state = SessionState::Disconnected;
        Ok((reply, Effect::AdmissionChanged(admission)))
    }

    fn prepare_recovery(&self, peer: &UnixStream, busy: bool) -> Result<Prepared, Error> {
        let owner = self
            .owners
            .inspect_pending(self.context.runtime(), peer)
            .map_err(Error::Owner)?;
        let configuration = self
            .configurations
            .prepare_recovery(peer)
            .map_err(Error::Configuration)?;
        let connection = self
            .connection
            .inspect_pending(self.context.runtime())
            .map_err(|error| Error::Connection(error.into()))?;
        if connection.is_none() {
            self.connection
                .inspect(self.context.runtime())
                .map_err(|error| Error::Connection(error.into()))?;
        }
        let journal = NetworkJournal::open(self.context.runtime()).map_err(storage_error)?;
        let network = journal
            .inspect_pending(self.context.runtime())
            .map_err(storage_error)?;
        let current = if network.is_none() {
            journal
                .inspect(self.context.runtime())
                .map_err(storage_error)?
        } else {
            None
        };
        let committed = network
            .as_ref()
            .and_then(|token| token.committed())
            .or(current.as_ref());
        let (keep, cancellation) = tokio::sync::watch::channel(false);
        let request = Request {
            deadline: tokio::time::Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        let native_required = match tun::inspect_snapshot(&self.context, committed, request.clone())
        {
            Ok(tun::RecoveryInspection::Retirable) => true,
            Ok(tun::RecoveryInspection::NoRecord | tun::RecoveryInspection::Retired) => false,
            Err(tun::Error::OwnerAlive) if busy => false,
            Err(error) => return Err(Error::Recovery(error)),
        };
        let pending =
            owner.is_some() || configuration.pending() || connection.is_some() || network.is_some();
        let report = Recovery {
            pending,
            required: pending
                || configuration.required
                || self.intent_uncertain
                || self.state == SessionState::RecoveryRequired
                || native_required,
            busy,
        };
        Ok(Prepared {
            owner,
            configuration,
            connection,
            network,
            journal,
            report,
            request,
            _owner: keep,
        })
    }
}
fn storage_error(error: warper_control::runtime::journal::Error) -> Error {
    Error::Recovery(tun::Error::Storage(error))
}
