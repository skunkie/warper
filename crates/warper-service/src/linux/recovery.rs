// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Stopped-service inspection under the actual exclusive native runtime lease.

use super::{configuration, context::Context, tun};
use std::{fmt, sync::Arc, time::Duration};
use warper_control::runtime::{
    RuntimeLease, connection::ConnectionStore, endpoint, enrollment::OwnerStore,
    journal::NetworkJournal, managed::ManagedStore,
};
use warper_core::transport::Request;

#[derive(Debug)]
pub enum Error {
    Runtime(warper_control::runtime::Error),
    Endpoint(endpoint::Error),
    Owner(warper_control::runtime::enrollment::Error),
    Connection(warper_control::runtime::connection::Error),
    Storage(warper_control::runtime::journal::Error),
    Configuration(configuration::Error),
    Context(super::context::Error),
    Network(tun::Error),
    Invariant,
    Incomplete(Box<Error>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(f),
            Self::Endpoint(error) => error.fmt(f),
            Self::Owner(error) => error.fmt(f),
            Self::Connection(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
            Self::Configuration(error) => error.fmt(f),
            Self::Context(error) => error.fmt(f),
            Self::Network(error) => error.fmt(f),
            Self::Invariant => {
                f.write_str("RecoveryRequired: exclusive recovery ownership was lost")
            }
            Self::Incomplete(primary) => {
                write!(f, "Recovery incomplete: {primary}; inspect before retrying")
            }
        }
    }
}
impl std::error::Error for Error {}

struct Prepared {
    owner_pending: Option<warper_control::runtime::enrollment::PendingInspection>,
    owners: OwnerStore,
    configuration_pending: Option<warper_control::runtime::managed::PendingInspection>,
    managed: ManagedStore,
    connection_pending: Option<warper_control::runtime::connection::PendingInspection>,
    connection: ConnectionStore,
    network_pending: Option<warper_control::runtime::journal::PendingInspection>,
    journal: NetworkJournal,
    report: Report,
    request: Request,
    _cancellation_owner: tokio::sync::watch::Sender<bool>,
    // Release every store/token before the persistent instance lock.
    runtime: Arc<RuntimeLease>,
}
impl Prepared {
    fn repair(mut self) -> Result<(), Error> {
        let result = (|| {
            let runtime = Arc::get_mut(&mut self.runtime).ok_or(Error::Invariant)?;
            endpoint::recover(runtime).map_err(Error::Endpoint)?;
            if let Some(token) = self.owner_pending.take() {
                self.owners
                    .discard_pending_offline(runtime, token)
                    .map_err(Error::Owner)?;
            }
            self.owners.resync_offline(runtime).map_err(Error::Owner)?;
            if let Some(token) = self.configuration_pending.take() {
                self.managed
                    .discard_pending(runtime, token)
                    .map_err(Error::Storage)?;
            }
            self.managed.resync(runtime).map_err(Error::Storage)?;
            if let Some(token) = self.connection_pending.take() {
                self.connection
                    .discard_pending(runtime, token)
                    .map_err(Error::Connection)?;
            }
            self.connection.resync(runtime).map_err(Error::Connection)?;
            if let Some(token) = self.network_pending.take() {
                self.journal
                    .discard_pending(runtime, token)
                    .map_err(Error::Storage)?;
            }
            self.journal.resync(runtime).map_err(Error::Storage)?;
            let context =
                Context::capture(self.runtime.clone(), &self.connection).map_err(Error::Context)?;
            tun::recover_abandoned(&context, self.request.clone()).map_err(Error::Network)?;
            Ok(())
        })();
        result.map_err(|primary| Error::Incomplete(Box::new(primary)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    pub endpoint: endpoint::Inspection,
    pub owner_pending: bool,
    pub configuration_pending: bool,
    pub connection_pending: bool,
    pub network_pending: bool,
    pub network: tun::RecoveryInspection,
}
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let yes_no = |present| if present { "yes" } else { "no" };
        writeln!(
            f,
            "Control endpoint: {}",
            match self.endpoint {
                endpoint::Inspection::Absent => "absent",
                endpoint::Inspection::Retirable => "retirable",
            }
        )?;
        writeln!(f, "Owner pending intent: {}", yes_no(self.owner_pending))?;
        writeln!(
            f,
            "Configuration pending intent: {}",
            yes_no(self.configuration_pending)
        )?;
        writeln!(
            f,
            "Connection pending intent: {}",
            yes_no(self.connection_pending)
        )?;
        writeln!(
            f,
            "Network pending intent: {}",
            yes_no(self.network_pending)
        )?;
        writeln!(
            f,
            "Network ownership: {}",
            match self.network {
                tun::RecoveryInspection::NoRecord => "absent",
                tun::RecoveryInspection::Retired => "retired",
                tun::RecoveryInspection::Retirable => "retirable",
            }
        )
    }
}

/// Synchronous native entry point. No service, configuration source or backend
/// is started, and no asynchronous task survives the call. Filesystem/account
/// inspection has no hard kernel deadline; native queries share five seconds.
pub fn inspect() -> Result<Report, Error> {
    Ok(prepare()?.report)
}

/// Repair only unchanged unpublished state after complete stopped-service
/// preflight. This never starts a backend or changes accepted connection intent.
pub fn recover() -> Result<(), Error> {
    prepare()?.repair()
}

fn prepare() -> Result<Prepared, Error> {
    let mut runtime = RuntimeLease::acquire().map_err(Error::Runtime)?;
    let endpoint = endpoint::inspect(&runtime).map_err(Error::Endpoint)?;
    let owners = OwnerStore::open(&runtime).map_err(Error::Owner)?;
    let owner_pending = owners
        .inspect_pending_offline(&mut runtime)
        .map_err(Error::Owner)?;
    if owner_pending.is_none() {
        owners.read(&runtime).map_err(Error::Owner)?;
    }
    let connection = ConnectionStore::open(&runtime).map_err(Error::Connection)?;
    let connection_pending = connection
        .inspect_pending(&runtime)
        .map_err(Error::Connection)?;
    if connection_pending.is_none() {
        connection.inspect(&runtime).map_err(Error::Connection)?;
    }
    let managed = ManagedStore::open(&runtime).map_err(Error::Storage)?;
    let configuration_pending = managed.inspect_pending(&runtime).map_err(Error::Storage)?;
    let configuration = if configuration_pending.is_none() {
        managed.inspect(&runtime).map_err(Error::Storage)?
    } else {
        None
    };
    let committed = configuration_pending
        .as_ref()
        .and_then(|token| token.committed())
        .or(configuration.as_ref());
    if let Some(committed) = committed {
        configuration::validate(committed.payload()).map_err(Error::Configuration)?;
    }
    let journal = NetworkJournal::open(&runtime).map_err(Error::Storage)?;
    let network_pending = journal.inspect_pending(&runtime).map_err(Error::Storage)?;
    let network = if network_pending.is_none() {
        journal.inspect(&runtime).map_err(Error::Storage)?
    } else {
        None
    };
    let committed = network_pending
        .as_ref()
        .and_then(|token| token.committed())
        .or(network.as_ref());
    let runtime = Arc::new(runtime);
    let context = Context::capture(runtime.clone(), &connection).map_err(Error::Context)?;
    let (owner, cancellation) = tokio::sync::watch::channel(false);
    let request = Request {
        deadline: tokio::time::Instant::now() + Duration::from_secs(5),
        cancellation,
    };
    let network =
        tun::inspect_snapshot(&context, committed, request.clone()).map_err(Error::Network)?;
    drop(context);
    let report = Report {
        endpoint,
        owner_pending: owner_pending.is_some(),
        configuration_pending: configuration_pending.is_some(),
        connection_pending: connection_pending.is_some(),
        network_pending: network_pending.is_some(),
        network,
    };
    Ok(Prepared {
        owner_pending,
        owners,
        configuration_pending,
        managed,
        connection_pending,
        connection,
        network_pending,
        journal,
        report,
        request,
        _cancellation_owner: owner,
        runtime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_output_distinguishes_absent_and_dirty_state_without_record_contents() {
        let empty = Report {
            endpoint: endpoint::Inspection::Absent,
            owner_pending: false,
            configuration_pending: false,
            connection_pending: false,
            network_pending: false,
            network: tun::RecoveryInspection::NoRecord,
        };
        assert_eq!(
            empty.to_string(),
            "Control endpoint: absent\nOwner pending intent: no\nConfiguration pending intent: no\nConnection pending intent: no\nNetwork pending intent: no\nNetwork ownership: absent\n"
        );
        let dirty = Report {
            endpoint: endpoint::Inspection::Retirable,
            owner_pending: true,
            configuration_pending: true,
            connection_pending: true,
            network_pending: true,
            network: tun::RecoveryInspection::Retirable,
        };
        assert_eq!(
            dirty.to_string(),
            "Control endpoint: retirable\nOwner pending intent: yes\nConfiguration pending intent: yes\nConnection pending intent: yes\nNetwork pending intent: yes\nNetwork ownership: retirable\n"
        );
    }
}
