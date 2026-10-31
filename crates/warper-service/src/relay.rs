// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded retained relay workers; client connections never own these tasks.

use std::{fmt, io, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    task::{JoinError, JoinSet},
    time::{Instant, timeout_at},
};
use warper_core::{
    BackendId,
    transport::{Backend, Capabilities, CapturedTcp, Error as SetupError, Request},
};

mod transfer;

pub const COPY_BUFFER_BYTES: usize = 8192;
const MAX_FLOWS: usize = 1024;
const MAX_BACKENDS: usize = 64;
const MAX_DURATION: Duration = Duration::from_secs(365 * 86400);

#[derive(Clone, Copy)]
pub struct Limits {
    pub flows: usize,
    pub setup_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_age: Duration,
    pub shutdown_timeout: Duration,
}
impl Limits {
    fn validate(self) -> Result<(), AdmissionError> {
        if self.flows == 0
            || self.flows > MAX_FLOWS
            || [
                self.setup_timeout,
                self.idle_timeout,
                self.max_age,
                self.shutdown_timeout,
            ]
            .iter()
            .any(|value| *value < Duration::from_millis(1) || *value > MAX_DURATION)
        {
            return Err(AdmissionError::InvalidLimits);
        }
        Ok(())
    }
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            flows: 1024,
            setup_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            max_age: Duration::from_secs(86400),
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    InvalidLimits,
    InvalidBackends,
    DuplicateFlow,
    InvalidFlow,
    UnknownBackend,
    UnsupportedCapability,
    Full,
    Stopping,
    InvalidClock,
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP relay admission: {self:?}")
    }
}
impl std::error::Error for AdmissionError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowError {
    Setup(SetupError),
    Io(io::ErrorKind),
    Cancelled,
    IdleTimeout,
    MaxAge,
    InvalidClock,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Transferred {
    pub sent: u64,
    pub received: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub id: u64,
    pub backend: BackendId,
    pub transferred: Transferred,
    pub outcome: Result<(), FlowError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerError {
    Panicked,
    Cancelled,
}
impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP relay worker: {self:?}")
    }
}
impl std::error::Error for WorkerError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownError {
    Deadline,
    InvalidClock,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub admitted: u64,
    pub finished: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub worker_failures: u64,
    pub aborted: u64,
    pub transferred: Transferred,
    pub first_flow_failure: Option<Completion>,
    pub first_worker_failure: Option<WorkerError>,
    pub shutdown_error: Option<ShutdownError>,
}

struct Registration {
    id: BackendId,
    capabilities: Capabilities,
    backend: Arc<dyn Backend>,
}
pub struct Relays {
    tasks: JoinSet<Completion>,
    active: Vec<u64>,
    backends: Box<[Registration]>,
    limits: Limits,
    cancel: watch::Sender<bool>,
    stopping: bool,
    report: Report,
}
impl Relays {
    pub fn new(backends: Vec<Arc<dyn Backend>>, limits: Limits) -> Result<Self, AdmissionError> {
        limits.validate()?;
        if backends.is_empty() || backends.len() > MAX_BACKENDS {
            return Err(AdmissionError::InvalidBackends);
        }
        let mut registrations = Vec::with_capacity(backends.len());
        for backend in backends {
            let id = backend.id();
            if registrations
                .iter()
                .any(|entry: &Registration| entry.id == id)
            {
                return Err(AdmissionError::InvalidBackends);
            }
            registrations.push(Registration {
                id,
                capabilities: backend.capabilities(),
                backend,
            });
        }
        let (cancel, _receiver) = watch::channel(false);
        Ok(Self {
            tasks: JoinSet::new(),
            active: Vec::with_capacity(limits.flows),
            backends: registrations.into_boxed_slice(),
            limits,
            cancel,
            stopping: false,
            report: Report::default(),
        })
    }
    pub fn admit(&mut self, flow: CapturedTcp) -> Result<(), AdmissionError> {
        if self.stopping {
            return Err(AdmissionError::Stopping);
        }
        if flow.metadata.id == 0 || flow.metadata.destination.port() == 0 {
            return Err(AdmissionError::InvalidFlow);
        }
        if self.active.contains(&flow.metadata.id) {
            return Err(AdmissionError::DuplicateFlow);
        }
        if self.tasks.len() >= self.limits.flows {
            return Err(AdmissionError::Full);
        }
        let registration = self
            .backends
            .iter()
            .find(|entry| entry.id == flow.metadata.backend)
            .ok_or(AdmissionError::UnknownBackend)?;
        let capabilities = registration.capabilities;
        if !capabilities.tcp
            || !(if flow.metadata.destination.is_ipv4() {
                capabilities.ipv4
            } else {
                capabilities.ipv6
            })
        {
            return Err(AdmissionError::UnsupportedCapability);
        }
        let now = Instant::now();
        let end = now
            .checked_add(self.limits.max_age)
            .ok_or(AdmissionError::InvalidClock)?;
        let setup = now
            .checked_add(self.limits.setup_timeout)
            .ok_or(AdmissionError::InvalidClock)?
            .min(end);
        let id = flow.metadata.id;
        self.tasks.spawn(transfer::run(
            flow,
            registration.backend.clone(),
            Request {
                deadline: setup,
                cancellation: self.cancel.subscribe(),
            },
            end,
            self.limits.idle_timeout,
        ));
        self.active.push(id);
        self.report.admitted = self.report.admitted.saturating_add(1);
        Ok(())
    }
    pub async fn next(&mut self) -> Result<Option<Completion>, WorkerError> {
        let Some(result) = self.tasks.join_next().await else {
            return Ok(None);
        };
        self.observe(result).map(Some)
    }
    pub fn stop(&mut self) {
        self.stopping = true;
        // send_replace also preserves cancellation when no receiver remains.
        self.cancel.send_replace(true);
    }
    pub async fn shutdown(mut self) -> Report {
        self.stop();
        let deadline = Instant::now().checked_add(self.limits.shutdown_timeout);
        let Some(deadline) = deadline else {
            self.report.shutdown_error = Some(ShutdownError::InvalidClock);
            self.abort_remaining().await;
            return self.report;
        };
        while !self.tasks.is_empty() {
            let result = timeout_at(deadline, self.tasks.join_next()).await;
            match result {
                Ok(Some(result)) => {
                    let _ = self.observe(result);
                }
                Ok(None) => break,
                Err(_) => {
                    self.report.shutdown_error = Some(ShutdownError::Deadline);
                    self.abort_remaining().await;
                    break;
                }
            }
        }
        self.report
    }
    pub fn retained(&self) -> usize {
        self.tasks.len()
    }
    pub fn required_buffer_capacity(limits: Limits) -> Result<usize, AdmissionError> {
        limits.validate()?;
        Ok(limits.flows * COPY_BUFFER_BYTES * 2)
    }
    async fn abort_remaining(&mut self) {
        self.tasks.abort_all();
        while let Some(result) = self.tasks.join_next().await {
            match result {
                Err(error) if error.is_cancelled() => {
                    self.report.aborted = self.report.aborted.saturating_add(1);
                    self.report.cancelled = self.report.cancelled.saturating_add(1)
                }
                other => {
                    let _ = self.observe(other);
                }
            }
        }
        self.active.clear();
    }
    fn observe(
        &mut self,
        result: Result<Completion, JoinError>,
    ) -> Result<Completion, WorkerError> {
        let completion = match result {
            Ok(completion) => completion,
            Err(error) => {
                self.stop();
                self.report.worker_failures = self.report.worker_failures.saturating_add(1);
                let cause = if error.is_panic() {
                    WorkerError::Panicked
                } else {
                    WorkerError::Cancelled
                };
                self.report.first_worker_failure.get_or_insert(cause);
                return Err(cause);
            }
        };
        self.active.retain(|id| *id != completion.id);
        match completion.outcome {
            Ok(()) => self.report.finished = self.report.finished.saturating_add(1),
            Err(FlowError::Cancelled | FlowError::Setup(SetupError::Cancelled)) => {
                self.report.cancelled = self.report.cancelled.saturating_add(1)
            }
            Err(_) => {
                self.report.failed = self.report.failed.saturating_add(1);
                self.report.first_flow_failure.get_or_insert(completion);
            }
        }
        self.report.transferred.sent = self
            .report
            .transferred
            .sent
            .saturating_add(completion.transferred.sent);
        self.report.transferred.received = self
            .report
            .transferred
            .received
            .saturating_add(completion.transferred.received);
        Ok(completion)
    }
}
#[cfg(test)]
mod tests;
