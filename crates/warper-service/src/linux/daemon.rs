// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Foreground service ownership. Pending cleanup stays owned after a deadline.

use super::{
    controller::{self, Controller, Dispatch, Effect},
    network::{self, Network},
};
use crate::native;
use std::{
    collections::VecDeque, fmt, future::pending, io, os::unix::net::UnixStream as NativeStream,
    sync::Arc, time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until},
};
use warper_control::{
    OwnerPolicy,
    admission::{self, Admission, ClientPermit},
    runtime::{self, endpoint::ControlEndpoint},
    session::{self, AuthorizedRequest, Session},
    wire::Frame,
};
use warper_core::transport::Request;

mod client;
mod worker;

const CHANNEL_CAPACITY: usize = 64;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_OBSERVATION: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_NOTICES: usize = 3;
const MAX_CLIENT_TASKS: usize = 64;

pub type Outcome = Result<network::Report, network::Failure>;
#[derive(Debug)]
pub enum ClientError {
    Session(session::Error),
    Io(io::ErrorKind),
    Deadline,
    ActorLost,
}
#[derive(Debug)]
pub enum Error {
    Runtime(runtime::Error),
    Endpoint(runtime::endpoint::Error),
    Publication(runtime::endpoint::Failure),
    Controller(controller::Error),
    Admission(admission::Error),
    Authentication(warper_control::Error),
    Native(native::Error),
    NetworkFailure(Arc<Outcome>),
    PolicyUpdate {
        primary: Option<Box<controller::Error>>,
        secondary: Box<controller::Error>,
    },
    Io(io::ErrorKind),
    ClientTask,
    NetworkTask,
    ClientProtocol,
    ActorStopped,
    ChannelClosed,
    InvalidState,
    ResourceLimit,
    Deadline,
    OwnershipUncertain,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(f),
            Self::Endpoint(error) => error.fmt(f),
            Self::Publication(error) => error.fmt(f),
            Self::Controller(error) => error.fmt(f),
            Self::Admission(error) => error.fmt(f),
            Self::Authentication(error) => error.fmt(f),
            Self::Native(error) => error.fmt(f),
            Self::NetworkFailure(outcome) => match outcome.as_ref() {
                Err(error) => error.fmt(f),
                Ok(_) => f.write_str("RecoveryRequired: invalid network failure outcome"),
            },
            Self::PolicyUpdate { primary, secondary } => {
                if let Some(primary) = primary {
                    write!(f, "{primary}; control policy refresh also failed")
                } else {
                    secondary.fmt(f)
                }
            }
            Self::Io(_) => f.write_str("NativeIo: daemon control socket operation failed"),
            Self::Deadline => {
                f.write_str("Timeout: daemon cleanup deadline expired with ownership retained")
            }
            Self::OwnershipUncertain => {
                f.write_str("RecoveryRequired: daemon ownership retirement remains unverified")
            }
            Self::ResourceLimit => f.write_str("ResourceLimit: daemon event capacity exhausted"),
            Self::InvalidState => f.write_str("Conflict: daemon lifecycle state is invalid"),
            Self::ClientProtocol => {
                f.write_str("WorkerFailed: service produced an invalid client reply")
            }
            Self::ClientTask | Self::NetworkTask | Self::ActorStopped | Self::ChannelClosed => {
                f.write_str("WorkerFailed: owned daemon task or channel stopped")
            }
        }
    }
}
impl std::error::Error for Error {}
#[derive(Debug, Default)]
pub struct Report {
    pub cleaned: bool,
    pub accepted_clients: u64,
    pub rejected_clients: u64,
    pub client_failures: u64,
    pub detached_replies: u64,
    pub rejected_requests: u64,
    pub networks_started: u64,
    pub network_failures: u64,
    pub last_client_failure: Option<ClientError>,
    pub last_rejection: Option<controller::Error>,
    pub last_outcome: Option<Arc<Outcome>>,
}
#[derive(Debug)]
pub struct Failure {
    pub primary: Option<Error>,
    pub cleanup: Vec<Error>,
    pub report: Box<Report>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.primary {
            error.fmt(f)?;
        } else if let Some(error) = self.cleanup.first() {
            error.fmt(f)?;
        } else {
            f.write_str("RecoveryRequired: daemon cleanup failed")?;
        }
        if !self.cleanup.is_empty() {
            write!(f, "; {} cleanup failure(s)", self.cleanup.len())?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {}

// Drop the kernel peer before the request's final quota lease.
enum Command {
    Admit {
        stream: NativeStream,
        permit: ClientPermit,
    },
    Dispatch {
        peer: Arc<NativeStream>,
        request: AuthorizedRequest,
        response: oneshot::Sender<Response>,
    },
    Connected(u64),
    Finished {
        epoch: u64,
        outcome: Arc<Outcome>,
    },
    StartFailed {
        epoch: u64,
        error: network::Error,
    },
    Shutdown,
}
struct Response {
    frame: Frame,
    request: AuthorizedRequest,
}
enum Event {
    Boot {
        lease: Arc<runtime::RuntimeLease>,
        endpoint: Arc<ControlEndpoint>,
        listener: std::os::unix::net::UnixListener,
        instance: [u8; 16],
        plan: admission::Plan,
        effect: Effect,
    },
    Admitted {
        stream: NativeStream,
        permit: ClientPermit,
    },
    RejectedPeer,
    Reply {
        dispatch: Dispatch,
        request: AuthorizedRequest,
        response: oneshot::Sender<Response>,
    },
    Finished(u64),
    StartFailed(u64),
    Notified,
}
struct Running {
    epoch: u64,
    stop: watch::Sender<bool>,
    observed: Option<watch::Receiver<network::State>>,
    notified: bool,
    task: JoinHandle<(Network, Arc<Outcome>)>,
}
struct Stopped {
    epoch: u64,
    network: Network,
    outcome: Arc<Outcome>,
    notified: bool,
    retry: bool,
}

pub struct Daemon {
    workers: native::Workers,
    actor: Option<native::Task<Result<(), Error>>>,
    retirement: Option<native::Task<Result<(), runtime::endpoint::Error>>>,
    endpoint: Option<Arc<ControlEndpoint>>,
    listener: Option<std::os::unix::net::UnixListener>,
    lease: Option<Arc<runtime::RuntimeLease>>,
    endpoint_failed: bool,
    network_lost: bool,
    unstarted: Option<u64>,
    events_closed: bool,
    admission: Option<Arc<Admission>>,
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<Event>,
    policy: watch::Receiver<Arc<OwnerPolicy>>,
    stop: watch::Sender<bool>,
    join_keep: watch::Sender<bool>,
    clients: JoinSet<Result<(), ClientError>>,
    running: Option<Running>,
    stopped: Option<Stopped>,
    notices: VecDeque<Command>,
    instance: [u8; 16],
    accept_sent: bool,
    used: bool,
    report: Report,
}
impl Daemon {
    /// Starts native bootstrap in one retained worker. Call run and retain this
    /// owner until cleanup is complete; dropping is only emergency cancellation.
    pub fn new() -> Result<Self, Error> {
        let workers = native::Workers::new(1).map_err(Error::Native)?;
        let (commands, inbox) = mpsc::channel(CHANNEL_CAPACITY);
        let (events_out, events) = mpsc::channel(CHANNEL_CAPACITY);
        let (policy_out, policy) = watch::channel(Arc::new(
            OwnerPolicy::new(None).map_err(Error::Authentication)?,
        ));
        let (stop, cancellation) = watch::channel(false);
        let (join_keep, _) = watch::channel(false);
        let actor = workers
            .try_reserve()
            .map_err(Error::Native)?
            .start(move || worker::run(inbox, events_out, policy_out, cancellation));
        Ok(Self {
            workers,
            actor: Some(actor),
            retirement: None,
            endpoint: None,
            listener: None,
            lease: None,
            endpoint_failed: false,
            network_lost: false,
            unstarted: None,
            events_closed: false,
            admission: None,
            commands,
            events,
            policy,
            stop,
            join_keep,
            clients: JoinSet::new(),
            running: None,
            stopped: None,
            notices: VecDeque::with_capacity(MAX_NOTICES),
            instance: [0; 16],
            accept_sent: false,
            used: false,
            report: Report::default(),
        })
    }

    pub async fn run(
        &mut self,
        mut cancellation: watch::Receiver<bool>,
    ) -> Result<Report, Failure> {
        if self.used {
            return Err(Failure {
                primary: Some(Error::InvalidState),
                cleanup: vec![],
                report: Box::default(),
            });
        }
        self.used = true;
        let result = match self.bootstrap(&mut cancellation).await {
            Ok(()) => self.serve(&mut cancellation).await,
            Err(error) => Err(error),
        };
        self.finish(result.err()).await
    }

    pub async fn cleanup(&mut self) -> Result<Report, Failure> {
        self.finish(None).await
    }

    async fn bootstrap(&mut self, cancellation: &mut watch::Receiver<bool>) -> Result<(), Error> {
        let deadline = Instant::now() + NATIVE_OBSERVATION;
        loop {
            tokio::select! { biased;
                () = cancelled(cancellation) => return Ok(()),
                () = sleep_until(deadline) => return Err(Error::Deadline),
                result = actor_result(&mut self.actor, &self.join_keep) => {
                    return match result {
                        Err(native::Error::Deadline) => Err(Error::Deadline),
                        result => { self.actor.take(); match result { Ok(Err(error)) => Err(error), Err(error) => Err(Error::Native(error)), Ok(Ok(())) => Err(Error::ActorStopped) } }
                    };
                }
                event = self.events.recv(), if !self.events_closed => match event {
                    Some(event @ Event::Boot { .. }) => return self.event(event, false),
                    None => self.events_closed = true,
                    _ => return Err(Error::InvalidState),
                }
            }
        }
    }

    async fn serve(&mut self, cancellation: &mut watch::Receiver<bool>) -> Result<(), Error> {
        if self.endpoint.is_none() {
            return Ok(());
        }
        let listener =
            tokio::net::UnixListener::from_std(self.listener.take().ok_or(Error::InvalidState)?)
                .map_err(|error| Error::Io(error.kind()))?;
        let commands = self.commands.clone();
        let mut admitted = None;
        loop {
            self.retry_cleanup()?;
            tokio::select! { biased;
                () = cancelled(cancellation) => return Ok(()),
                event = network_event(&mut self.running) => match event {
                    NetworkEvent::Joined(joined) => self.network_joined(*joined)?,
                    NetworkEvent::State(state) => {
                        if let Some(running) = &mut self.running {
                            match state {
                                Some(network::State::Connected) if !running.notified => { running.notified = true; let epoch = running.epoch; self.notice(Command::Connected(epoch))?; }
                                None => running.observed = None,
                                _ => {},
                            }
                        }
                    }
                },
                result = actor_result(&mut self.actor, &self.join_keep) => match result {
                    Err(native::Error::Deadline) => {},
                    result => { self.actor.take(); return match result { Ok(Err(error)) => Err(error), Err(error) => Err(Error::Native(error)), Ok(Ok(())) => Err(Error::ActorStopped) }; }
                },
                event = self.events.recv(), if !self.events_closed => match event {
                    Some(Event::Admitted { stream, permit }) => {
                        self.accept_sent = false;
                        self.accept(stream, permit)?;
                    }
                    Some(Event::RejectedPeer) => {
                        self.accept_sent = false;
                        self.report.rejected_clients = self.report.rejected_clients.saturating_add(1);
                    }
                    Some(event) => self.event(event, false)?,
                    None => self.events_closed = true,
                },
                joined = self.clients.join_next(), if !self.clients.is_empty() => {
                    if let Some(joined) = joined { self.client_joined(joined, false)?; }
                },
                permit = commands.reserve(), if !self.notices.is_empty() || admitted.is_some() => {
                    let permit = permit.map_err(|_| Error::ChannelClosed)?;
                    let command = if let Some(command) = self.notices.pop_front() { command }
                        else { self.accept_sent = true; admitted.take().ok_or(Error::InvalidState)? };
                    permit.send(command);
                },
                incoming = listener.accept(), if admitted.is_none() && !self.accept_sent => {
                    let (stream, _) = incoming.map_err(|error| Error::Io(error.kind()))?;
                    let admission = self.admission.as_ref().ok_or(Error::InvalidState)?;
                    match admission.try_client() {
                        Ok(permit) => admitted = Some(Command::Admit { stream: stream.into_std().map_err(|error| Error::Io(error.kind()))?, permit }),
                        Err(admission::Error::Full) => self.report.rejected_clients = self.report.rejected_clients.saturating_add(1),
                        Err(error) => return Err(Error::Admission(error)),
                    }
                },
            }
        }
    }

    fn accept(&mut self, stream: NativeStream, permit: ClientPermit) -> Result<(), Error> {
        // Completed task results still occupy metadata until joined; quota
        // release alone must not allow the join set to grow without a bound.
        if self.clients.len() >= MAX_CLIENT_TASKS {
            self.report.rejected_clients = self.report.rejected_clients.saturating_add(1);
            return Ok(());
        }
        self.report.accepted_clients = self.report.accepted_clients.saturating_add(1);
        self.clients.spawn(client::run(
            stream,
            permit,
            self.instance,
            self.policy.clone(),
            self.commands.clone(),
            self.stop.subscribe(),
        ));
        Ok(())
    }
    fn event(&mut self, event: Event, stopping: bool) -> Result<(), Error> {
        match event {
            Event::Boot {
                lease,
                endpoint,
                listener,
                instance,
                plan,
                effect,
            } => {
                if self.endpoint.is_some() {
                    return Err(Error::InvalidState);
                }
                self.endpoint = Some(endpoint);
                if !stopping {
                    self.listener = Some(listener);
                }
                self.lease = Some(lease);
                self.instance = instance;
                self.admission = Some(Arc::new(Admission::new(plan)));
                if !stopping {
                    self.effect(effect)?;
                }
            }
            Event::Reply {
                dispatch,
                request,
                response,
            } => {
                if let Some(error) = dispatch.rejection {
                    self.report.rejected_requests = self.report.rejected_requests.saturating_add(1);
                    self.report.last_rejection = Some(error);
                }
                if !stopping {
                    self.effect(dispatch.effect)?;
                    if response
                        .send(Response {
                            frame: dispatch.reply,
                            request,
                        })
                        .is_err()
                    {
                        self.report.detached_replies =
                            self.report.detached_replies.saturating_add(1);
                    }
                }
            }
            Event::Finished(epoch) if !stopping => {
                let stopped = self.stopped.as_mut().ok_or(Error::InvalidState)?;
                if stopped.epoch != epoch {
                    return Err(Error::InvalidState);
                }
                stopped.notified = true;
                if retired(&stopped.outcome) {
                    self.stopped.take();
                }
            }
            Event::Admitted { .. }
            | Event::RejectedPeer
            | Event::Finished(_)
            | Event::StartFailed(_)
            | Event::Notified
                if stopping => {}
            Event::StartFailed(epoch) => {
                if self.unstarted != Some(epoch) {
                    return Err(Error::InvalidState);
                }
                self.unstarted = None;
            }
            Event::Notified => {}
            _ => return Err(Error::InvalidState),
        }
        Ok(())
    }
    fn effect(&mut self, effect: Effect) -> Result<(), Error> {
        match effect {
            Effect::None => {}
            Effect::AdmissionChanged(plan) => self
                .admission
                .as_ref()
                .ok_or(Error::InvalidState)?
                .reconfigure(plan)
                .map_err(Error::Admission)?,
            Effect::Start {
                epoch,
                configuration,
            } => {
                if self.running.is_some() || self.stopped.is_some() {
                    return Err(Error::InvalidState);
                }
                match Network::new(configuration) {
                    Ok(network) => {
                        self.launch(epoch, network, false);
                        self.report.networks_started =
                            self.report.networks_started.saturating_add(1);
                    }
                    Err(error) => {
                        self.unstarted = Some(epoch);
                        self.notice(Command::StartFailed { epoch, error })?;
                    }
                }
            }
            Effect::Stop { epoch } => {
                if let Some(running) = &self.running {
                    if running.epoch != epoch {
                        return Err(Error::InvalidState);
                    }
                    running.stop.send_replace(true);
                } else if let Some(stopped) = &mut self.stopped {
                    if stopped.epoch != epoch {
                        return Err(Error::InvalidState);
                    }
                    stopped.retry = true;
                } else if self.unstarted != Some(epoch) {
                    return Err(Error::InvalidState);
                }
            }
        }
        Ok(())
    }
    fn launch(&mut self, epoch: u64, mut network: Network, cleanup: bool) {
        let (stop, cancellation) = watch::channel(false);
        let (state, observed) = watch::channel(network::State::Starting);
        let task = tokio::spawn(async move {
            let result = if cleanup {
                network.cleanup().await
            } else {
                network.run(cancellation, &state).await
            };
            (network, Arc::new(result))
        });
        self.running = Some(Running {
            epoch,
            stop,
            observed: (!cleanup).then_some(observed),
            notified: cleanup,
            task,
        });
    }
    fn notice(&mut self, command: Command) -> Result<(), Error> {
        if self.notices.len() >= MAX_NOTICES {
            return Err(Error::ResourceLimit);
        }
        self.notices.push_back(command);
        Ok(())
    }
    fn network_joined(
        &mut self,
        joined: Result<(Network, Arc<Outcome>), tokio::task::JoinError>,
    ) -> Result<(), Error> {
        let running = self.running.take().ok_or(Error::InvalidState)?;
        let (network, outcome) = match joined {
            Ok(joined) => joined,
            Err(_) => {
                self.network_lost = true;
                return Err(Error::NetworkTask);
            }
        };
        if outcome.is_err() {
            self.report.network_failures = self.report.network_failures.saturating_add(1);
        }
        self.report.last_outcome = Some(outcome.clone());
        let epoch = running.epoch;
        self.stopped = Some(Stopped {
            epoch,
            network,
            outcome: outcome.clone(),
            notified: false,
            retry: false,
        });
        self.notice(Command::Finished { epoch, outcome })
    }
    fn retry_cleanup(&mut self) -> Result<(), Error> {
        if self
            .stopped
            .as_ref()
            .is_some_and(|owner| owner.notified && owner.retry)
        {
            let stopped = self.stopped.take().ok_or(Error::InvalidState)?;
            self.launch(stopped.epoch, stopped.network, true);
        }
        Ok(())
    }
    fn client_joined(
        &mut self,
        joined: Result<Result<(), ClientError>, tokio::task::JoinError>,
        stopping: bool,
    ) -> Result<(), Error> {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let fatal = matches!(
                    &error,
                    ClientError::ActorLost
                        | ClientError::Session(
                            session::Error::UnexpectedReply
                                | session::Error::Sequence
                                | session::Error::InvalidLimits
                                | session::Error::InvalidInstance
                                | session::Error::Admission(admission::Error::Closed)
                        )
                );
                self.report.client_failures = self.report.client_failures.saturating_add(1);
                self.report.last_client_failure = Some(error);
                if fatal && !stopping {
                    return Err(Error::ClientProtocol);
                }
            }
            Err(error) if stopping && error.is_cancelled() => {}
            Err(_) => return Err(Error::ClientTask),
        }
        Ok(())
    }

    async fn finish(&mut self, primary: Option<Error>) -> Result<Report, Failure> {
        self.finish_until(primary, Instant::now() + STOP_TIMEOUT)
            .await
    }
    async fn finish_until(
        &mut self,
        primary: Option<Error>,
        deadline: Instant,
    ) -> Result<Report, Failure> {
        self.stop.send_replace(true);
        self.listener.take();
        if let Some(admission) = &self.admission {
            admission.close();
        }
        if let Some(running) = &self.running {
            running.stop.send_replace(true);
        }
        self.clients.abort_all();
        // A full inbox is already waking the actor, which checks stop before
        // its next mutation. An empty inbox needs this explicit wakeup.
        match self.commands.try_send(Command::Shutdown) {
            Ok(())
            | Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {}
        }
        self.notices.clear();
        let mut errors = Vec::new();
        let mut attempted = false;
        loop {
            while let Ok(event) = self.events.try_recv() {
                if let Err(error) = self.event(event, true) {
                    errors.push(error);
                }
            }
            if self.running.is_none()
                && let Some(stopped) = self.stopped.take()
            {
                if retired(&stopped.outcome) {
                    drop(stopped);
                } else if !attempted {
                    attempted = true;
                    self.launch(stopped.epoch, stopped.network, true);
                } else {
                    self.stopped = Some(stopped);
                }
            }
            if self.actor.is_none() && self.clients.is_empty() && self.running.is_none() {
                break;
            }
            tokio::select! { biased;
                joined = network_result(&mut self.running) => {
                    let epoch = self.running.as_ref().map(|owner| owner.epoch);
                    self.running.take();
                    match (epoch, joined) {
                        (Some(epoch), Ok((network, outcome))) => {
                            if outcome.is_err() { self.report.network_failures = self.report.network_failures.saturating_add(1); }
                            if let Err(failure) = outcome.as_ref() && !(failure.primary == Some(network::Error::Cancelled) && !failure.cleanup.failed() && failure.report.retired) {
                                errors.push(Error::NetworkFailure(outcome.clone()));
                            }
                            self.report.last_outcome = Some(outcome.clone());
                            self.stopped = Some(Stopped { epoch, network, outcome, notified: true, retry: false });
                        }
                        _ => { self.network_lost = true; errors.push(Error::NetworkTask); },
                    }
                }
                result = actor_result(&mut self.actor, &self.join_keep) => match result {
                    Err(native::Error::Deadline) => {},
                    result => {
                        self.actor.take();
                        match result { Ok(Ok(())) => {}, Ok(Err(error)) => errors.push(error), Err(error) => errors.push(Error::Native(error)) }
                    }
                },
                event = self.events.recv(), if self.actor.is_some() && !self.events_closed => {
                    match event { Some(event) => if let Err(error) = self.event(event, true) { errors.push(error); }, None => self.events_closed = true }
                },
                joined = self.clients.join_next(), if !self.clients.is_empty() => { if let Some(joined) = joined && let Err(error) = self.client_joined(joined, true) { errors.push(error); } },
                () = sleep_until(deadline) => { errors.push(Error::Deadline); break; },
            }
        }
        if self.actor.is_none()
            && self.running.is_none()
            && self.stopped.is_none()
            && self.clients.is_empty()
            && !self.network_lost
        {
            if let Err(error) = self.retire(deadline).await {
                errors.push(error);
            }
        } else if !errors.iter().any(|error| matches!(error, Error::Deadline)) {
            errors.push(Error::OwnershipUncertain);
        }
        self.report.cleaned = self.actor.is_none()
            && self.running.is_none()
            && self.stopped.is_none()
            && self.clients.is_empty()
            && self.endpoint.is_none()
            && self.retirement.is_none()
            && !self.network_lost
            && !self.endpoint_failed;
        if self.report.cleaned {
            self.lease.take();
        }
        let report = std::mem::take(&mut self.report);
        if primary.is_none() && errors.is_empty() && report.cleaned {
            Ok(report)
        } else {
            Err(Failure {
                primary,
                cleanup: errors,
                report: Box::new(report),
            })
        }
    }
    async fn retire(&mut self, deadline: Instant) -> Result<(), Error> {
        if self.retirement.is_none()
            && let Some(endpoint) = self.endpoint.take()
        {
            let reservation = match self.workers.try_reserve() {
                Ok(slot) => slot,
                Err(error) => {
                    self.endpoint = Some(endpoint);
                    return Err(Error::Native(error));
                }
            };
            let endpoint = match Arc::try_unwrap(endpoint) {
                Ok(endpoint) => endpoint,
                Err(endpoint) => {
                    self.endpoint = Some(endpoint);
                    return Err(Error::OwnershipUncertain);
                }
            };
            self.retirement = Some(reservation.start(move || endpoint.close()));
        }
        if let Some(task) = &mut self.retirement {
            let result = task
                .wait(Request {
                    deadline,
                    cancellation: self.join_keep.subscribe(),
                })
                .await;
            match result {
                Ok(result) => {
                    self.retirement.take();
                    if let Err(error) = result {
                        self.endpoint_failed = true;
                        return Err(Error::Endpoint(error));
                    }
                }
                Err(error) => return Err(Error::Native(error)),
            }
        }
        Ok(())
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        let _wake = self.commands.try_send(Command::Shutdown);
        self.clients.abort_all();
        if let Some(running) = &self.running {
            running.stop.send_replace(true);
            running.task.abort();
        }
        // Native work is not asynchronously abortable. Its closure/result owns
        // runtime resources until completion or process termination.
    }
}
async fn actor_result(
    actor: &mut Option<native::Task<Result<(), Error>>>,
    keep: &watch::Sender<bool>,
) -> Result<Result<(), Error>, native::Error> {
    match actor {
        Some(actor) => {
            actor
                .wait(Request {
                    deadline: Instant::now() + NATIVE_OBSERVATION,
                    cancellation: keep.subscribe(),
                })
                .await
        }
        None => pending().await,
    }
}
async fn network_result(
    running: &mut Option<Running>,
) -> Result<(Network, Arc<Outcome>), tokio::task::JoinError> {
    match running {
        Some(running) => (&mut running.task).await,
        None => pending().await,
    }
}
enum NetworkEvent {
    Joined(Box<Result<(Network, Arc<Outcome>), tokio::task::JoinError>>),
    State(Option<network::State>),
}
async fn network_event(running: &mut Option<Running>) -> NetworkEvent {
    let Some(running) = running else {
        return pending().await;
    };
    tokio::select! { biased;
        joined = &mut running.task => NetworkEvent::Joined(Box::new(joined)),
        state = async {
            match &mut running.observed {
                Some(observed) => if observed.changed().await.is_err() { None } else { Some(*observed.borrow_and_update()) },
                None => pending().await,
            }
        } => NetworkEvent::State(state),
    }
}
fn retired(outcome: &Outcome) -> bool {
    match outcome {
        Ok(report) => report.retired,
        Err(failure) => failure.report.retired,
    }
}
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() || cancel.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
