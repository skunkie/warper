// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Service-owned networking through acknowledged startup and explicit retirement.

use std::{
    fmt,
    future::{Future, poll_fn},
    num::NonZeroU32,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use warper_config::schema::Platform;
use warper_core::transport::Request;
use warper_stack::{
    Seed,
    runtime::{self, Channels},
};

use super::{
    change_monitor::Invalidation,
    configuration::ConfigurationLease,
    egress, packet,
    tun::{self, Owner, PacketPort, Stage},
};
use crate::{
    native,
    preflight::{self, Plan},
    relay,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Starting,
    Connected,
    Stopping,
    Disconnected,
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidState,
    Cancelled,
    OwnerLost,
    OwnershipUncertain,
    TaskStopped,
    TaskPanicked,
    TaskAborted,
    Deadline,
    NativeWorker(native::Error),
    Tun(tun::Error),
    Retirement(tun::Failure),
    Preflight(preflight::Error),
    Entropy(warper_stack::SeedError),
    Egress(egress::Error),
    Packet(packet::Error),
    Runtime(runtime::Error),
    CaptureChanged(Invalidation),
    RelayAdmission(relay::AdmissionError),
    RelayWorker(relay::WorkerError),
    RelayShutdown,
    FlowReferences,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tun(error) => error.fmt(f),
            Self::Retirement(error) => error.fmt(f),
            Self::Preflight(error) => error.fmt(f),
            Self::Egress(error) => error.fmt(f),
            Self::Entropy(error) => error.fmt(f),
            Self::NativeWorker(error) => error.fmt(f),
            Self::Packet(error) => error.fmt(f),
            Self::Runtime(error) => error.fmt(f),
            Self::RelayAdmission(error) => error.fmt(f),
            Self::RelayWorker(error) => error.fmt(f),
            _ => f.write_str(match self {
                Self::InvalidState => "Conflict: network supervisor is not in the required state",
                Self::Cancelled => "Cancelled: network startup was canceled",
                Self::OwnerLost => "Cancelled: network service owner disappeared",
                Self::OwnershipUncertain => {
                    "RecoveryRequired: native ownership or retirement is unverified"
                }
                Self::TaskStopped => "WorkerFailed: network task stopped unexpectedly",
                Self::TaskPanicked => "WorkerFailed: network task panicked",
                Self::TaskAborted => "WorkerFailed: network task required abort during shutdown",
                Self::Deadline => "Timeout: network supervisor deadline expired",
                Self::CaptureChanged(_) => {
                    "NativeUncertain: capture changed during service operation"
                }
                Self::RelayShutdown => "WorkerFailed: relay shutdown did not finish cleanly",
                Self::FlowReferences => "RecoveryRequired: captured flow references remain",
                _ => "WorkerFailed: network operation failed",
            }),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Default)]
pub struct Report {
    pub relays: Option<relay::Report>,
    pub runtime: Option<Box<runtime::Report>>,
    pub packets: Option<Box<packet::Report>>,
    pub rejected_flows: u64,
    pub last_admission_failure: Option<relay::AdmissionError>,
    pub forced: bool,
    pub retired: bool,
}
#[derive(Debug, Default)]
pub struct Cleanup {
    pub pending_native: Option<Error>,
    pub quiescence: Option<Error>,
    pub relay_shutdown: Option<Error>,
    pub withdrawal: Option<Error>,
    pub packets: Option<Error>,
    pub packet_join: Option<Error>,
    pub packet_secondary: [Option<packet::Error>; 2],
    pub runtime: Option<Error>,
    pub runtime_join: Option<Error>,
    pub retirement: Option<Error>,
}
impl Cleanup {
    pub fn failed(&self) -> bool {
        [
            self.pending_native,
            self.quiescence,
            self.relay_shutdown,
            self.withdrawal,
            self.packets,
            self.packet_join,
            self.runtime,
            self.runtime_join,
            self.retirement,
        ]
        .iter()
        .any(Option::is_some)
            || self.packet_secondary.iter().any(Option::is_some)
    }
}
#[derive(Debug)]
pub struct Failure {
    pub primary: Option<Error>,
    pub cleanup: Box<Cleanup>,
    pub report: Box<Report>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = self.primary {
            error.fmt(f)?;
        } else {
            f.write_str("RecoveryRequired: network cleanup failed")?;
        }
        if self.primary.is_some() && self.cleanup.failed() {
            f.write_str("; network cleanup also failed")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {}

enum Product {
    None,
    Port(PacketPort),
    Preparation(egress::Preparation),
}
struct NativeResult {
    owner: Option<Owner>,
    result: Result<Product, Error>,
    _configuration: ConfigurationLease,
}
type RuntimeTask = JoinHandle<(
    ConfigurationLease,
    Result<runtime::Report, runtime::Failure>,
)>;
type PacketTask = JoinHandle<(
    packet::Pump,
    ConfigurationLease,
    Result<packet::Report, packet::Failure>,
)>;

pub struct Network {
    native: Option<Owner>,
    job: Option<native::Task<NativeResult>>,
    runtime: Option<RuntimeTask>,
    packets: Option<PacketTask>,
    stopped_pump: Option<packet::Pump>,
    idle_output: Option<runtime::Egress>,
    channels: Option<Channels>,
    live: Option<Live>,
    relays: Option<relay::Relays>,
    packet_stop: Option<watch::Sender<bool>>,
    port: Option<Arc<PacketPort>>,
    workers: native::Workers,
    used: bool,
    uncertain: bool,
    report: Report,
    packet_secondary: [Option<packet::Error>; 2],
    startup_timeout: Duration,
    shutdown_timeout: Duration,
    // Configuration/context ownership outlives every native and async resource.
    lease: ConfigurationLease,
}
impl Network {
    pub fn new(lease: ConfigurationLease) -> Result<Self, Error> {
        Plan::prepare(lease.config(), Platform::Linux).map_err(Error::Preflight)?;
        let startup_timeout = lease.config().timeouts.connect;
        let shutdown_timeout = lease.config().timeouts.shutdown;
        Ok(Self {
            native: None,
            job: None,
            runtime: None,
            packets: None,
            stopped_pump: None,
            idle_output: None,
            channels: None,
            live: None,
            relays: None,
            packet_stop: None,
            port: None,
            workers: native::Workers::new(1).map_err(Error::NativeWorker)?,
            used: false,
            uncertain: false,
            report: Report::default(),
            packet_secondary: [None; 2],
            startup_timeout,
            shutdown_timeout,
            lease,
        })
    }

    /// The service retains this owner and its run task across client detach.
    /// If cleanup fails, retain this owner and call cleanup before releasing it.
    pub async fn run(
        &mut self,
        mut cancellation: watch::Receiver<bool>,
        state: &watch::Sender<State>,
    ) -> Result<Report, Failure> {
        if self.used {
            return Err(Failure {
                primary: Some(Error::InvalidState),
                cleanup: Box::default(),
                report: Box::default(),
            });
        }
        self.used = true;
        state.send_replace(State::Starting);
        tracing::event!(name: "network_starting", target: "warper.lifecycle", tracing::Level::INFO, {});
        let request = Request {
            deadline: Instant::now() + self.startup_timeout,
            cancellation: cancellation.clone(),
        };
        let startup = self.start(request).await;
        let primary = match startup {
            Ok(()) => {
                state.send_replace(State::Connected);
                tracing::event!(name: "network_connected", target: "warper.lifecycle", tracing::Level::INFO, {});
                self.serve(&mut cancellation).await.err()
            }
            Err(error) => Some(error),
        };
        state.send_replace(State::Stopping);
        tracing::event!(name: "network_stopping", target: "warper.lifecycle", tracing::Level::INFO, {});
        let cleanup = self.stop(primary.is_none()).await;
        state.send_replace(if self.report.retired {
            State::Disconnected
        } else {
            State::RecoveryRequired
        });
        if self.report.retired {
            tracing::event!(name: "network_retired", target: "warper.lifecycle", tracing::Level::INFO, {});
        } else {
            tracing::event!(name: "network_recovery_required", target: "warper.lifecycle", tracing::Level::WARN, {});
        }
        if primary.is_some() || cleanup.failed() {
            tracing::event!(name: "network_failed", target: "warper.lifecycle", tracing::Level::WARN, {});
        }
        self.result(primary, cleanup)
    }

    /// Retry only retained cleanup; never reconstruct or replay application work.
    pub async fn cleanup(&mut self) -> Result<Report, Failure> {
        let cleanup = self.stop(false).await;
        self.result(None, cleanup)
    }

    async fn start(&mut self, request: Request) -> Result<(), Error> {
        check(&request)?;
        let plan = Plan::prepare(self.lease.config(), Platform::Linux).map_err(Error::Preflight)?;
        let endpoints = plan
            .endpoints()
            .map(|(_, endpoint)| endpoint)
            .collect::<Vec<_>>();
        let capacity = plan.flow_capacity();
        let tunnel = self.lease.config().tunnel.clone();
        let context = self.lease.context();
        let native_request = request.clone();
        let product = self
            .transition(request.clone(), move |owner| {
                check(&native_request)?;
                *owner = Some(
                    Owner::prepare(context, tunnel.name.as_deref(), tunnel.mtu)
                        .map_err(Error::Tun)?,
                );
                let owner = owner.as_mut().ok_or(Error::InvalidState)?;
                owner.allocate().map_err(Error::Tun)?;
                owner.apply_name().map_err(Error::Tun)?;
                owner
                    .assign_ipv4(tunnel.ipv4, native_request.clone())
                    .map_err(Error::Tun)?;
                owner.enable(native_request).map_err(Error::Tun)?;
                owner.packet_port().map(Product::Port).map_err(Error::Tun)
            })
            .await?;
        let Product::Port(port) = product else {
            return Err(Error::InvalidState);
        };
        self.port = Some(Arc::new(port));
        let context = self.lease.context();
        let product = self
            .transition(request.clone(), move |owner| {
                let index = owner
                    .as_ref()
                    .and_then(Owner::index)
                    .and_then(NonZeroU32::new)
                    .ok_or(Error::InvalidState)?;
                egress::Preparation::new(context, &endpoints, index, capacity)
                    .map(Product::Preparation)
                    .map_err(Error::Egress)
            })
            .await?;
        let Product::Preparation(preparation) = product else {
            return Err(Error::InvalidState);
        };
        let connector = preparation
            .prepare(request.clone())
            .await
            .map_err(Error::Egress)?;
        check(&request)?;
        let networking = plan
            .instantiate(
                Seed::generate().map_err(Error::Entropy)?,
                Arc::new(LeasedConnector {
                    connector,
                    _configuration: self.lease.clone(),
                }),
            )
            .map_err(Error::Preflight)?;
        let preflight::Networking {
            runtime,
            channels,
            relays,
            ..
        } = networking;
        self.channels = Some(channels);
        self.relays = Some(relays);
        let configuration = self.lease.clone();
        let (runtime_task, ready) = spawn_started(async move {
            let result = runtime.run().await;
            (configuration, result)
        });
        self.runtime = Some(runtime_task);
        wait_started(ready, request.clone()).await?;
        // Move only the packet receiver; retain the remaining runtime channels.
        let channels = self.channels.take().ok_or(Error::InvalidState)?;
        let Channels {
            ingress,
            packets,
            tcp,
            udp_dns: _,
            admission,
            publication,
            shutdown,
        } = channels;
        let pump_ingress = ingress.clone();
        self.live = Some(Live {
            tcp,
            admission,
            publication,
            shutdown: Some(shutdown),
            _ingress: ingress,
        });
        let mut pump = packet::Pump::new(
            self.port.as_ref().ok_or(Error::InvalidState)?.clone(),
            pump_ingress,
            packets,
            self.startup_timeout,
        )
        .map_err(Error::Packet)?;
        let (stop, cancellation) = watch::channel(false);
        self.packet_stop = Some(stop);
        let configuration = self.lease.clone();
        let (packets, ready) = spawn_started(async move {
            let result = pump.run(cancellation).await;
            (pump, configuration, result)
        });
        self.packets = Some(packets);
        wait_started(ready, request.clone()).await?;
        let publication = self
            .live
            .as_ref()
            .ok_or(Error::InvalidState)?
            .publication
            .clone();
        let native_request = request.clone();
        self.transition(request.clone(), move |owner| {
            owner
                .as_mut()
                .ok_or(Error::InvalidState)?
                .publish_capture(publication, native_request)
                .map_err(Error::Tun)?;
            Ok(Product::None)
        })
        .await?;
        check(&request)?;
        if self.runtime.as_ref().is_none_or(JoinHandle::is_finished)
            || self.packets.as_ref().is_none_or(JoinHandle::is_finished)
        {
            return Err(Error::TaskStopped);
        }
        Ok(())
    }

    async fn transition<F>(&mut self, request: Request, work: F) -> Result<Product, Error>
    where
        F: FnOnce(&mut Option<Owner>) -> Result<Product, Error> + Send + 'static,
    {
        if self.job.is_some() {
            return Err(Error::InvalidState);
        }
        check(&request)?;
        let reservation = self.workers.try_reserve().map_err(Error::NativeWorker)?;
        let mut owner = self.native.take();
        let configuration = self.lease.clone();
        self.job = Some(reservation.start(move || {
            let result = work(&mut owner);
            NativeResult {
                owner,
                result,
                _configuration: configuration,
            }
        }));
        self.join_native(request).await
    }
    async fn join_native(&mut self, request: Request) -> Result<Product, Error> {
        let result = self
            .job
            .as_mut()
            .ok_or(Error::InvalidState)?
            .wait(request)
            .await;
        match result {
            Ok(NativeResult { owner, result, .. }) => {
                self.job = None;
                self.native = owner;
                result
            }
            Err(error) => {
                if !matches!(
                    error,
                    native::Error::WaitCancelled | native::Error::Deadline
                ) {
                    self.job = None;
                    self.uncertain = true;
                }
                Err(Error::NativeWorker(error))
            }
        }
    }

    async fn serve(&mut self, cancellation: &mut watch::Receiver<bool>) -> Result<(), Error> {
        loop {
            let live = self.live.as_mut().ok_or(Error::InvalidState)?;
            let relays = self.relays.as_mut().ok_or(Error::InvalidState)?;
            let native = self.native.as_mut().ok_or(Error::InvalidState)?;
            let changes = native.capture_changes().map_err(Error::Tun)?;
            let runtime = self.runtime.as_mut().ok_or(Error::InvalidState)?;
            let packets = self.packets.as_mut().ok_or(Error::InvalidState)?;
            tokio::select! { biased;
                lost=cancelled(cancellation)=>return if lost {Err(Error::OwnerLost)} else {Ok(())},
                result=runtime=>{
                    self.runtime=None;
                    return self.runtime_result(result).and(Err(Error::TaskStopped));
                },
                result=packets=>{
                    self.packets=None;
                    return self.packet_result(result).and(Err(Error::TaskStopped));
                },
                reason=poll_fn(|context|changes.poll_invalidation(context))=>return Err(Error::CaptureChanged(reason)),
                result=relays.next(),if relays.retained()>0=>{ result.map_err(Error::RelayWorker)?; },
                flow=live.tcp.recv()=>{
                    let flow=flow.ok_or(Error::Runtime(runtime::Error::ConsumerClosed))?;
                    dispatch(relays,&mut self.report,flow.into_core())?;
                },
            }
        }
    }

    async fn stop(&mut self, graceful: bool) -> Cleanup {
        let mut cleanup = Cleanup::default();
        let deadline = Instant::now() + self.shutdown_timeout;
        let flow_deadline = Instant::now() + self.shutdown_timeout / 2;
        let grace_deadline = Instant::now() + self.shutdown_timeout / 4;
        let (owner, _) = watch::channel(false);
        let request = || Request {
            deadline,
            cancellation: owner.subscribe(),
        };
        if self.job.is_some() {
            if let Err(error) = self.join_native(request()).await {
                cleanup.pending_native = Some(error);
            }
            if self.job.is_some() {
                return cleanup;
            }
        }
        // Startup may not yet have moved channels into the live view.
        if let Some(channels) = self.channels.take() {
            let Channels {
                ingress,
                packets,
                tcp,
                udp_dns: _,
                admission,
                publication,
                shutdown,
            } = channels;
            self.idle_output = Some(packets);
            self.live = Some(Live {
                tcp,
                admission,
                publication,
                shutdown: Some(shutdown),
                _ingress: ingress,
            });
        }
        if let Some(live) = &mut self.live {
            let quiescence = live.admission.quiesce();
            cleanup.quiescence = match quiescence {
                Ok(mut receipt) => receipt
                    .wait(Request {
                        deadline: flow_deadline,
                        cancellation: owner.subscribe(),
                    })
                    .await
                    .err()
                    .map(Error::Runtime),
                Err(error) => Some(Error::Runtime(error)),
            };
            if graceful && cleanup.quiescence.is_none() {
                self.drain(grace_deadline).await;
            }
        }
        if let Some(live) = &mut self.live {
            for _ in 0..live.tcp.max_capacity() {
                if live.tcp.try_recv().is_err() {
                    break;
                }
            }
            if live.publication.retained_flows() != 0 {
                self.report.forced = true;
                let result = match live.admission.cancel_flows() {
                    Ok(mut receipt) => receipt
                        .wait(Request {
                            deadline: flow_deadline,
                            cancellation: owner.subscribe(),
                        })
                        .await
                        .map(|_| ()),
                    Err(error) => Err(error),
                };
                if cleanup.quiescence.is_none() {
                    cleanup.quiescence = result.err().map(Error::Runtime);
                }
            }
        }
        if let Some(relays) = self.relays.take() {
            let report = relays.shutdown_until(flow_deadline).await;
            if report.first_worker_failure.is_some() || report.shutdown_error.is_some() {
                cleanup.relay_shutdown = Some(Error::RelayShutdown);
            }
            self.report.relays = Some(report);
        }
        // Joining relays and dropping queued application streams releases their
        // references. Driver cancellation is acknowledged before this check.
        if self
            .live
            .as_ref()
            .is_some_and(|live| live.publication.retained_flows() != 0)
        {
            cleanup.withdrawal = Some(Error::FlowReferences);
            return cleanup;
        }
        let captured = self.native.as_ref().is_some_and(|owner| {
            matches!(
                owner.stage(),
                Stage::Routing | Stage::Captured | Stage::RoutesRetiring
            )
        });
        if captured {
            let native_request = request();
            if let Err(error) = self
                .transition(request(), move |owner| {
                    owner
                        .as_mut()
                        .ok_or(Error::InvalidState)?
                        .withdraw_capture(native_request)
                        .map_err(Error::Tun)?;
                    Ok(Product::None)
                })
                .await
            {
                cleanup.withdrawal = Some(error);
                return cleanup;
            }
        }
        if let Some(stop) = &self.packet_stop {
            stop.send_replace(true);
        }
        if let Some(mut packets) = self.packets.take() {
            match timeout_at(deadline, &mut packets).await {
                Ok(result) => cleanup.packets = self.packet_result(result).err(),
                Err(_) => {
                    packets.abort();
                    cleanup.packet_join = self.packet_result(packets.await).err();
                    cleanup.packets = Some(Error::Deadline);
                }
            }
        }
        self.packet_stop = None;
        if let Some(live) = &mut self.live
            && let Some(shutdown) = live.shutdown.take()
        {
            // A completed runtime task already explains a closed shutdown pipe.
            if shutdown.send(()).is_err() && self.runtime.is_some() {
                cleanup.runtime = Some(Error::Runtime(runtime::Error::ShutdownOwnerLost));
            }
        }
        if let Some(mut runtime) = self.runtime.take() {
            match timeout_at(deadline, &mut runtime).await {
                Ok(result) => {
                    let error = self.runtime_result(result).err();
                    if cleanup.runtime.is_none() {
                        cleanup.runtime = error;
                    }
                }
                Err(_) => {
                    runtime.abort();
                    cleanup.runtime_join = self.runtime_result(runtime.await).err();
                    cleanup.runtime = Some(Error::Deadline);
                }
            }
        }
        self.live = None;
        self.stopped_pump = None;
        self.idle_output = None;
        self.port = None;
        if self.native.is_some()
            && let Err(error) = self
                .transition(request(), |owner| {
                    owner
                        .as_mut()
                        .ok_or(Error::InvalidState)?
                        .close()
                        .map_err(Error::Retirement)?;
                    *owner = None;
                    Ok(Product::None)
                })
                .await
        {
            cleanup.retirement = Some(error);
        }
        self.report.retired = self.native.is_none()
            && self.job.is_none()
            && !self.uncertain
            && self.runtime.is_none()
            && self.packets.is_none()
            && self.relays.is_none()
            && self.port.is_none()
            && self.live.is_none()
            && self.channels.is_none()
            && self.stopped_pump.is_none()
            && self.idle_output.is_none();
        if !self.report.retired && cleanup.retirement.is_none() {
            cleanup.retirement = Some(Error::OwnershipUncertain);
        }
        cleanup
    }

    async fn drain(&mut self, deadline: Instant) {
        loop {
            let Some(live) = &mut self.live else { return };
            let Some(relays) = &mut self.relays else {
                return;
            };
            if relays.retained() == 0 && live.publication.retained_flows() == 0 {
                return;
            }
            tokio::select! { biased;
                ()=tokio::time::sleep_until(deadline)=>return,
                result=relays.next(),if relays.retained()>0=>{if result.is_err(){return;}},
                flow=live.tcp.recv()=>{
                    let Some(flow)=flow else {return};
                    if dispatch(relays,&mut self.report,flow.into_core()).is_err(){return;}
                },
                ()=tokio::time::sleep(Duration::from_millis(1))=>{},
            }
        }
    }
    fn runtime_result(
        &mut self,
        result: Result<
            (
                ConfigurationLease,
                Result<runtime::Report, runtime::Failure>,
            ),
            tokio::task::JoinError,
        >,
    ) -> Result<(), Error> {
        match result {
            Ok((_configuration, Ok(report))) => {
                self.report.runtime = Some(Box::new(report));
                Ok(())
            }
            Ok((_configuration, Err(failure))) => {
                self.report.runtime = Some(failure.report);
                Err(Error::Runtime(failure.cause))
            }
            Err(error) => Err(if error.is_panic() {
                Error::TaskPanicked
            } else {
                Error::TaskAborted
            }),
        }
    }
    fn packet_result(
        &mut self,
        result: Result<
            (
                packet::Pump,
                ConfigurationLease,
                Result<packet::Report, packet::Failure>,
            ),
            tokio::task::JoinError,
        >,
    ) -> Result<(), Error> {
        match result {
            Ok((pump, _configuration, result)) => {
                self.stopped_pump = Some(pump);
                match result {
                    Ok(report) => {
                        self.report.packets = Some(Box::new(report));
                        Ok(())
                    }
                    Err(failure) => {
                        self.report.packets = Some(failure.report);
                        self.packet_secondary = failure.secondary;
                        Err(Error::Packet(failure.cause))
                    }
                }
            }
            Err(error) => Err(if error.is_panic() {
                Error::TaskPanicked
            } else {
                Error::TaskAborted
            }),
        }
    }
    fn result(&mut self, primary: Option<Error>, mut cleanup: Cleanup) -> Result<Report, Failure> {
        cleanup.packet_secondary = std::mem::take(&mut self.packet_secondary);
        let report = std::mem::take(&mut self.report);
        if primary.is_some() || cleanup.failed() {
            Err(Failure {
                primary,
                cleanup: Box::new(cleanup),
                report: Box::new(report),
            })
        } else {
            Ok(report)
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        // Emergency cancellation is not journaled cleanup. Normal ownership
        // retains and joins both tasks and verifies native retirement first.
        if let Some(stop) = &self.packet_stop {
            stop.send_replace(true);
        }
        if let Some(task) = &self.packets {
            task.abort();
        }
        if let Some(task) = &self.runtime {
            task.abort();
        }
    }
}
struct LeasedConnector {
    connector: egress::Connector,
    _configuration: ConfigurationLease,
}
impl warper_core::transport::EndpointConnector for LeasedConnector {
    fn connect_tcp(
        &self,
        endpoint: std::net::SocketAddr,
        request: Request,
    ) -> warper_core::transport::OpenTcp<'_> {
        warper_core::transport::EndpointConnector::connect_tcp(&self.connector, endpoint, request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dispatch {
    Admitted,
    Rejected,
}
fn dispatch(
    relays: &mut relay::Relays,
    report: &mut Report,
    flow: warper_core::transport::CapturedTcp,
) -> Result<Dispatch, Error> {
    match relays.admit(flow) {
        Ok(()) => Ok(Dispatch::Admitted),
        Err(error) => {
            report.rejected_flows = report.rejected_flows.saturating_add(1);
            report.last_admission_failure = Some(error);
            if error == relay::AdmissionError::Full {
                Ok(Dispatch::Rejected)
            } else {
                Err(Error::RelayAdmission(error))
            }
        }
    }
}

struct Live {
    tcp: tokio::sync::mpsc::Receiver<warper_stack::host::AcceptedFlow>,
    admission: runtime::AdmissionControl,
    publication: runtime::Publication,
    shutdown: Option<oneshot::Sender<()>>,
    _ingress: runtime::Ingress,
}

fn check(request: &Request) -> Result<(), Error> {
    if *request.cancellation.borrow() {
        Err(Error::Cancelled)
    } else if request.cancellation.has_changed().is_err() {
        Err(Error::OwnerLost)
    } else if Instant::now() >= request.deadline {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
fn spawn_started<F, T>(future: F) -> (JoinHandle<T>, oneshot::Receiver<()>)
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::pin!(future);
        let mut sender = Some(sender);
        poll_fn(|context| match future.as_mut().poll(context) {
            Poll::Pending => {
                if let Some(sender) = sender.take() {
                    let _delivery = sender.send(());
                }
                Poll::Pending
            }
            Poll::Ready(result) => Poll::Ready(result),
        })
        .await
    });
    (task, receiver)
}
async fn wait_started(mut ready: oneshot::Receiver<()>, mut request: Request) -> Result<(), Error> {
    let result = tokio::select! {biased;
        lost=cancelled(&mut request.cancellation)=>return Err(if lost {Error::OwnerLost}else{Error::Cancelled}),
        ()=tokio::time::sleep_until(request.deadline)=>return Err(Error::Deadline),
        result=&mut ready=>result,
    };
    check(&request)?;
    result.map_err(|_| Error::TaskStopped)
}
async fn cancelled(cancellation: &mut watch::Receiver<bool>) -> bool {
    loop {
        if *cancellation.borrow_and_update() {
            return false;
        }
        if cancellation.changed().await.is_err() {
            return true;
        }
    }
}

#[cfg(test)]
mod tests;
