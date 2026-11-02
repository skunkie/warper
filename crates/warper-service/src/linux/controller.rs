// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Serialized native dispatch. Execute in retained workers, never on async I/O
//! threads. Returned actions belong to the service, not to the requesting client.

use std::{fmt, os::unix::net::UnixStream, sync::Arc};
use warper_config::{managed::Snapshot as ManagedSnapshot, schema::Platform};
use warper_control::{
    Access, OwnerPolicy, admission,
    message::{OperationState, SessionState, Status},
    runtime::{
        RuntimeLease,
        connection::{self, Acceptance, ConnectionStore, Desired},
        enrollment::{self, OwnerStore},
    },
    unix,
    wire::{self, Code, Frame, Kind},
};
use warper_core::transport::Request;

use super::{
    configuration::{self, ConfigurationLease, Configurations},
    context::{self, Context},
    network, tun,
};
mod history;
use history::History;
pub(crate) use history::MAX_OPERATIONS;

#[derive(Debug)]
pub enum Error {
    Context(context::Error),
    Connection(connection::Failure),
    Owner(enrollment::Error),
    Enrollment(enrollment::Failure),
    Configuration(configuration::Error),
    Authentication(warper_control::Error),
    Recovery(tun::Error),
    Wire(wire::Error),
    Rejected(Code),
    Invariant,
}
impl Error {
    pub fn code(&self) -> Code {
        match self {
            Self::Authentication(_) => Code::PermissionDenied,
            Self::Rejected(code) => *code,
            Self::Wire(_) => Code::Malformed,
            Self::Configuration(configuration::Error::Busy) => Code::Busy,
            Self::Configuration(configuration::Error::Conflict) => Code::Conflict,
            Self::Configuration(configuration::Error::Authentication(_)) => Code::PermissionDenied,
            Self::Configuration(configuration::Error::Preflight(
                crate::preflight::Error::UnsupportedPlatform
                | crate::preflight::Error::UnsupportedDns
                | crate::preflight::Error::UnsupportedRouting
                | crate::preflight::Error::UnsupportedBackend
                | crate::preflight::Error::UnsupportedFamily
                | crate::preflight::Error::UnsupportedMtu
                | crate::preflight::Error::EndpointResolutionRequired
                | crate::preflight::Error::CredentialImportRequired,
            )) => Code::Unsupported,
            Self::Configuration(
                configuration::Error::Managed(_)
                | configuration::Error::Preflight(_)
                | configuration::Error::Control(_),
            ) => Code::Malformed,
            Self::Connection(error) if error.cleanup.is_none() => match error.primary {
                connection::Error::Conflict => Code::Conflict,
                connection::Error::InvalidRequest => Code::Malformed,
                _ => Code::RecoveryRequired,
            },
            Self::Enrollment(error) if error.cleanup.is_none() => match error.primary {
                enrollment::Error::Peer(_) => Code::PermissionDenied,
                enrollment::Error::RevisionConflict => Code::Conflict,
                enrollment::Error::InvalidOwner => Code::Malformed,
                _ => Code::RecoveryRequired,
            },
            _ => Code::RecoveryRequired,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => error.fmt(f),
            Self::Connection(error) => error.fmt(f),
            Self::Owner(error) => error.fmt(f),
            Self::Enrollment(error) => error.fmt(f),
            Self::Configuration(error) => error.fmt(f),
            Self::Authentication(error) => error.fmt(f),
            Self::Recovery(error) => error.fmt(f),
            Self::Wire(error) => error.fmt(f),
            Self::Invariant => f.write_str("RecoveryRequired: controller state is inconsistent"),
            Self::Rejected(code) => write!(f, "ControlRejected: {code:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Self::Wire(error)
    }
}

#[derive(Debug)]
pub enum Effect {
    None,
    Start {
        epoch: u64,
        configuration: ConfigurationLease,
    },
    Stop {
        epoch: u64,
    },
    AdmissionChanged(admission::Plan),
}
#[derive(Debug)]
pub struct Dispatch {
    pub reply: Frame,
    pub effect: Effect,
    /// Retain the typed primary error for redacted service diagnostics.
    pub rejection: Option<Error>,
}

pub struct Controller {
    context: Arc<Context>,
    connection: ConnectionStore,
    owners: OwnerStore,
    configurations: Configurations,
    history: History,
    state: SessionState,
    active: Option<u64>,
    pending: Option<([u8; 16], Desired)>,
    stopping: bool,
    intent_uncertain: bool,
}
impl Controller {
    /// Reconcile proven-ended native ownership before restoring same-boot
    /// intent or autoconnect. All filesystem/netlink work stays in this worker.
    pub fn open(runtime: Arc<RuntimeLease>, request: Request) -> Result<(Self, Effect), Error> {
        let connection =
            ConnectionStore::open(&runtime).map_err(|error| Error::Connection(error.into()))?;
        let context = Arc::new(Context::capture(runtime, &connection).map_err(Error::Context)?);
        let owners = OwnerStore::open(context.runtime()).map_err(Error::Owner)?;
        owners.read(context.runtime()).map_err(Error::Owner)?;
        tun::recover_abandoned(&context, request).map_err(Error::Recovery)?;
        let configurations = Configurations::open(context.clone()).map_err(Error::Configuration)?;
        let lease = configurations.lease().map_err(Error::Configuration)?;
        let capacity = lease
            .as_ref()
            .map_or(256, |lease| lease.config().limits.max_control_operations);
        let mut controller = Self {
            context,
            connection,
            owners,
            configurations,
            history: History::new(capacity).map_err(history_error)?,
            state: SessionState::Disconnected,
            active: None,
            pending: None,
            stopping: false,
            intent_uncertain: false,
        };
        let saved = controller
            .connection
            .read(controller.context.runtime())
            .map_err(|error| Error::Connection(error.into()))?;
        let decision = boot_decision(
            saved.as_ref().map(|saved| {
                (
                    saved.same_boot(&controller.connection.boot_id()),
                    saved.desired(),
                    saved.configuration_generation(),
                )
            }),
            lease
                .as_ref()
                .map(|lease| (lease.generation(), lease.config().autoconnect)),
        );
        let epoch = match decision {
            Boot::Disconnected => return Ok((controller, Effect::None)),
            Boot::Blocked => {
                controller.state = SessionState::RecoveryRequired;
                return Ok((controller, Effect::None));
            }
            Boot::Resume => saved
                .as_ref()
                .ok_or(Error::Rejected(Code::RecoveryRequired))?
                .revision(),
            Boot::Autoconnect => {
                let revision = saved.as_ref().map_or(0, |saved| saved.revision());
                let generation = lease
                    .as_ref()
                    .ok_or(Error::Rejected(Code::RecoveryRequired))?
                    .generation();
                let operation = wire::operation_id(revision, nonce()?)?;
                let accepted = controller
                    .connection
                    .accept(
                        controller.context.runtime(),
                        generation,
                        connection::Request {
                            operation,
                            expected_configuration: generation,
                            expected_revision: revision,
                            expected_instance: controller.connection.instance_id(),
                            desired: Desired::Up,
                        },
                    )
                    .map_err(Error::Connection)?;
                match accepted {
                    Acceptance::Accepted(snapshot) | Acceptance::AlreadyAccepted(snapshot) => {
                        snapshot.revision()
                    }
                }
            }
        };
        let configuration = lease.ok_or(Error::Rejected(Code::RecoveryRequired))?;
        controller.active = Some(epoch);
        controller.state = SessionState::Preparing;
        Ok((
            controller,
            Effect::Start {
                epoch,
                configuration,
            },
        ))
    }

    pub fn instance_id(&self) -> [u8; 16] {
        self.connection.instance_id()
    }
    pub fn policy(&self) -> Result<OwnerPolicy, Error> {
        self.owners
            .read(self.context.runtime())
            .map(|enrollment| enrollment.policy())
            .map_err(Error::Owner)
    }
    pub fn state(&self) -> SessionState {
        self.state
    }
    pub fn admission_plan(&self) -> Result<admission::Plan, Error> {
        let lease = self.configurations.lease().map_err(Error::Configuration)?;
        plan(lease.as_ref().map(|lease| &lease.config().limits))
    }

    /// The service must retain and execute the effect even if reply delivery
    /// fails. Session framing/sequence admission precedes this fresh auth check.
    pub fn dispatch(&mut self, peer: &UnixStream, request: &Frame) -> Result<Dispatch, Error> {
        match self.handle(peer, request) {
            Ok((reply, effect)) => Ok(Dispatch {
                reply,
                effect,
                rejection: None,
            }),
            Err(error) => {
                let code = error.code();
                let effect = if (code == Code::RecoveryRequired
                    && !matches!(&error, Error::Rejected(_)))
                    || matches!(&error, Error::Configuration(configuration::Error::Conflict))
                {
                    self.intent_uncertain = true;
                    self.state = SessionState::RecoveryRequired;
                    self.stopping = true;
                    self.active
                        .map_or(Effect::None, |epoch| Effect::Stop { epoch })
                } else {
                    Effect::None
                };
                let reply = Frame::new(
                    Kind::ErrorReply,
                    request.request_id(),
                    (code as u16).to_be_bytes().to_vec(),
                )?;
                Ok(Dispatch {
                    reply,
                    effect,
                    rejection: Some(error),
                })
            }
        }
    }

    /// Only an actual supervisor readiness notification may call this method.
    /// Disconnect suppresses readiness from its superseded startup epoch.
    pub fn connected(&mut self, epoch: u64) -> Result<(), Error> {
        if self.active != Some(epoch) {
            return Err(Error::Rejected(Code::Conflict));
        }
        if self.stopping || self.state != SessionState::Preparing {
            return Ok(());
        }
        if let Some((operation, desired)) = self.pending.take() {
            if desired != Desired::Up {
                return Err(Error::Invariant);
            }
            self.history
                .finish(operation, OperationState::Succeeded, Code::None)
                .map_err(history_error)?;
        }
        self.state = SessionState::Connected;
        Ok(())
    }

    /// Retain the Network owner after unverified retirement. A successful
    /// cleanup result may later be delivered for the same epoch.
    pub fn finished(
        &mut self,
        epoch: u64,
        result: &Result<network::Report, network::Failure>,
    ) -> Result<(), Error> {
        let (retired, code) = match result {
            Ok(report) => (report.retired, Code::Failed),
            Err(failure) => (
                failure.report.retired,
                if failure.primary == Some(network::Error::Deadline) {
                    Code::Timeout
                } else {
                    Code::Failed
                },
            ),
        };
        self.finish(epoch, retired, code)
    }

    /// Use only when Network construction failed before any native mutation.
    pub fn start_failed(&mut self, epoch: u64, error: network::Error) -> Result<(), Error> {
        if !matches!(
            self.state,
            SessionState::Preparing | SessionState::Disconnecting
        ) {
            return Err(Error::Rejected(Code::Conflict));
        }
        self.finish(
            epoch,
            true,
            if error == network::Error::Deadline {
                Code::Timeout
            } else {
                Code::Failed
            },
        )
    }

    /// Service shutdown preserves accepted desired intent for same-boot restart.
    pub fn shutdown(&mut self) -> Effect {
        self.stopping = true;
        if self.active.is_some() {
            self.state = SessionState::Disconnecting;
        }
        self.active
            .map_or(Effect::None, |epoch| Effect::Stop { epoch })
    }

    fn handle(&mut self, peer: &UnixStream, frame: &Frame) -> Result<(Frame, Effect), Error> {
        self.context.revalidate().map_err(Error::Context)?;
        let access = match frame.kind() {
            Kind::Hello | Kind::Status | Kind::OperationStatus => Access::Observe,
            Kind::Connect | Kind::Disconnect => Access::Operate,
            Kind::Enroll | Kind::InstallConfig | Kind::InspectRecovery => Access::Administer,
            _ => return Err(Error::Rejected(Code::Malformed)),
        };
        let policy = if access == Access::Administer {
            OwnerPolicy::new(None).map_err(Error::Authentication)?
        } else {
            self.policy()?
        };
        unix::authenticate_client(peer, &policy, access).map_err(Error::Authentication)?;
        let id = frame.request_id();
        let reply = match frame.kind() {
            Kind::Hello => Frame::new(Kind::HelloReply, id, self.instance_id().to_vec())?,
            Kind::Status => self.status()?.frame(id)?,
            Kind::OperationStatus => self
                .history
                .get(
                    &frame
                        .body()
                        .try_into()
                        .map_err(|_| Error::Rejected(Code::Malformed))?,
                )
                .map_err(history_error)?
                .frame(id)?,
            Kind::Connect | Kind::Disconnect => return self.accept(frame),
            Kind::Enroll => {
                let body = frame.body();
                let expected = number(&body[..8])?;
                let present = u32::from_be_bytes(
                    body[8..12]
                        .try_into()
                        .map_err(|_| Error::Rejected(Code::Malformed))?,
                );
                let uid = u32::from_be_bytes(
                    body[12..16]
                        .try_into()
                        .map_err(|_| Error::Rejected(Code::Malformed))?,
                );
                let enrollment = self
                    .owners
                    .enroll(
                        self.context.runtime(),
                        peer,
                        expected,
                        (present != 0).then_some(uid),
                    )
                    .map_err(Error::Enrollment)?;
                Frame::new(
                    Kind::EnrollmentReply,
                    id,
                    enrollment.revision().to_be_bytes().to_vec(),
                )?
            }
            Kind::InstallConfig => return self.install(peer, frame),
            _ => return Err(Error::Rejected(Code::Unsupported)),
        };
        Ok((reply, Effect::None))
    }
    fn status(&self) -> Result<Status, Error> {
        let configuration = self.configurations.status().map_err(Error::Configuration)?;
        let owner = self
            .owners
            .read(self.context.runtime())
            .map_err(Error::Owner)?;
        let desired = self
            .connection
            .read(self.context.runtime())
            .map_err(|error| Error::Connection(error.into()))?;
        Ok(Status {
            state: self.state,
            configuration_generation: configuration.generation,
            owner_revision: owner.revision(),
            configuration_present: configuration.present,
            desired_revision: desired.map_or(0, |desired| desired.revision()),
        })
    }
    fn accept(&mut self, frame: &Frame) -> Result<(Frame, Effect), Error> {
        let request = connection::Request::from_frame(frame)
            .map_err(|error| Error::Connection(error.into()))?;
        let reply = Frame::new(
            Kind::Accepted,
            frame.request_id(),
            request.operation.to_vec(),
        )?;
        if self
            .history
            .lookup(&request)
            .map_err(history_error)?
            .is_some()
        {
            return Ok((reply, Effect::None));
        }
        if self.intent_uncertain {
            return Err(Error::Rejected(Code::RecoveryRequired));
        }
        if self.state == SessionState::Disconnecting
            || (request.desired == Desired::Up && self.state == SessionState::Preparing)
        {
            return Err(Error::Rejected(Code::Busy));
        }
        if request.desired == Desired::Up && self.state == SessionState::RecoveryRequired {
            return Err(Error::Rejected(Code::RecoveryRequired));
        }
        let superseding = if request.desired == Desired::Down {
            self.pending.map(|(id, _)| id)
        } else {
            None
        };
        let reservation = self.history.reserve(superseding).map_err(history_error)?;
        let lease = self.configurations.lease().map_err(Error::Configuration)?;
        let generation = lease.as_ref().map_or(0, ConfigurationLease::generation);
        if request.desired == Desired::Up && lease.is_none() {
            return Err(Error::Rejected(Code::Conflict));
        }
        let accepted = self
            .connection
            .accept(self.context.runtime(), generation, request)
            .map_err(Error::Connection)?;
        let Acceptance::Accepted(snapshot) = accepted else {
            // Missing history is never permission to execute the last operation
            // again, even if protected intent still recognizes its identity.
            return Err(Error::Rejected(Code::Conflict));
        };
        if request.desired == Desired::Down
            && let Some((previous, _)) = self.pending.take()
        {
            self.history
                .finish(previous, OperationState::Superseded, Code::None)
                .map_err(history_error)?;
        }
        self.history
            .commit(reservation, request)
            .map_err(history_error)?;
        let effect = match request.desired {
            Desired::Up if self.state == SessionState::Connected => {
                self.history
                    .finish(request.operation, OperationState::Succeeded, Code::None)
                    .map_err(history_error)?;
                Effect::None
            }
            Desired::Up => {
                let configuration = lease.ok_or(Error::Rejected(Code::RecoveryRequired))?;
                self.pending = Some((request.operation, Desired::Up));
                self.active = Some(snapshot.revision());
                self.stopping = false;
                self.state = SessionState::Preparing;
                Effect::Start {
                    epoch: snapshot.revision(),
                    configuration,
                }
            }
            Desired::Down => {
                if let Some(epoch) = self.active {
                    self.pending = Some((request.operation, Desired::Down));
                    self.stopping = true;
                    self.state = SessionState::Disconnecting;
                    Effect::Stop { epoch }
                } else {
                    self.history
                        .finish(request.operation, OperationState::Succeeded, Code::None)
                        .map_err(history_error)?;
                    self.state = SessionState::Disconnected;
                    Effect::None
                }
            }
        };
        Ok((reply, effect))
    }
    fn install(&mut self, peer: &UnixStream, frame: &Frame) -> Result<(Frame, Effect), Error> {
        if self.active.is_some()
            || !matches!(
                self.state,
                SessionState::Disconnected | SessionState::Failed
            )
        {
            return Err(Error::Rejected(Code::Busy));
        }
        let expected = number(&frame.body()[..8])?;
        let bytes = &frame.body()[8..];
        let decoded = ManagedSnapshot::decode(bytes, Platform::Linux)
            .map_err(|error| Error::Configuration(configuration::Error::Managed(error)))?;
        let history = self
            .history
            .resized(decoded.config().limits.max_control_operations)
            .map_err(history_error)?;
        let admission = plan(Some(&decoded.config().limits))?;
        drop(decoded);
        let generation = self
            .configurations
            .install(peer, expected, bytes)
            .map_err(Error::Configuration)?;
        self.history = history;
        Ok((
            Frame::new(
                Kind::ConfigReply,
                frame.request_id(),
                generation.to_be_bytes().to_vec(),
            )?,
            Effect::AdmissionChanged(admission),
        ))
    }
    fn finish(&mut self, epoch: u64, retired: bool, code: Code) -> Result<(), Error> {
        if self.active != Some(epoch) {
            return Err(Error::Rejected(Code::Conflict));
        }
        if let Some((operation, desired)) = self.pending.take() {
            let state =
                if retired && desired == Desired::Down && self.stopping && !self.intent_uncertain {
                    OperationState::Succeeded
                } else {
                    OperationState::Failed
                };
            self.history
                .finish(
                    operation,
                    state,
                    if state == OperationState::Succeeded {
                        Code::None
                    } else if !retired || self.intent_uncertain {
                        Code::RecoveryRequired
                    } else {
                        code
                    },
                )
                .map_err(history_error)?;
        }
        self.state = if !retired || self.intent_uncertain {
            SessionState::RecoveryRequired
        } else if self.stopping {
            SessionState::Disconnected
        } else {
            SessionState::Failed
        };
        if retired {
            self.active = None;
        }
        self.stopping = false;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Boot {
    Disconnected,
    Resume,
    Autoconnect,
    Blocked,
}
fn boot_decision(saved: Option<(bool, Desired, u64)>, approved: Option<(u64, bool)>) -> Boot {
    if let Some((true, desired, generation)) = saved {
        return match desired {
            Desired::Down => Boot::Disconnected,
            Desired::Up if approved.is_some_and(|(current, _)| current == generation) => {
                Boot::Resume
            }
            Desired::Up => Boot::Blocked,
        };
    }
    if approved.is_some_and(|(_, autoconnect)| autoconnect) {
        Boot::Autoconnect
    } else {
        Boot::Disconnected
    }
}
fn history_error(code: Code) -> Error {
    if code == Code::RecoveryRequired {
        Error::Invariant
    } else {
        Error::Rejected(code)
    }
}
fn number(bytes: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::Rejected(Code::Malformed))?,
    ))
}
fn plan(limits: Option<&warper_config::schema::Limits>) -> Result<admission::Plan, Error> {
    let Some(limits) = limits else {
        // Bootstrap before any approval uses the canonical schema defaults.
        return admission::Plan::new(16, 64, 1_048_576, 8_388_608)
            .map_err(|error| Error::Configuration(configuration::Error::Control(error)));
    };
    admission::Plan::new(
        limits.max_control_clients,
        limits.max_control_inflight_requests,
        limits.max_control_message_bytes,
        limits.max_control_buffered_bytes_total,
    )
    .map_err(|error| Error::Configuration(configuration::Error::Control(error)))
}
fn nonce() -> Result<[u8; 8], Error> {
    let mut bytes = [0; 8];
    let count = rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::NONBLOCK)
        .map_err(|error| {
            Error::Connection(
                connection::Error::Entropy(
                    std::io::Error::from_raw_os_error(error.raw_os_error()).kind(),
                )
                .into(),
            )
        })?;
    if count != bytes.len() || bytes == [0; 8] {
        return Err(Error::Connection(
            connection::Error::EntropyIncomplete.into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
