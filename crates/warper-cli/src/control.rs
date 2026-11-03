// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded native command observation. The service owns accepted operations.

use std::{fmt, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::{Instant, sleep_until},
};
use warper_control::{
    message::{Operation, OperationState, Status},
    wire::{self, Code, Frame, Kind},
};

use crate::args::{ServiceCommand, Wait};

const RPC_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_REPLY_BYTES: usize = 68;

#[derive(Debug)]
pub enum Error {
    Wire(wire::Error),
    Service(Code),
    UnexpectedReply,
    InvalidWait,
    Unsupported,
    Administrative(Box<Error>),
    Entropy(std::io::ErrorKind),
    EntropyIncomplete,
    WaitExpired {
        operation: [u8; 16],
    },
    Operation(Operation),
    Observation {
        operation: [u8; 16],
        cause: Box<Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(f),
            Self::Service(code) => write!(f, "ServiceRejected: {code:?}"),
            Self::UnexpectedReply => f.write_str("Protocol: unexpected control reply or identity"),
            Self::InvalidWait => {
                f.write_str("InvalidArguments: wait duration is not representable")
            }
            Self::Administrative(cause) => write!(
                f,
                "Administrative request: {cause}; inspect status before retrying"
            ),
            Self::Unsupported => f.write_str("UnsupportedCapability: unavailable service command"),
            Self::Entropy(_) | Self::EntropyIncomplete => {
                f.write_str("Entropy: operation identity randomness is unavailable")
            }
            Self::WaitExpired { operation } => write!(
                f,
                "Timeout: observation of operation {} expired; accepted work continues",
                identifier(operation)
            ),
            Self::Operation(operation) => write!(
                f,
                "Operation {}: {} ({:?})",
                identifier(&operation.id),
                operation.state.name(),
                operation.code
            ),
            Self::Observation { operation, cause } => write!(
                f,
                "Operation {}: {cause}; query status before issuing another command",
                identifier(operation)
            ),
        }
    }
}
impl std::error::Error for Error {}
impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Self::Wire(error)
    }
}

pub(crate) enum Administrative {
    Install(warper_config::schema::Secret<Vec<u8>>),
    Enroll(Option<u32>),
}

#[cfg(target_os = "linux")]
pub(crate) async fn native(
    command: ServiceCommand,
    administrative: Option<Administrative>,
) -> Result<String, crate::Error> {
    let (_cancel, mut cancellation) = watch::channel(false);
    // No configurable path or identity bypass: authenticate initial-namespace
    // root at the protected endpoint before Hello or any other payload.
    let stream = warper_control::runtime::client::connect(
        Instant::now() + RPC_TIMEOUT,
        cancellation.clone(),
    )
    .await
    .map_err(crate::Error::Admission)?;
    if let Some(administrative) = administrative {
        return administer(stream, administrative, &mut cancellation)
            .await
            .map_err(crate::Error::Control);
    }
    let mut nonce = [0; 8];
    if matches!(
        command,
        ServiceCommand::Up { .. } | ServiceCommand::Down { .. }
    ) {
        let count = rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::NONBLOCK)
            .map_err(|error| {
                crate::Error::Control(Error::Entropy(
                    std::io::Error::from_raw_os_error(error.raw_os_error()).kind(),
                ))
            })?;
        if count != nonce.len() || nonce == [0; 8] {
            return Err(crate::Error::Control(Error::EntropyIncomplete));
        }
    }
    execute(stream, command, nonce, &mut cancellation)
        .await
        .map_err(crate::Error::Control)
}

async fn administer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    command: Administrative,
    cancel: &mut watch::Receiver<bool>,
) -> Result<String, Error> {
    let mut client = Client {
        stream,
        request_id: 0,
    };
    client
        .exchange(Kind::Hello, vec![], Kind::HelloReply, None, cancel)
        .await?;
    let frame = client
        .exchange(Kind::Status, vec![], Kind::StatusReply, None, cancel)
        .await?;
    let status = Status::decode(&frame)?;
    let (kind, expected, body, label, counter) = match command {
        Administrative::Install(encoded) => {
            let mut body = status.configuration_generation.to_be_bytes().to_vec();
            body.extend_from_slice(encoded.expose());
            (
                Kind::InstallConfig,
                Kind::ConfigReply,
                body,
                "Configuration installed",
                "generation",
            )
        }
        Administrative::Enroll(owner) => {
            let mut body = status.owner_revision.to_be_bytes().to_vec();
            body.extend_from_slice(&u32::from(owner.is_some()).to_be_bytes());
            body.extend_from_slice(&owner.unwrap_or(0).to_be_bytes());
            (
                Kind::Enroll,
                Kind::EnrollmentReply,
                body,
                "Owner policy updated",
                "revision",
            )
        }
    };
    let reply = client
        .exchange(kind, body, expected, None, cancel)
        .await
        .map_err(|cause| Error::Administrative(Box::new(cause)))?;
    let revision = u64::from_be_bytes(
        reply
            .body()
            .try_into()
            .map_err(|_| Error::Administrative(Box::new(Error::UnexpectedReply)))?,
    );
    Ok(format!("{label} ({counter} {revision}).\n"))
}

// The stream must already be authenticated by the platform connector. Keeping
// this transport flow independent permits controlled peers without exposing a
// production socket-path override or an authority override.
async fn execute<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    command: ServiceCommand,
    nonce: [u8; 8],
    cancel: &mut watch::Receiver<bool>,
) -> Result<String, Error> {
    let wait = match command {
        ServiceCommand::Status { .. } => Wait::None,
        ServiceCommand::Up { wait } | ServiceCommand::Down { wait } => wait,
        _ => return Err(Error::Unsupported),
    };
    // Reject impossible durations before transmitting a state-changing command.
    let wait_duration = match wait {
        Wait::None => None,
        Wait::Milliseconds(value) => {
            let duration = Duration::from_millis(value);
            if value == 0 || Instant::now().checked_add(duration).is_none() {
                return Err(Error::InvalidWait);
            }
            Some(duration)
        }
    };
    let mut client = Client {
        stream,
        request_id: 0,
    };
    let hello = client
        .exchange(Kind::Hello, vec![], Kind::HelloReply, None, cancel)
        .await?;
    let instance = hello.body().to_vec();
    let frame = client
        .exchange(Kind::Status, vec![], Kind::StatusReply, None, cancel)
        .await?;
    let status = Status::decode(&frame)?;
    if let ServiceCommand::Status { json } = command {
        return Ok(format_status(status, json));
    }
    let operation = wire::operation_id(status.desired_revision, nonce)?;
    let mut body = Vec::with_capacity(48);
    body.extend_from_slice(&operation);
    body.extend_from_slice(&status.configuration_generation.to_be_bytes());
    body.extend_from_slice(&status.desired_revision.to_be_bytes());
    body.extend_from_slice(&instance);
    let kind = if matches!(command, ServiceCommand::Up { .. }) {
        Kind::Connect
    } else {
        Kind::Disconnect
    };
    // Never retry a partially sent request or generate a second operation after
    // uncertainty. Even a lost Accepted reply reports the original identity.
    let result = client
        .exchange(kind, body, Kind::Accepted, None, cancel)
        .await
        .and_then(|reply| {
            if reply.body() == operation {
                Ok(())
            } else {
                Err(Error::UnexpectedReply)
            }
        });
    result.map_err(|cause| Error::Observation {
        operation,
        cause: Box::new(cause),
    })?;
    let Some(duration) = wait_duration else {
        return Ok(format!("Operation {}: accepted\n", identifier(&operation)));
    };
    let deadline = Instant::now()
        .checked_add(duration)
        .ok_or(Error::InvalidWait)?;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::WaitExpired { operation });
        }
        let reply = client
            .exchange(
                Kind::OperationStatus,
                operation.to_vec(),
                Kind::OperationReply,
                Some(deadline),
                cancel,
            )
            .await
            .map_err(|cause| match cause {
                Error::Wire(wire::Error::Deadline) if Instant::now() >= deadline => {
                    Error::WaitExpired { operation }
                }
                cause => Error::Observation {
                    operation,
                    cause: Box::new(cause),
                },
            })?;
        let observed = Operation::decode(&reply)?;
        if observed.id != operation {
            return Err(Error::Observation {
                operation,
                cause: Box::new(Error::UnexpectedReply),
            });
        }
        match observed.state {
            OperationState::Succeeded => {
                return Ok(format!("Operation {}: succeeded\n", identifier(&operation)));
            }
            OperationState::Failed | OperationState::Superseded => {
                return Err(Error::Operation(observed));
            }
            OperationState::Accepted | OperationState::Running => {}
        }
        let wake = (Instant::now() + POLL_INTERVAL).min(deadline);
        tokio::select! {
            biased;
            () = cancelled(cancel) => return Err(Error::Observation { operation, cause: Box::new(Error::Wire(wire::Error::Cancelled)) }),
            () = sleep_until(wake) => {}
        }
        if *cancel.borrow() {
            return Err(Error::Observation {
                operation,
                cause: Box::new(Error::Wire(wire::Error::Cancelled)),
            });
        }
    }
}

struct Client<S> {
    stream: S,
    request_id: u64,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    async fn exchange(
        &mut self,
        kind: Kind,
        body: Vec<u8>,
        expected: Kind,
        observer_deadline: Option<Instant>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Frame, Error> {
        self.request_id = self
            .request_id
            .checked_add(1)
            .ok_or(Error::UnexpectedReply)?;
        let deadline = observer_deadline.map_or(Instant::now() + RPC_TIMEOUT, |deadline| {
            deadline.min(Instant::now() + RPC_TIMEOUT)
        });
        let request = Frame::new(kind, self.request_id, body)?;
        request.write(&mut self.stream, deadline, cancel).await?;
        let reply =
            Frame::read_limited(&mut self.stream, deadline, cancel, MAX_REPLY_BYTES).await?;
        if reply.request_id() != self.request_id {
            return Err(Error::UnexpectedReply);
        }
        if reply.kind() == Kind::ErrorReply {
            return Err(Error::Service(Code::parse(u16::from_be_bytes([
                reply.body()[0],
                reply.body()[1],
            ]))?));
        }
        if reply.kind() != expected {
            return Err(Error::UnexpectedReply);
        }
        Ok(reply)
    }
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() || cancel.changed().await.is_err() {
            return;
        }
    }
}

fn identifier(value: &[u8; 16]) -> String {
    use fmt::Write;
    let mut result = String::with_capacity(32);
    for byte in value {
        // Writing to an owned String cannot fail.
        write!(result, "{byte:02x}").expect("String formatting is infallible");
    }
    result
}
fn format_status(status: Status, json: bool) -> String {
    if json {
        format!(
            "{{\"state\":\"{}\",\"configuration_generation\":{},\"owner_revision\":{},\"configuration_present\":{},\"desired_revision\":{}}}\n",
            status.state.name(),
            status.configuration_generation,
            status.owner_revision,
            status.configuration_present,
            status.desired_revision
        )
    } else {
        format!(
            "State: {}\nConfiguration: {} (generation {})\nOwner revision: {}\nDesired revision: {}\n",
            status.state.name(),
            if status.configuration_present {
                "installed"
            } else {
                "absent"
            },
            status.configuration_generation,
            status.owner_revision,
            status.desired_revision
        )
    }
}

#[cfg(test)]
mod tests;
