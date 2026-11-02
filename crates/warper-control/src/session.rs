// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Linux framed request ownership. Command execution belongs to the service.

use std::fmt;
use tokio::{
    net::UnixStream,
    sync::{OwnedSemaphorePermit, watch},
    time::Instant,
};

use crate::{
    Access, OwnerPolicy, Role,
    admission::{self, ClientPermit},
    unix,
    wire::{self, Frame, Kind},
};

pub const MIN_MESSAGE_BYTES: usize = 68;
const MAX_MESSAGE_BYTES: usize = 20 + wire::MAX_BODY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    Admission(admission::Error),
    InvalidInstance,
    Closed,
    Sequence,
    Authentication(crate::Error),
    Frame(wire::Error),
    UnexpectedRequest,
    UnexpectedReply,
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(formatter),
            Self::InvalidLimits => {
                formatter.write_str("ResourceLimit: invalid control session message limit")
            }
            Self::InvalidInstance => {
                formatter.write_str("InvalidConfig: control session needs a service instance")
            }
            Self::Closed => formatter.write_str("Protocol: control session is closed"),
            Self::Sequence => formatter.write_str("Protocol: invalid control session sequence"),
            Self::Authentication(error) => error.fmt(formatter),
            Self::Frame(error) => error.fmt(formatter),
            Self::UnexpectedRequest => {
                formatter.write_str("Protocol: unexpected control request or identity")
            }
            Self::UnexpectedReply => {
                formatter.write_str("Protocol: control reply does not match its request")
            }
        }
    }
}
impl std::error::Error for Error {}

/// Authorization at dispatch time only. Queued/waiting handlers must authorize
/// again against protected state immediately before their mutation boundary.
pub struct AuthorizedRequest {
    frame: Frame,
    role: Role,
    _reservation: Option<OwnedSemaphorePermit>,
}
impl AuthorizedRequest {
    pub fn frame(&self) -> &Frame {
        &self.frame
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn reply(&self, kind: Kind, body: Vec<u8>) -> Result<Frame, Error> {
        if !reply_matches(self.frame.kind(), kind) {
            return Err(Error::UnexpectedReply);
        }
        Frame::new(kind, self.frame.request_id(), body).map_err(Error::Frame)
    }
}
impl fmt::Debug for AuthorizedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedRequest(<redacted>)")
    }
}

pub struct Session {
    stream: Option<UnixStream>,
    instance: [u8; 16],
    max_encoded: usize,
    pending: Option<Frame>,
    active: Option<(Kind, u64)>,
    hello_done: bool,
    last_id: u64,
    pending_reservation: Option<OwnedSemaphorePermit>,
    client: Option<ClientPermit>,
}
impl Session {
    pub fn new(stream: UnixStream, instance: [u8; 16], max_encoded: usize) -> Result<Self, Error> {
        if instance == [0; 16] {
            return Err(Error::InvalidInstance);
        }
        if !(MIN_MESSAGE_BYTES..=MAX_MESSAGE_BYTES).contains(&max_encoded) {
            return Err(Error::InvalidLimits);
        }
        Ok(Self {
            stream: Some(stream),
            instance,
            max_encoded,
            pending: None,
            active: None,
            hello_done: false,
            last_id: 0,
            pending_reservation: None,
            client: None,
        })
    }

    /// Use the service's shared admission owner, retaining its client capacity.
    pub fn admitted(
        stream: UnixStream,
        instance: [u8; 16],
        client: ClientPermit,
    ) -> Result<Self, Error> {
        let mut session = Self::new(stream, instance, client.max_encoded())?;
        session.client = Some(client);
        Ok(session)
    }

    /// Admission policy is checked before frame allocation. Load fresh protected
    /// policy after this await and pass it to authorize before dispatch.
    pub async fn receive(
        &mut self,
        policy: &OwnerPolicy,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), Error> {
        if self.stream.is_none() {
            return Err(Error::Closed);
        }
        if self.pending.is_some() || self.active.is_some() {
            return self.fail(Error::Sequence);
        }
        let mut stream = self.stream.take().ok_or(Error::Closed)?;
        unix::authenticate_client(&stream, policy, Access::Observe)
            .map_err(Error::Authentication)?;
        let reservation = match &self.client {
            Some(client) => Some(
                client
                    .request(deadline, cancel)
                    .await
                    .map_err(Error::Admission)?,
            ),
            None => None,
        };
        let frame = Frame::read_limited(&mut stream, deadline, cancel, self.max_encoded)
            .await
            .map_err(Error::Frame)?;
        // Taking the stream before await makes abandonment terminal, including
        // dropping this future from an outer select after a partial header.
        self.pending = Some(frame);
        self.pending_reservation = reservation;
        self.stream = Some(stream);
        Ok(())
    }

    pub fn authorize(&mut self, policy: &OwnerPolicy) -> Result<AuthorizedRequest, Error> {
        if self.stream.is_none() {
            return Err(Error::Closed);
        }
        let Some(frame) = self.pending.take() else {
            return self.fail(Error::Sequence);
        };
        if !frame.kind().is_request()
            || frame.request_id() <= self.last_id
            || (!self.hello_done && frame.kind() != Kind::Hello)
            || (self.hello_done && frame.kind() == Kind::Hello)
        {
            return self.fail(Error::UnexpectedRequest);
        }
        let role = match unix::authenticate_client(
            self.stream.as_ref().ok_or(Error::Closed)?,
            policy,
            access(frame.kind()),
        ) {
            Ok(role) => role,
            Err(error) => return self.fail(Error::Authentication(error)),
        };
        self.last_id = frame.request_id();
        self.active = Some((frame.kind(), frame.request_id()));
        Ok(AuthorizedRequest {
            frame,
            role,
            _reservation: self.pending_reservation.take(),
        })
    }

    pub async fn respond(
        &mut self,
        frame: Frame,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), Error> {
        if self.stream.is_none() {
            return Err(Error::Closed);
        }
        let Some((kind, request_id)) = self.active else {
            return self.fail(Error::Sequence);
        };
        if frame.request_id() != request_id
            || !reply_matches(kind, frame.kind())
            || (frame.kind() == Kind::HelloReply && frame.body() != self.instance)
        {
            return self.fail(Error::UnexpectedReply);
        }
        let mut stream = self.stream.take().ok_or(Error::Closed)?;
        // Failed/dropped writes permanently close ownership. Never restart a
        // partially sent response or replay an accepted operation's payload.
        frame
            .write_limited(&mut stream, deadline, cancel, self.max_encoded)
            .await
            .map_err(Error::Frame)?;
        self.active = None;
        if kind == Kind::Hello {
            if frame.kind() != Kind::HelloReply {
                return Ok(());
            }
            self.hello_done = true;
        }
        self.stream = Some(stream);
        Ok(())
    }

    pub fn instance_id(&self) -> &[u8; 16] {
        &self.instance
    }
    pub fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stream = None;
        self.pending = None;
        self.pending_reservation = None;
        self.active = None;
        Err(error)
    }
}
impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlSession(<redacted>)")
    }
}

fn access(kind: Kind) -> Access {
    match kind {
        Kind::Connect | Kind::Disconnect => Access::Operate,
        Kind::Enroll | Kind::InstallConfig | Kind::InspectRecovery => Access::Administer,
        _ => Access::Observe,
    }
}
fn reply_matches(request: Kind, reply: Kind) -> bool {
    if reply == Kind::ErrorReply {
        return true;
    }
    matches!(
        (request, reply),
        (Kind::Hello, Kind::HelloReply)
            | (Kind::Status, Kind::StatusReply)
            | (Kind::Connect | Kind::Disconnect, Kind::Accepted)
            | (Kind::Enroll, Kind::EnrollmentReply)
            | (Kind::InstallConfig, Kind::ConfigReply)
            | (Kind::InspectRecovery, Kind::RecoveryReply)
            | (Kind::OperationStatus, Kind::OperationReply)
    )
}
