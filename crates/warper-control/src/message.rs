// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Typed version-two control metadata shared by native clients and handlers.
//! These values contain no credentials and do not establish authority/readiness.

use crate::wire::{Code, Error, Frame, Kind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionState {
    Disconnected = 0,
    Preparing = 1,
    Connected = 2,
    Disconnecting = 3,
    Failed = 4,
    RecoveryRequired = 5,
}
impl SessionState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Preparing => "preparing",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::Failed => "failed",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}
impl TryFrom<u8> for SessionState {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Disconnected),
            1 => Ok(Self::Preparing),
            2 => Ok(Self::Connected),
            3 => Ok(Self::Disconnecting),
            4 => Ok(Self::Failed),
            5 => Ok(Self::RecoveryRequired),
            _ => Err(Error::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub state: SessionState,
    pub configuration_generation: u64,
    pub owner_revision: u64,
    pub configuration_present: bool,
    pub desired_revision: u64,
}
impl Status {
    pub fn frame(self, request_id: u64) -> Result<Frame, Error> {
        let mut body = Vec::with_capacity(26);
        body.push(self.state as u8);
        body.extend_from_slice(&self.configuration_generation.to_be_bytes());
        body.extend_from_slice(&self.owner_revision.to_be_bytes());
        body.push(u8::from(self.configuration_present));
        body.extend_from_slice(&self.desired_revision.to_be_bytes());
        Frame::new(Kind::StatusReply, request_id, body)
    }
    pub fn decode(frame: &Frame) -> Result<Self, Error> {
        if frame.kind() != Kind::StatusReply {
            return Err(Error::Malformed);
        }
        let body = frame.body();
        Ok(Self {
            state: SessionState::try_from(body[0])?,
            configuration_generation: number(&body[1..9])?,
            owner_revision: number(&body[9..17])?,
            configuration_present: body[17] != 0,
            desired_revision: number(&body[18..26])?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperationState {
    Accepted = 0,
    Running = 1,
    Succeeded = 2,
    Failed = 3,
    Superseded = 4,
}
impl OperationState {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Superseded)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
        }
    }
}
impl TryFrom<u8> for OperationState {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Running),
            2 => Ok(Self::Succeeded),
            3 => Ok(Self::Failed),
            4 => Ok(Self::Superseded),
            _ => Err(Error::Malformed),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    pub id: [u8; 16],
    pub state: OperationState,
    pub code: Code,
}
impl Operation {
    pub fn frame(self, request_id: u64) -> Result<Frame, Error> {
        let mut body = Vec::with_capacity(19);
        body.extend_from_slice(&self.id);
        body.push(self.state as u8);
        body.extend_from_slice(&(self.code as u16).to_be_bytes());
        Frame::new(Kind::OperationReply, request_id, body)
    }
    pub fn decode(frame: &Frame) -> Result<Self, Error> {
        if frame.kind() != Kind::OperationReply {
            return Err(Error::Malformed);
        }
        let body = frame.body();
        Ok(Self {
            id: body[..16].try_into().map_err(|_| Error::Malformed)?,
            state: OperationState::try_from(body[16])?,
            code: Code::parse(u16::from_be_bytes([body[17], body[18]]))?,
        })
    }
}

fn number(bytes: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| Error::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_preserves_independent_configuration_owner_and_desired_revisions() {
        for state in [
            SessionState::Disconnected,
            SessionState::Preparing,
            SessionState::Connected,
            SessionState::Disconnecting,
            SessionState::Failed,
            SessionState::RecoveryRequired,
        ] {
            let status = Status {
                state,
                configuration_generation: 17,
                owner_revision: 29,
                configuration_present: true,
                desired_revision: u64::MAX,
            };
            let frame = status.frame(41).unwrap();
            assert_eq!(frame.request_id(), 41);
            assert_eq!(frame.body().len(), 26);
            assert_eq!(frame.body()[17], 1);
            assert_eq!(Status::decode(&frame), Ok(status));
        }
        let absent = Status {
            state: SessionState::Disconnected,
            configuration_generation: 0,
            owner_revision: 0,
            configuration_present: false,
            desired_revision: 0,
        };
        assert_eq!(Status::decode(&absent.frame(1).unwrap()), Ok(absent));
        assert_eq!(SessionState::try_from(6), Err(Error::Malformed));
        assert_eq!(
            Status::decode(&Frame::new(Kind::Status, 1, vec![]).unwrap()),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn operation_terminal_state_and_failure_code_are_not_interchangeable() {
        let id = crate::wire::operation_id(13, [7; 8]).unwrap();
        for state in [
            OperationState::Accepted,
            OperationState::Running,
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Superseded,
        ] {
            let code = if state == OperationState::Failed {
                Code::RecoveryRequired
            } else {
                Code::None
            };
            let operation = Operation { id, state, code };
            let frame = operation.frame(9).unwrap();
            assert_eq!(Operation::decode(&frame), Ok(operation));
            assert_eq!(
                state.terminal(),
                !matches!(state, OperationState::Accepted | OperationState::Running)
            );
        }
        assert!(matches!(
            Operation {
                id,
                state: OperationState::Failed,
                code: Code::None
            }
            .frame(1),
            Err(Error::Malformed)
        ));
        assert!(matches!(
            Operation {
                id,
                state: OperationState::Succeeded,
                code: Code::Failed
            }
            .frame(1),
            Err(Error::Malformed)
        ));
        assert_eq!(OperationState::try_from(5), Err(Error::Malformed));
        assert_eq!(
            Operation::decode(&Frame::new(Kind::Status, 1, vec![]).unwrap()),
            Err(Error::Malformed)
        );
    }
}
