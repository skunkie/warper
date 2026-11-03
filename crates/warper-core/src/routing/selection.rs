// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Atomic flow selection with optional DNS route ownership.

use std::{fmt, net::IpAddr};

use super::Policy;
use crate::{BackendId, dns::lease::Flow};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionError {
    Unselected,
    Busy,
    Unready,
    Unavailable,
}
impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unselected => "destination has no selected route",
            Self::Busy => "route selection admission is busy",
            Self::Unready => "selected route is not ready for flow admission",
            Self::Unavailable => "route selection owner is unavailable",
        })
    }
}
impl std::error::Error for SelectionError {}

/// Move the entire selection into the flow's shared lifetime. Dropping it
/// releases any DNS pin; observing the backend does not detach ownership.
pub struct Selection {
    backend: BackendId,
    _pin: Option<Flow>,
}
impl Selection {
    pub fn static_route(backend: BackendId) -> Self {
        Self {
            backend,
            _pin: None,
        }
    }
    pub fn leased(backend: BackendId, pin: Flow) -> Self {
        Self {
            backend,
            _pin: Some(pin),
        }
    }
    pub fn backend(&self) -> BackendId {
        self.backend
    }
}
impl fmt::Debug for Selection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Selection([redacted])")
    }
}

pub trait FlowSelector: Send + Sync {
    fn static_policy(&self) -> &Policy;
    fn lookup(&self, destination: IpAddr) -> Result<BackendId, SelectionError>;
    fn select_flow(&self, destination: IpAddr) -> Result<Selection, SelectionError>;
}
impl FlowSelector for Policy {
    fn static_policy(&self) -> &Policy {
        self
    }
    fn lookup(&self, destination: IpAddr) -> Result<BackendId, SelectionError> {
        self.select(destination).ok_or(SelectionError::Unselected)
    }
    fn select_flow(&self, destination: IpAddr) -> Result<Selection, SelectionError> {
        self.lookup(destination).map(Selection::static_route)
    }
}
