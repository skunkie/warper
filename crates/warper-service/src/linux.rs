// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native Linux boundaries. Read-only lookup is not a physical-path lease.

use nix::errno::Errno;
use std::{fmt, io};

pub mod change_monitor;
pub mod context;
pub mod link_lookup;
mod netlink;
pub mod route_lookup;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryError {
    InvalidInput,
    ResourceLimit,
    Cancelled,
    Timeout,
    Socket(Errno),
    Io(io::ErrorKind),
    UnexpectedSender,
    InvalidReply,
    Lost,
    UnsupportedRoute,
    UnsupportedLink,
    Kernel(i32),
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "InvalidConfig: invalid native network query",
            Self::ResourceLimit => "ResourceLimit: native network query capacity exhausted",
            Self::Cancelled => "Cancelled: native network query cancelled",
            Self::Timeout => "Timeout: native network query deadline expired",
            Self::Socket(_) | Self::Io(_) => "NativeIo: native network query failed",
            Self::UnexpectedSender => "NativeProtocol: native query reply is not from the kernel",
            Self::InvalidReply => "NativeProtocol: invalid or uncorrelated native query reply",
            Self::Lost => "NativeUncertain: native query reply lost or truncated",
            Self::UnsupportedRoute => {
                "UnsupportedIntegration: native network query cannot be represented"
            }
            Self::UnsupportedLink => "UnsupportedIntegration: link metadata cannot be represented",
            Self::Kernel(_) => "NativeRejected: kernel rejected native network query",
        })
    }
}
impl std::error::Error for QueryError {}
