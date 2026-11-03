// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded DNS protocol adapters. These do not publish answers or routes.

mod packet;
mod query;
mod tcp;
mod udp;

pub use packet::{Error, Limits, Packet, Question};
pub use query::QueryBudget;
pub use tcp::{Admission, DirectTcpTransport, ExchangeError, TcpTransport};
pub use udp::DirectUdpTransport;
