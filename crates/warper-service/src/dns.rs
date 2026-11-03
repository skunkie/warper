// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded DNS protocol adapters. These do not publish answers or routes.

mod packet;
mod tcp;

pub use packet::{Error, Limits, Packet, Question};
pub use tcp::{Admission, ExchangeError, TcpTransport};
