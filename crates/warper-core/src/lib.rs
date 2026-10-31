// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Backend-independent policy and offline configuration preparation.

pub mod configuration;
pub mod routing;
pub mod transport;

/// Registry identity within one immutable configuration generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendId(pub u64);
