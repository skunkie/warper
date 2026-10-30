// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Backend-independent selection policy. Networking belongs to the service.

pub mod routing;

/// Registry identity within one immutable configuration generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendId(pub u64);
