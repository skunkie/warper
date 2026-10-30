// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Executable contract models, not platform drivers or a production service.
//!
//! The models make ownership and publication transitions observable without
//! depending on a third-party network stack or mutating the host.

pub mod dns;
pub mod routes;
pub mod supervisor;
pub mod transport;
