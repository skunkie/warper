// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native configuration preparation for ordinary-user import and diagnostics.
//! The installed service uses protected managed material instead of these paths.

pub mod schema;
pub mod source;
pub mod yaml;

#[cfg(unix)]
pub mod identity;
