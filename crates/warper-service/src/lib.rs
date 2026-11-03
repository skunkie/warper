// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Owned networking tasks and Linux daemon/control/platform composition.

pub mod dns;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod native;
pub mod preflight;
pub mod relay;
pub mod telemetry;
