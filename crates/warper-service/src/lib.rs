// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Owned networking tasks; the daemon/control/platform composition is pending.

#[cfg(target_os = "linux")]
pub mod linux;
pub mod preflight;
pub mod relay;
