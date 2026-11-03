// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Packet-stack adapters behind backend-independent application streams.

mod device;
pub mod host;
pub mod runtime;
mod seed;

pub use seed::{Error as SeedError, Seed};

#[cfg(test)]
mod fixture;
