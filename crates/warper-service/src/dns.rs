// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded DNS protocol adapters. These do not publish answers or routes.

pub mod output;
mod packet;
mod query;
pub mod routes;
mod tcp;
mod udp;

pub use packet::{
    Address, AddressAnswer, AddressError, AddressLookup, AddressProgress, AddressSection,
    BindingSet, Error, Limits, LocalReply, Packet, Question, RelatedAddress, RelatedSet,
    ServiceAlias, ServiceBinding, ServiceError, TimedAlias,
};
pub use query::QueryBudget;
pub use tcp::{
    AddressDiscoveryLimits, AddressResolution, Admission, DependencyKind, DirectTcpTransport,
    DiscoveryError, EndpointPath, EndpointSource, ExchangeError, ServiceDiscoveryError,
    ServiceDiscoveryLimits, ServiceEndpoint, ServiceResolution, TcpTransport,
};
pub use udp::DirectUdpTransport;
