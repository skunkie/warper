<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0016. Bounded read-only Linux route lookups

- Status: accepted read-only boundary; physical path and mutation pending.
- Date: 2026-10-31
- Related: ADR 0014, physical path contract, NET-01 and NET-05.

## Context and alternatives

The Linux driver needs native route observations before it can protect numeric
SOCKS endpoints and publish capture routes. A command subprocess cannot provide
production socket ownership, typed replies or precise cancellation. The higher
level rtnetlink connection also introduces an unsolicited message channel whose
retention would require separate bounding. Local netlink parsing or unsafe
socket registration would expand the project's maintenance and safety boundary.

## Decision

Use released MIT `netlink-packet-core` 0.9.0 and `netlink-packet-route` 0.33.0
behind the service's Linux adapter, with `netlink-sys` 0.9.0's safe Tokio socket
API. These versions already exist in the lockfile; enable the socket's Tokio
feature without upgrading existing packages. The upstream socket owns its stable
close-on-exec descriptor and nonblocking reactor registration. No local unsafe
code, detached connection task, notification queue or generic mutation API is
introduced.

A query owns one socket and one nonrepeating process-local sequence number.
Request a single IPv4 TCP route with destination/port, native effective UID and
optional actual source/port and output interface. Carry the whole deadline and
cancellation through send/receive; owner loss cancels. Drop closes the socket.
Never resend after successful send, and never infer success from an ACK.

Enable strict kernel input checking and cap the kernel receive queue at 64 KiB
(including Linux doubling). Bound the serialized request to 128 bytes and the
received datagram to 32 KiB.
Receive into a fixed slice with one extra byte; oversized/truncated input cannot
become a successful prefix. Accept exactly one complete correlated kernel
unicast reply. Reject overrun, unknown/multipart messages, invalid errno, missing
or duplicate routing attributes and unrepresentable routes. Decode using the
released packet libraries only after checking the envelope and length bound.
The IPv4 RTCF_LOCAL flag is recognized only for local routes. Unknown flags,
multipath, nexthop indirection, encapsulation and other unsupported attributes
fail closed. Errors and Debug output do not contain route addresses or payloads.

## Consequences

An observation contains the reported interface index, selected source, optional
gateway, reported table and local/unicast kind. It is not an owned interface
identity, a routing exemption, a consistent monitored snapshot or permission to
send. Source/interface binding, route/link/address/rule notification processing,
uncertainty invalidation, ownership journals and mutation ACKs remain required.
No existing connector is authorized by this observation. Callers must limit
concurrent lookups, reserve transient parsing memory and retain the futures.
The native adapter is Linux-only; no macOS integration is implied.

## Validation and reconsideration

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p warper-service linux::route_lookup
CARGO_INCREMENTAL=0 cargo llvm-cov --locked -p warper-service --all-features --html
CARGO_INCREMENTAL=0 scripts/check.sh
```

Controlled native tests query loopback with and without a source/interface
constraint and check a genuine kernel rejection for an absent interface. No
external DNS, network payload or host mutation is involved. Malformed replies,
correlation, unsupported routes and deadline/cancellation have separate tests.
The existing owner-dispatched isolated TUN fixture also runs a private loopback
query; fresh root CI execution remains pending until recorded in the ledger.
Retain raw evidence under `target/evidence/phase-1/linux-route-lookup/`.
Reconsider if required routes cannot be represented, measured preflight costs
are excessive or the upstream socket ownership contract changes.
