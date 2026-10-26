<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0002. Userspace stack selection

- Status: proposed; no stack has been selected or demonstrated.
- Date: 2026-10-26
- Related: [plan section 2.1](../implementation-plan.md#21-dependency-and-stack-feasibility-gate),
  [implementation contracts](../implementation-contracts.md), NET-01,
  NET-05, NET-06, and NET-07 in the [acceptance contract](../acceptance.md).

## Context

Two independent capabilities are required: accepting transparent TCP/UDP
flows from host TUN packets, and actively dialing sockets through a userspace
WireGuard tunnel. A library implementing one role does not prove it supports
the other. The choice must preserve original destinations, cancellation,
bounded buffers, half-close, and datagram semantics on Linux and macOS.

## Alternatives

Evaluate pinned versions/APIs of `ipstack`, `netstack-smoltcp`/`smoltcp`,
and any justified alternatives. A configured proxy runner is usable only if
its embedding/dispatch boundary meets the contract. A local proxy bridge or
fork requires explicit maintenance/extra-hop analysis. Do not infer accepted
capabilities from dependency names or README descriptions.

## Decision

Pending Phase 0. Fill in exact selected versions/features, role-specific API
calls, supported platforms/families, adapter responsibilities, and reasons
for rejecting alternatives after executable probes. Do not accept the ADR
until both role gates pass against controlled peers and the initial
implementation contracts have compile-checked usage.

## Consequences

Until accepted, keep experimental packages isolated from production-facing
interfaces. The adapters may differ by role; the production workspace must
hide third-party types behind the contracts needed by its next working
slice. Record any fork, unsupported behavior, or platform limitation before
dependent implementation begins.

## Validation and reconsideration

Phase 0 must add `scripts/verify-feasibility.sh` and document clean-checkout
peer/isolation setup. Required entry points will be:

```sh
./scripts/verify-feasibility.sh host-stack
./scripts/verify-feasibility.sh wireguard-stack
```

These commands are required deliverables, not implemented commands yet.
Artifacts go under `target/evidence/phase-0/`, with exact environment,
dependency versions, assertions, redacted traffic summaries, cancellation,
cleanup, IPv4/IPv6, and rekey results. Record native macOS evidence separately.
Revisit on a failed required capability, dependency API change, unsupported
platform behavior, or unacceptable maintenance cost.
