<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0021. Linux bound TCP egress API

- Status: proposed; real competing-route TCP evidence pending.
- Date: 2026-10-31
- Related: ADR 0016, NET-01 and NET-04.

## Context and alternatives

The service must protect numeric SOCKS5 endpoints from its capture routes.
Read-only route/link observations do not establish socket egress. An unbound
connection followed by post-connect inspection can already have emitted a SYN
through capture. Source binding alone does not constrain the egress interface.
Manual prefix exemptions have separate journal/ownership/conflict obligations.

## Proposed decision

Probe the released Tokio IPv4 TCP source/device binding API before production
modules depend on it. Bind the verified source and device before connect,
read back the option and actual ephemeral tuple, then query that same tuple
with the interface constraint. Require actual peer traffic under a competing
TUN /32, preserving source/port, payload boundaries and response after FIN.
The capture TUN must observe no IPv4 packet from that connection. No failure
may fall back to an unbound socket.

Use the existing disposable private Linux harness and a second fixture-only
network namespace connected by veth. Create an unnamed fresh capture TUN and
rename it atomically. Retain/join the peer process, bound readiness and all I/O,
and clean up fixture-owned objects independently of production journals.
The experiment does not implement a physical connector or claim capture-route
ownership. Virtual routed evidence does not prove a hardware NIC deployment.

## Consequences and limits

The eventual connector must also own path generations and budgets, revalidate
before sends and fail closed on network changes/loss. Production exemption
policy and continuous invalidation remain open even if this experiment passes.
No new dependency, local unsafe code, public network peer or host resolver
mutation is needed. A negative competing-route result requires a different
mechanism; it must never be hidden by a successful unbound retry.

## Evidence and reproduction

Run `CARGO_INCREMENTAL=0 scripts/check.sh`. Native execution runs only via the
owner-dispatched Linux CI's `linux_network_probe` under
`scripts/control_acceptance.py`, preserving raw artifacts and independent host
state checks. The `--physical-peer` role requires initial root plus inherited
private namespace anchors and accepts one bounded synthetic connection.
Evidence belongs under `target/evidence/phase-1/bound-tcp-egress/`. Real native
binding/bypass behavior remains unverified pending that run.
