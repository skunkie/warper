<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0021. Linux bound TCP egress API

- Status: accepted scoped protected TCP connector; full driver integration pending.
- Date: 2026-10-31
- Related: ADR 0016, NET-01 and NET-04.

## Context and alternatives

The service must protect numeric SOCKS5 endpoints from its capture routes.
Read-only route/link observations do not establish socket egress. An unbound
connection followed by post-connect inspection can already have emitted a SYN
through capture. Source binding alone does not constrain the egress interface.
Manual prefix exemptions have separate journal/ownership/conflict obligations.

## Decision

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
binding/bypass behavior passes in [owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41235377897)
at `999e86f`, with independently preserved host state. This establishes the
scoped socket mechanism; hardware deployment and complete daemon acceptance
remain unverified.

## Initial connector implementation

Preparation records deterministic route/link selection for at most 64 IPv4
endpoints under a change subscription, after native-worker context validation.
These observations confer no send authority. Each dial reserves one of at most
16 lifetime slots, subscribes afresh, verifies the selected link, binds source
and device, and validates the actual tuple route before connect and again before
return. Limit/read back TCP receive/send kernel buffers to 64 KiB each.

Support unstacked Ethernet/veth unicast and explicit local loopback endpoints;
reject other underlays and mismatches without alternate selection. Per-stream
monitor polling wakes both I/O directions, closes the socket on any change/loss
and preserves half-close ownership. No monitor task is detached. Socket and
monitor retire before their permit and native context. Kernel queue accounting
is exposed separately from payload budgets; full service admission remains an
integration gate. Genuine production connector/idle-invalidation execution
passes in [owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41239873952)
at `25396a0`, including an independently parked reader, retained half-close
admission, changed-path rejection and the real journaled TUN/SOCKS flow. Both
root probes exit zero without timeout and preserve host state independently.
Production capture ownership, full native-budget admission and complete daemon
readiness remain open.
