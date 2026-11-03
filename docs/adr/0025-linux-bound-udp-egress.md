<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0025. Linux bound UDP egress mechanism

- Status: proposed
- Date: 2026-11-03
- Related contracts and acceptance criteria: ADR 0016, ADR 0021, NET-02, NET-08.

## Context

Unmatched DNS must reach a preserved physical resolver after capture routes and
system DNS policy are installed. The existing protected connector proves TCP
tuples only. UDP route selection must query protocol 17 with the actual bound
source port; TCP route observations cannot authorize UDP sends.

## Alternatives

- Unbound UDP with post-send inspection can emit a datagram into capture before
  detecting a routing loop.
- Source binding alone does not constrain the outgoing device.
- Source/device binding before connect/send can use the same physical path
  selection and change-invalidation model as the TCP connector, subject to an
  executable UDP mechanism gate.

## Decision

Extend the bounded read-only route query with explicit `Protocol::{Tcp, Udp}`.
Encode the corresponding IP protocol and reject an inconsistent returned echo.
Existing callers explicitly select TCP. Probe Tokio 1.54.1's released UDP
source/device API in the existing private native fixture before production DNS
depends on it. Bind the source, set/read back the device, obtain the actual
ephemeral tuple and constrain that UDP tuple's kernel lookup before connecting
or sending. Binding itself emits no application datagram.

Accept the scoped mechanism only after the owner-dispatched isolated gate
passes real UDP roundtrips under a competing TUN /32. The unconstrained UDP
lookup must select capture, the device-constrained lookup must preserve the
original egress, two different payload lengths must retain datagram boundaries,
the peer must report the original source port, and capture must observe no
IPv4 traffic from either the UDP or existing TCP exchanges.

## Consequences

No new dependency, unsafe code or host resolver mutation is needed. The fixture
retains and joins its existing peer process, bounds readiness/I/O and removes
its private veth and namespace independently of service journals. This evidence
is virtual routed Linux IPv4 traffic, not hardware or IPv6 deployment proof.

The experiment is not a production datagram connector. Production must retain
native ownership, limit/read back kernel queues, validate before every send,
invalidate on network changes/loss and release request/socket admission on drop.
DNS UDP/TCP fallback must use the same upstream/path and original deadline;
selected-backend errors must never switch to direct traffic.

## Validation and reconsideration

Run `scripts/check.sh`. Run `linux_network_probe` only through the
owner-dispatched workflow and `scripts/control_acceptance.py`; ordinary local
execution does not establish privileged evidence. Retain manifests/logs under
`target/evidence/phase-2/bound-udp-egress/`. The `--physical-peer` role remains
limited to inherited private namespace anchors and a fixed synthetic peer.
Reject the mechanism if tuple proof differs, capture sees the traffic or cleanup
cannot be established. Revisit on routing-policy, binding-API or supported
underlay changes. DNS transport and resolver integration are separate gates.
