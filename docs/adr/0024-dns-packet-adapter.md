<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0024. Bounded DNS packet adapter

- Status: accepted
- Date: 2026-11-03
- Related contracts and acceptance criteria: implementation-contracts, Phase 2;
  NET-02, NET-03 and NET-11.

## Context

Phase 2 needs compressed DNS names, EDNS, valid negatives and RFC 9460 records.
Core names and domain matching already preserve arbitrary wire labels separately
from configuration IDNA normalization. A DNS parser must not allocate record
vectors from untrusted counts before admission or expose upstream diagnostics
containing names or record data. A truncated UDP reply may end inside a record;
TCP retry needs the original ID and complete question correlation first.

## Alternatives

- Handwritten DNS record decoding avoids dependencies but adds a substantial
  protocol maintenance and adversarial-input burden, especially for SVCB.
- Hickory's resolver provides DNS resolution policy and network transports that
  would duplicate the service's selected-backend and physical-path ownership.
- Hickory's protocol library provides packet parsing and encoding without an
  independent resolver or service task tree.

## Decision

Use released `hickory-proto` 0.26.3 with only `std`, pinned in the workspace and
lockfile. Keep its types behind `warper_service::dns::Packet`. Do not enable a
resolver, DNSSEC cryptography, mDNS, access-control or runtime integrations.
The packet fixtures and repository checks establish this scoped boundary;
this decision does not accept production DNS routing or native integration.

Admit wire bytes and total answer/authority/additional counts before library
decoding. Require exactly one question and standard-query opcode. Validate
response ID, canonical question, class, type and direction before recognizing
truncation. Truncation returns a typed retry indication, never a partial packet.
Full packets must consume all input. Output limits apply during serialization;
implicit library record truncation is rejected rather than passed as success.
Protocol errors and Debug output are
redacted. Preserve valid response codes, TTLs, parameters and unknown data.

## Consequences

The protocol library adds its locked dependencies, including a second rand
generation and platform-specific Android discovery support through its generic
protocol graph. Existing locked versions remain unchanged. Its MIT/Apache-2.0
license fits dependency policy. Names remain bounded by DNS wire limits.
Record vectors and expanded names are bounded by the admitted record count;
wire payload storage is bounded separately by packet size. These are per-packet
bounds, not a service-wide RSS claim. Retained caches, leases and concurrent
request admission still need independent accounting.

No I/O, timers or tasks are started by this adapter. Transports must own the
selected backend, original deadline, cancellation and TCP retry. The endpoint
and route gate must authorize every positive answer before output; successful
packet decoding or encoding never grants that authorization.

## Validation and reconsideration

Run `cargo test --locked -p warper-service --lib dns::packet`, then
`scripts/check.sh`. Fixtures cover compressed records, binary/protocol names,
valid negatives, TTL zero, malformed lengths/pointers, admission, response
correlation, partial truncated records, EDNS and SVCB/HTTPS parameter order and
roundtrips. Evidence belongs under `target/evidence/phase-2/packet-adapter/`.
These are deterministic parser fixtures; physical transport and routing are
not exercised. Reconsider on parser advisories, unbounded decoding behavior,
protocol incompatibility or a required dependency feature change.
