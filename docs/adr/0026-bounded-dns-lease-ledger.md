<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0026. Fixed-capacity DNS lease and reference ownership

- Status: accepted
- Date: 2026-11-03
- Related contracts and acceptance criteria:
  [retained DNS state](../configuration.md#retained-dns-state-admission),
  [production ledger](../implementation-contracts.md#production-dns-lease-ledger),
  [ADR 0003](0003-dns-endpoint-routing.md), NET-10 and NET-12.

## Context

DNS freshness, pending output, timed route retention and active flows have
separate lifetimes. Distinct question keys must consume capacity even when
one IP/backend is shared, while same-key renewal must not append stale timer
records. The initial contract model established these policies but used
fixed experiment limits, logical allocation charges and manually released
flow handles. Native route publication and output remain separate gates.

## Alternatives

- Grow maps, provenance objects and expiry queues on demand. This requires
  capacity/allocator accounting and bounded timer compaction at each mutation.
- Retain every DNS question for each active flow. This protects routing but
  unnecessarily prevents expired name metadata from being reclaimed.
- Preallocate bounded lease/address/reference storage and track flows against
  shared address ownership, with separate timed leases and pending responses.

## Decision

Use the final approach in the production
[core ledger](../../crates/warper-core/src/dns/lease.rs). Allocate fixed slots,
open-addressed indexes, free lists and response/flow metadata before native
mutation. Derive the effective lease capacity from both the configured count
and retained-byte budget. Charge actual capacities, control storage and
reserved handles; document allocator/runtime overhead separately. No shared
response cache is implemented.

Opaque handles use fixed atomic drop markers and one coalesced owner wake.
Maintain one conservative next-expiry timestamp, recomputing it on expiry;
renewal never grows an expiry queue. Publication, uncertainty and retirement
are fenced by ledger/owner generation. Preserve ownership until native
withdrawal is verified, including after all logical references expire.

## Consequences

All backends share one ledger per supervised session. Expired question keys
can be reclaimed while flows retain their address/backend. Pending output
survives TTL/deadline expiry until its actual I/O owner is destroyed or hands
off successfully. Closing admission and draining metadata never declares
native cleanup complete. A byte budget can admit fewer leases than its count
limit; protected ownership is never evicted to accept another name/backend.

The ledger performs metadata work only. Its publication/retirement methods
require externally proven native results; they neither perform OS operations
nor authorize replay after uncertainty. Service integration must preserve
that ordering and account separately for transient discovery/output buffers.

## Validation and reconsideration

Run `cargo test --locked -p warper-core --lib dns::lease`, then
`scripts/check.sh`. The explicit release workload is documented in
[development](../development.md). Raw evidence is under
`target/evidence/phase-2/lease-ledger/`: controlled-clock lifetime/failure tests,
default-capacity admission, one-IP count/byte exhaustion, collision/churn tests,
foreign-handle regression, coverage and repeated-renewal measurements.

This accepts storage and lifecycle policy, not NET-10/NET-12 native acceptance.
Reconsider if native/output composition needs different completion semantics,
allocator/platform layouts invalidate accounting, cache storage is introduced,
or controlled workloads show unacceptable scan/lookup latency.
