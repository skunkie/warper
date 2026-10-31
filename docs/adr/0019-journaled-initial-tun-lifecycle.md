<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0019. Journaled initial Linux TUN lifecycle

- Status: accepted scoped native lifecycle; full driver integration pending.
- Date: 2026-10-31
- Related: ADR 0014, ADR 0017, ADR 0018, NET-01 and NET-05.

## Context and alternatives

The safe TUN API has actual kernel traffic and collision evidence, and native
owner context/storage have privileged evidence. The production native boundary
still needs durable intent, committed ownership, explicit rollback and resource
ordering. Adopting a configured interface name could touch foreign state.
Inferring cleanup authority from a persisted name/index would permit reuse bugs.

## Decision

Introduce a synchronous owner for retained native workers. Validate native
context, name/MTU and the fixed protected TUN character device before durable
preparation. Always create an unnamed, down, nonpersistent 1280-byte TUN, with
plain packet framing and offload disabled. Never attach a named device. Verify
descriptor-derived identity/MTU and commit ownership before success. Persist
rename intent before a requested atomic kernel rename and commit the verified
result; report explicit OS-selected/already-applied outcomes for unchanged names.

Use a version-one 160-byte WTUN payload within protected network storage. It
contains the owner component, lifecycle stage, requested/actual name and kernel
index. Stages are Prepared, Allocated, Renaming, Named, Retiring and Retired.
Active/unknown/pending/uncertain prior state blocks fresh preparation. Only
validated Retired state permits reuse of the journal slot.

Rollback closes the freshly created descriptor and verifies kernel index absence
before committing Retired. It never deletes a stored name/index. The original
durable intent also permits compensating closure of an owned temporary after a
later storage failure; report that failure and any cleanup/inspection failures.
Unexpected surviving indices remain recovery failures. Drop releases the owned
descriptor before context/runtime ownership but leaves conservative journal
state. No drop hook reports cleanup success or performs asynchronous I/O.

## Consequences and limits

`tun-rs` moves from development-only to normal Linux dependency without changing
its exact version/features or other lockfile versions. Upstream filesystem repair
must remain unreachable through preflight: require protected real directories
and a root-owned single-link character device 10:200 before the constructor.
No local unsafe code, background thread, arbitrary descriptor adoption, UP flag,
address, route, DNS setting or packet task is introduced. Synchronous filesystem
and native calls belong to retained/joined workers; no hard kernel filesystem
deadline is promised. The supervisor retains operation ownership across client
detach and preserves initial application errors alongside rollback failures.

This payload covers TUN lifecycle only. Full platform transaction encoding,
process-liveness recovery, interface marks, addresses/routes/exemptions, packet
I/O, service supervision and daemon/control readiness remain open. A successful
allocation does not establish a usable capture path. Unknown or surviving
objects are preserved for recovery; no generic automatic deletion exists.

## Validation and acceptance

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p warper-service linux::tun
CARGO_INCREMENTAL=0 scripts/check.sh
```

Bounded codec tests cover all reachable stages, malformed envelopes, names and
indices. Local strict checks compile the real native paths; privileged execution
is unavailable locally. The existing isolated owner-dispatched fixture now
performs actual journaled allocation, introduces a foreign name after allocation,
checks atomic rename conflict and rollback, verifies unchanged foreign identity,
exercises naming/close idempotency and OS-selected names, and confirms drop leaves
a conservative recovery gate. It also measures 20 serial prepare/allocate/close
cycles with latency distributions, CPU and peak RSS. There are no application
bytes or packet traffic in that lifecycle workload; packet drops/response bytes
are not measured. It is a startup/cleanup baseline, not tunnel throughput.

The [owner-dispatched gate](https://github.com/skunkie/warper/actions/runs/41220497788)
passes at `3b17c4a` with preserved host state, including raced rollback, explicit
storage-failure recovery, conservative drop and lifecycle workload. This accepts
the scoped lifecycle only. Retain source, checks, coverage and downloaded evidence under
`target/evidence/phase-1/journaled-tun/`. Reconsider for required persistence,
external surviving state, unsafe upstream node handling or a broader MTU/profile.
