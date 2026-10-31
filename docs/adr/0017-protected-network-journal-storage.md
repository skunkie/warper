<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0017. Protected bounded network journal storage

- Status: accepted local storage boundary; native root and driver integration pending.
- Date: 2026-10-31
- Related: ADR 0009, ADR 0015, Phase 1 native driver and recovery contracts.

## Context and alternatives

Accepted connection intent cannot describe the original, intended and committed
network objects needed for safe rollback. The platform needs a separate durable
record before mutation. An append-only event history would need compaction,
recovery and separate disk accounting. Reusing the connection snapshot would
couple command idempotency to native per-object progress. Arbitrary privileged
file APIs would expand the control boundary.

## Decision

Add fixed protected `network.journal`/`network.pending` storage under the same
root-owned state directory, reusing existing directory pins and runtime lease
validation. Keep its bounded versioned envelope independent of the platform's
payload schema. Payloads contain 1..65536 bytes of validated, secret-free native
metadata, never raw configuration or application data. No public path, UID or
file-descriptor override exists. Storage success is not OS ownership or a
kernel acknowledgement, and no RPC request can write arbitrary payloads.

Use one revisioned snapshot and exclusive staging. Sync the complete staged
file and directory, revalidate prior/pending identity and bytes, require exact
staged length, rename atomically and sync the directory before success.
Cache one bounded observed snapshot so deletion, replacement or in-place
changes fail closed instead of becoming revision zero. Reject exhausted
revisions and oversized payloads before creating staging.

Preserve staging on every post-create failure. Explicit inspected discard pins
and compares store/directory identity, previous committed content and staged
identity/timestamps/bytes before unlink/sync; it never promotes pending intent.
An abandoned/mismatched token preserves evidence. Post-rename or discard sync
uncertainty blocks normal operations until unchanged inspection/resync. No
rollback can infer that an uncertain operation never happened.

## Consequences

Protected storage remains in the Linux runtime boundary; the service platform
owns journal meaning, administrative RPC authorization and native recovery.
There are no new dependencies, detached tasks or automatic mutation retries.
Each store retains four directory descriptors and one bounded observed payload.
Tokens and calls retain bounded records/pins; fixed-size reads cannot grow with
concurrent file changes. The supervisor must admit bounded workers/tokens and
reserve serialization/readback memory and file descriptors before native work.
Filesystem calls are synchronous and cannot guarantee a hard kernel deadline;
retained blocking workers keep runtime ownership until joined.

## Validation and reconsideration

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p warper-control runtime::journal
CARGO_INCREMENTAL=0 cargo llvm-cov --locked -p warper-control --all-features --html
CARGO_INCREMENTAL=0 scripts/check.sh
```

Private real-file tests cover durable replacement/reopen, malformed/maximum
records, stale/exhausted revisions, changed/deleted prior snapshots, failed
staging, appended tails, commit/discard uncertainty, unchanged resync, partial
pending discard, changed tokens and unsafe file/runtime metadata. The appended
tail regression must fail with only its exact-length guard removed from an
ignored copy. Raw source/validation artifacts belong under
`target/evidence/phase-1/network-journal-storage/`.

The owner-dispatched root fixture now exercises the public store and explicit
partial recovery in private state. Fresh native execution remains required.
The platform payload schema, boot/namespace/instance ownership, mutation ACKs,
rollback/recovery application, service worker admission and the running daemon
remain open. Reconsider if required bounded metadata cannot fit or filesystem
failure evidence requires a different publication/recovery protocol.
