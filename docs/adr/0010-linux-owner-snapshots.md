<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0010. Revisioned Linux owner snapshots

- Status: accepted storage boundary; privileged service integration pending.
- Date: 2026-10-31
- Related: [runtime ownership](0009-linux-runtime-ownership.md), UX-01, UX-03.

## Context

Owner enrollment must survive reboot without trusting user YAML, home paths or
request identity fields. A partial or malformed protected record must not
silently reopen bootstrap access. Concurrent/stale requests need explicit
revision preconditions, and a failed durability acknowledgement must not undo
an update that could already be committed.

## Alternatives

- Owner fields in imported configuration confuse parsing with administrative
  authorization and permit untrusted privileged file selection.
- In-place writes can expose partial snapshots to restart/readers.
- Deleting malformed or pending records silently discards uncertain intent.
- Returning success after rename without syncing the directory ignores the
  filesystem durability boundary. Blind rollback after a failed sync is unsafe.

## Decision

Use fixed protected `/var/lib/warper/owner` under the held runtime lease, with
initial-user-namespace UID-0 admission, pinned protected ancestors and a
mode-0700 state directory. Installation provisions directories. OwnerStore has
no public path or descriptor constructor. Use the exact versioned 24-byte
record specified in [configuration](../configuration.md#linux-owner-enrollment-storage).
Reads inspect regular-file metadata before I/O and bound admitted bytes to 25.
Missing means revision zero; malformed, unsafe and pending state fail closed.

Administrative updates verify a live native root peer before record reads.
Check expected revision and validate the proposed UID. Exclusively stage
`owner.pending`, write/sync it and its directory, revalidate current state and
revision, atomically rename, and sync the directory before acknowledgement.
The global pending name serializes publication under the runtime lease.
State remains immutable between replacements. No source path is accepted.

Preserve primary and cleanup errors before publication, removing only unchanged
owned pending state. After rename, a directory-sync error is CommitUncertain;
never roll back or replay. Inspection of the current revision permits later
reconciliation. Existing pending state requires explicit administrative
recovery; this increment does not automatically clean it. See
[fsync](https://man7.org/linux/man-pages/man2/fsync.2.html).

## Consequences

Owner removal advances revision and preserves root administration. Callers must
refresh policy per request and revoke existing observers when enrollment
changes; a cached connection role cannot authorize a later request.

The adapter retains four directory descriptors plus bounded temporary file
handles, a 24-byte encoded snapshot and at most 25 admitted read bytes (plus
container/library overhead). It has no tasks, retries, payload logging or
networking changes. Filesystem waits are synchronous without a hard deadline.
Root and a stable launch mount namespace remain trusted. It is not a managed
configuration/credential store or a complete network recovery journal.

## Validation and reconsideration

`cargo test --locked -p warper-control` uses private current-UID fixtures for
real staging/sync/rename/reopen, revision conflicts/exhaustion, removal,
malformed/unsafe/pending state, changed-object preservation, native denial
before reads and exact record encoding. A final-sync fault is injected after
actual rename and proves that the new snapshot remains visible while reporting
uncertain durability. Tests also cover owned and replaced pending cleanup.

Full checks and changed-code coverage are recorded under
`target/evidence/phase-1/owner-enrollment/`. Positive public root construction
and enrollment, pending administrative recovery, live revocation and integrated
service acceptance remain open. No live `/var/lib` or `/run` state is changed.
Reconsider for multi-process writers, a new schema version or enrollment/config
transactions requiring a shared journal.
