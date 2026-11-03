<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0015. Durable connection intent and revision-bound operation IDs

- Status: accepted persistence boundary with native root evidence; daemon integration pending.
- Date: 2026-10-31
- Related: ADR 0004, ADR 0009, contract section 6, configuration storage contract.

## Context and alternatives

Client timeouts do not cancel accepted operations. Connect/Disconnect must
survive client detach and same-boot service crashes, while observed network
readiness remains separate. A bounded result history cannot remember every
opaque UUID forever. Accepting an unknown old ID with refreshed revision fields
could otherwise turn an old Connect into new intent after Disconnect.

Keeping all operation IDs forever is unbounded. Permanently refusing commands
when the history fills would cap service lifetime. Trusting clients to preserve
old fields does not protect against accidental refresh/retry behavior. Raw
source YAML and credentials do not belong in the intent record or its errors.

## Decision

Persist accepted intent in fixed protected `connection` snapshots alongside
owner state, reusing private protected-directory pins. Require the retained
runtime lease and an independently supplied approved configuration generation.
The root dispatcher still authorizes every request; this is persistence, not an
RPC authorization bypass. No path, boot identity or instance override exists in
the public store API.

The 16-byte operation ID is the big-endian expected desired revision followed
by a fresh nonzero eight-byte nonce. Retry preserves all fields. The codec and
store independently validate the binding. Accepted state increments that
revision exactly once. This makes an old identity incompatible with refreshed
revision fields even after history eviction. A restart changes the native
service instance fence; persistent desired revisions never reset at restart.
Only the last acceptance is required for on-disk repeat suppression. Bounded
operation-result retention remains a separate service responsibility.

Use an exact versioned 80-byte record, with native boot ID, accepting instance,
operation, desired revision, configuration generation and up/down state.
Exclusive pending creation, file/directory sync, prior snapshot revalidation,
atomic rename and final directory sync precede Accepted. Exact last-operation
repeats return AlreadyAccepted without rewriting. Observed file replacement,
mutation or deletion fails closed. An uncertain commit blocks further
acceptance until explicit unchanged inspection/resync; it does not authorize
network work or blind replay.

Root pending inspection/discard pins bounded current/staged state, compares
identity/timestamps/bytes and consumes an opaque in-process token. It never
promotes staged intent. Abandonment/mismatch preserves state. Unlink durability
uncertainty also blocks acceptance until resync. Filesystem operations remain
synchronous and require retained service worker ownership and serialization.

## Evidence and limits

Current-UID private filesystem tests exercise durable writes/reopen, repeat
suppression, generation/instance/revision conflicts, refreshed stale IDs,
exhaustion, deleted/replaced/changed state, pre-publication rollback, primary
and cleanup failure preservation, post-rename/post-unlink uncertainty and
empty/partial/complete pending discard. The replay regression must fail with
only the store's revision-binding guard removed from an ignored copy.
Native procfs boot stability and nonblocking instance entropy have local
evidence; injected malformed/short/zero/error inputs fail closed.

```sh
cargo test --locked -p warper-control
cargo llvm-cov --locked -p warper-control --all-features --html
scripts/check.sh
```

The owner-dispatched root fixture exercises public connection persistence,
restart fencing and partial pending discard in private state. Retain raw logs
and coverage review under
`target/evidence/phase-1/connection-intent/`. No new third-party dependency is
introduced by this boundary.

This is neither an OS recovery journal nor a connected service. Authenticated
handlers, approved managed material, boot/autoconnect policy, bounded result
history, late completion fencing and journaled native application remain open.
No application bytes are stored or replayed by intent persistence.

The [owner-dispatched root gate](https://github.com/skunkie/warper/actions/runs/41196275017)
passes at `ed834b5`: public root persistence, exact repeat suppression, reopened
same-boot intent with a changed instance fence, explicit resync and partial
pending discard. Existing owner/foreign-peer and actual kernel TUN gates also
pass with independently preserved host state. Raw artifacts are retained under
`target/evidence/phase-1/privileged-control-ci/run-41196275017/`. This closes the
native persistence boundary, not authenticated daemon lifecycle acceptance.
