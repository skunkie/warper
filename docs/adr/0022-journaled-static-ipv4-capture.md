<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0022. Journaled static IPv4 capture batches

- Status: accepted scoped static IPv4 capture lifecycle; service integration pending.
- Date: 2026-11-01
- Related: ADR 0016, ADR 0019, NET-01, NET-05 and Phase 1.

## Context and alternatives

The initial headless slice needs real selective capture routes associated with
its immutable host policy and original nonpersistent TUN. Fixture `ip` commands
cannot serve as the production driver. Replacing arbitrary existing routes,
using an unverified journal record as authority, or dropping active flow owners
on partial failure would violate lifecycle and host-preservation contracts.
A general policy-routing manager would expand this initial IPv4 slice before
its ordinary route lifecycle has executable evidence.

## Decision

Extend the retained TUN owner with exclusive main-table static capture batches,
using the bounded released-library netlink transport. Require a real allocated
host publication and an issued packet port; the supervisor must start and retain
the actual tasks before publication. Admit 1..4096 canonical IPv4 prefixes and
only the ordinary local/main/default IPv4 rule layout. Refuse overlapping local
routes and equally/more specific foreign capture conflicts before mutation.

Journal the complete batch before the first add. Each route uses the original
TUN index, static protocol, link scope, unicast type and an instance-derived
high-bit metric. Use CREATE|EXCL and correlated kernel ACKs without replay.
After the batch, create a fresh change subscription, inspect all routes/rules
and the exact UP/address/device identity, check notifications, commit ownership
and check again. Retain the monitor for supervisor invalidation. Expected own
notifications do not excuse lost or unsupported subsequent observations.

WTUN v4 stores the batch in at most 32928 bytes; its prefix records are eight
bytes each, strictly ordered, unique and canonical. Older records remain
readable but never authorize adopting an active/reused native object. The
runtime observation, journal and original descriptor survive uncertain or
partial mutation. Failed operations remain sticky rather than retrying adds.

Withdrawal requires quiescence and zero retained flows; the supervisor owns
additional packet/grace draining. Record retirement intent, inspect each full
prefix/metric key before exact deletion, require ACKs and final absence, then
clear capture ownership. Preserve changed keys and expose the conflict. Missing
keys allow repeated cleanup. Refuse explicit device close while capture is
attached. Closing the original nonpersistent descriptor on drop/crash remains
kernel-owned compensation, with dirty journal recovery still required.

## Consequences

This is a static IPv4 driver boundary, not a daemon or an atomic kernel routing
transaction. Custom rules, local-prefix conflicts and unsupported state fail
explicitly. No route replacement, alternate backend or direct fallback occurs.
The caller must retain/join native workers and supervise capture changes;
publication observations alone do not prove task scheduling or network readiness.

Inventory retains at most 8192 entries; conflict verification uses at most 4096
additional one-byte counters. Prefix plans, journal snapshots/serialization,
monitor memory and at most 64 KiB per kernel socket require separate native
budget admission. Each operation shares one at-most-30-second absolute deadline
and cancellation owner. The implementation creates no background workers or
unbounded event history. Large-batch latency, partial/uncertain ACK injection,
crash reconciliation and full flow/packet shutdown acceptance remain open.

## Validation and reconsideration

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p warper-service --lib linux::tun
CARGO_INCREMENTAL=0 cargo llvm-cov --locked -p warper-service --all-features --html
CARGO_INCREMENTAL=0 scripts/check.sh
gh workflow run ci.yml --ref codex/phase-1-linux
```

Local tests cover bounded/legacy journal decoding, nested owned prefix handling,
foreign conflict fields, duplicate/incomplete readback and request metadata.
The isolated native fixture measures twenty serial lifecycles, each publishing
three prefixes including nested routes. It checks repeated publication and the quiescence fence, preserves a changed route
key and joins withdrawal before dropping the real runtime. It uses the existing
independent host-preservation harness. The [owner-dispatched gate](https://github.com/skunkie/warper/actions/runs/41344128654)
passes at `2c6a268`, including all twenty lifecycles and independently preserved
host state. Artifacts are retained under
`target/evidence/phase-1/privileged-control-ci/run-41344128654/`.
This accepts only that scoped lifecycle, not crash recovery or a running service.
Raw evidence belongs under `target/evidence/phase-1/journaled-capture/`.
Reconsider when custom rules, host conflict semantics or native budget/latency
requirements exceed this deliberately narrow boundary.

The subsequent application fixture uses the same production owner for its real
TCP /32 capture route. It tests quiescence/retirement fencing with a retained
accepted stream, completes duplex data/FIN, supervises capture changes and joins
withdrawal while the runtime mapping remains published. Its controlled output
quiet interval is not a general service drain or DNS grace guarantee. Fresh
native execution remains required before accepting that traffic integration.
