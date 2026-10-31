<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0020. Journaled initial Linux IPv4 address

- Status: accepted scoped address transaction; full driver integration pending.
- Date: 2026-10-31
- Related: ADR 0019, NET-01 and NET-05.

## Context and alternatives

The initial TUN owner has privileged allocation and rollback evidence, but no
address transaction. The convenience address setter can remove an existing
address and create a connected-prefix route. A fresh owned descriptor does not
justify those broader operations. The asynchronous read-only netlink guard
intentionally cannot send mutations.

## Decision

Add a private synchronous netlink address adapter for retained native workers.
Use the existing pinned safe packet/socket libraries and global checked request
sequence. Bound socket queues, request/reply sizes, dump counts, deadlines and
cancellation checks. Observe namespace IPv4 addresses without retaining them;
reject any matching address before journaling intent. Persist Addressing before
one exclusive RTM_NEWADDR for the owned index with local/peer equal to the /32
address and IFA_F_NOPREFIXROUTE. Do not raise the interface.

Require a kernel unicast ACK matching request sequence, port and original
header. Distinguish not-sent, explicitly rejected and uncertain delivery. Never
resend after successful send. Verify exact owned address attributes in a fresh
bounded dump before committing Addressed. Repetition only verifies readback;
address changes remain unsupported. Rollback closes the originally owned TUN
and verifies retirement, preserving primary and cleanup errors.

WTUN version two retains the 160-byte envelope, storing IPv4 at bytes 136..140
and reserving 140..160. Preserve decoding of version-one records; only Retired
allows fresh preparation. Malformed versions/states/addresses require recovery.

## Consequences and limits

No new dependency, local unsafe code, automatic replacement, address-number
cleanup or application payload replay is introduced. Kernel snapshots are
observations; privileged external network managers can race them. Full monitor
integration, UP, route/exemption transactions, process-liveness recovery and
service supervision remain separate gates. Kernel filesystem waits have no
hard deadline; the supervisor must retain/join work after caller detach.

## Evidence and reproduction

Run `CARGO_INCREMENTAL=0 cargo test --locked -p warper-service linux::tun` and
`scripts/check.sh`. Parser tests reject malformed ACKs and inconsistent records;
a real read-only address dump requires no privileged mutation. Actual address
assignment, repeat verification, foreign-address preservation, no prefix route
and descriptor rollback run only in the owner-dispatched disposable Linux CI
fixture (`linux_network_probe` through `scripts/control_acceptance.py`).
The owner-dispatched [native CI run](https://github.com/skunkie/warper/actions/runs/41233000400)
at `51ddb3b` passes those address checks with exit code zero, no timeout and
independently preserved host state. This does not verify UP, capture routing or
complete service acceptance. Evidence is stored under `target/evidence/phase-1/journaled-ipv4-address/` and CI artifacts.
