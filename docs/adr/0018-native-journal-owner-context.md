<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0018. Native journal owner context

- Status: accepted native read-only evidence; public root integration pending.
- Date: 2026-10-31
- Related: ADR 0008, ADR 0009, ADR 0015, ADR 0017, Phase 1 native recovery.

## Context and alternatives

A persisted interface index or process number can be reused. Recovery needs a
boot/namespace/instance/process context, separately from object ownership marks.
Serialized IDs supplied by a client are not native authority. User namespaces
also change the meaning of UIDs, while PID namespaces change process numbers;
network namespace identity alone cannot safely attribute process liveness.

Trusting only names/PIDs would lose those boundaries. Opening arbitrary namespace
paths or accepting inherited descriptors would let callers redirect evidence.
Using local unsafe namespace ioctls is unnecessary for fixed guarded procfs links.

## Decision

Capture native boot evidence and service instance from the real connection
store while retaining the verified runtime lease. Anchor real procfs, open
fixed current-thread network/PID namespace links without overmount/magic-link
traversal, inspect their bounded labels, follow their checked fixed names into
nsfs and compare type/inode/label. Retain both namespace descriptors so their
identities cannot disappear during the context's lifetime. Read at most 4096
current-process stat bytes and match its PID to the kernel process ID. Preserve
field-22 start ticks, including zero, without logging the process name.

Store a fixed version-one 88-byte `WNOC` owner component. Decode is separate from
native capture and cannot construct native capabilities. Reject malformed,
zero or conflicting identities. Classify foreign boot/namespace, previous
instance, conflicting process and current captured owner separately. Only
inspection follows from classification; recovery still requires process
liveness, full native object identity/marks and the durable transaction record.
Revalidate the current thread's scopes/process/boot before driver operations.
Keep native resources ahead of the lease in field destruction order.

## Consequences

The Linux service now depends normally on the existing control runtime boundary;
core and shared logical control remain independent of backend/stack types.
Native boot bytes can be serialized into protected metadata without introducing
a public constructor for trusted BootId. There is no identity/path/descriptor
override, new third-party version, background task or namespace mutation in the
production adapter. Debug/errors redact native values. Procfs work uses bounded
synchronous reads in retained native workers. Context retains two namespace
handles and a reference to the existing four-descriptor runtime lease, plus
bounded temporary descriptors and fixed 4097/64-byte read buffers.

## Validation and reconsideration

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p warper-service linux::context
CARGO_INCREMENTAL=0 scripts/check.sh
```

Local native read-only scope inspection and synthetic parsers/owner records pass.
Tests cover spaces/parentheses/non-ASCII process names, exact serialization,
zero start ticks, bounds, namespace labels and every owner classification.
The isolated root TUN fixture now verifies public capture, a fresh service
instance fence, retained flock and a joined thread that unshares only its own
network namespace and must fail revalidation. Parent context and independent
cleanup must remain valid. Fresh public root execution remains pending.
Retain artifacts under `target/evidence/phase-1/native-journal-context/`.

This establishes an owner component, not a complete platform journal, physical
path or mutation driver. Reconsider for required recovery across PID/network
namespaces, unsupported procfs/stat layouts or a changed kernel namespace ABI.
