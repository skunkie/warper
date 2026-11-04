<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0027. Authorize DNS output before I/O and finalize observed delivery

- Status: accepted
- Date: 2026-11-04
- Related contracts and acceptance criteria:
  [DNS output authorization](../implementation-contracts.md#dns-output-authorization-and-delayed-completion),
  [bounded lease ownership](0026-bounded-dns-lease-ledger.md), NET-03, NET-10
  and NET-12.

## Context

A deadline can pass between the final successful write and metadata completion.
Rejecting handoff at that later observation would discard the pending reference
without giving an already-delivered zero-TTL answer its connection grace.
Pending output must also remain protected during partial writes and cancellation.
The ledger has bounded pending slots and shared address owners, but performs no
I/O and cannot infer whether bytes reached an output transport.

Controlled one-byte duplex I/O with real DNS framing and a paused clock proves
the completion-observation gap. Separate metadata tests prove that closing
admission or invalidating publication must not erase retention for output
already authorized and delivered. These tests do not establish native DNS
listener or kernel route-ACK/output acceptance.

## Alternatives

- Reject completion after the request deadline. This loses grace after a
  successful write whose metadata processing was delayed.
- Start grace before writing. This can consume grace during blocked output
  and creates retention for failed/incomplete messages.
- Extend the I/O deadline. This changes the request's bounded lifetime and
  does not resolve cancellation or completion-observation ordering.
- Authorize before I/O, then finalize successful delivery using the same
  pending reference, without reapplying the I/O deadline.

## Decision

Use the final alternative. Mint an opaque non-cloneable output handle only
after validating the original deadline, open admission and all committed
routes. Retain its pending ownership until failed I/O is destroyed or successful
delivery is finalized. Successful completion exchanges pending ownership for
grace measured from its observation, retaining any longer existing expiry.
No allocation, pending slot or timer is added by the conversion.

Already-authorized output can finalize after admission closes or publication
becomes uncertain; neither event can undo bytes already delivered. Completion
does not reopen admission or declare native publication ready. The caller must
report actual successful complete-message I/O; this handle is not a kernel
receipt. Synchronous metadata handoff remains available for an atomic
authorization/retention transition at one clock observation.

## Consequences

The service writer must retain/join its I/O owner and preserve output ownership
during metadata contention or completion errors. A caller deadline must not
turn delivered output into undelivered cancellation. Partial/cancelled I/O is
destroyed before its guard drops and creates no grace. Explicit session shutdown
can still drain timed leases after all output/flow owners are destroyed.

The pending byte budget reserves the larger response/output handle layout.
Original DNS freshness and wire TTL are unchanged by retention. TTL aging,
global transient-buffer admission and native listener/route/output integration
remain required; this decision does not close their acceptance gates.

## Validation and reconsideration

Run:

```sh
cargo test --locked -p warper-core --lib dns::lease::output_tests
cargo test --locked -p warper-service --lib dns::routes::output_tests
scripts/check.sh
```

Evidence belongs under `target/evidence/phase-2/output-completion/`: late
completion, rejected authorization, uncertainty/closure, foreign-handle/time
errors, partial frame cancellation, unchanged zero TTL, first-flow protection,
coverage, and the explicit metadata renewal workload. No privileged native
mutation is needed for these controlled tests. NET-10 still needs actual
native route ACK and output composition. Reconsider if a transport can report
failure after handing a complete message to the kernel, or if a writer cannot
retain completion ownership through its supervisor's shutdown protocol.
