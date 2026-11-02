<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0023. Managed configuration generations and retained installation ownership

- Status: accepted scoped managed configuration boundary; daemon integration pending.
- Date: 2026-11-02
- Related contracts and acceptance criteria: [configuration](../configuration.md),
  [managed contracts](../implementation-contracts.md#initial-managed-socks5-snapshot),
  CFG-01, CFG-02, UX-01, UX-02 and UX-03.

## Context

The ordinary user supplies YAML and selected credential files. The service must
not read arbitrary client paths, depend on that user's home at boot, adopt edits
without authorization or replace material still used by networking/cleanup.
A generation must refer to immutable approved data with stable explicit defaults.
Client disappearance cannot revoke supervisor ownership. Corrupt, pending or
uncertain storage must remain visible without promoting a proposal.

The initial managed codec has controlled public API evidence. Fixed protected
managed storage has native evidence in owner-dispatched CI at `37ea223`; its
root/ordinary-peer tests do not establish the installation owner's lifetime gate.

## Alternatives

- Let the service reread a user YAML path: retains live file dependencies and
  permits privileged path forwarding; it cannot represent approved generations.
- Store editable YAML and credentials in separate mutable files: useful for
  manual inspection but requires a multi-file transaction and secret-reference
  consistency before claiming atomic approval. It remains a possible export
  format, not the initial committed representation.
- Store only a versioned opaque binary object: supports framing but loses the
  existing normalized YAML schema and duplicates its semantic validation.

## Decision

Retain YAML as the user-facing source. Native client import produces a bounded
WMCF version-one snapshot with deterministic normalized YAML, every explicit
root default and a separate bounded credential table. Service decoding is pure,
requires canonical path-free data and never opens selected user files. The
whole envelope is secret material; Debug, errors and observable state redact it.
Root permissions protect storage; this format does not add encryption at rest.

Use the fixed root-owned `/etc/warper` slot and WCFG generation envelope with
bounded atomic staging, observed revision/identity checks and explicit pending/
uncertain recovery. Preserve the existing network journal format and capacity
while sharing its persistence implementation. Never promote pending bytes.

One authoritative configuration manager per exclusive runtime owns installation.
It freshly authorizes an administrative Unix peer, refuses retained leases,
checks the generation, validates WMCF and pure service capabilities, and only
then mutates protected storage. Confirmed durability publishes the new cache.
The manager and every approved lease retain a single-owner runtime claim;
dropping and reopening the manager cannot bypass a still active lease.
Supervisor preparation through final network cleanup must retain that lease.

The initial codec admits at most 64 SOCKS5 backends. SSH/WireGuard imports remain
explicitly unsupported. Neither a valid snapshot, stored generation nor approved
lease establishes native-budget approval, OS readiness or a connected tunnel.
Control handlers, CLI import and GUI editing remain separate implementation.

## Consequences

- No secret or file path is returned in ordinary status. A future editor needs
  a redacted configuration view and deliberate credential preservation/update
  semantics; the native full snapshot accessor is not an observable RPC.
- Editing the original YAML does not change the approved service generation.
  The client validates and explicitly applies a new draft while disconnected.
- Encoding/default changes need a versioned migration. Initial managed files
  are internal artifacts, not files users must edit by hand.
- File waits have no hard cancellation guarantee. Native workers, immutable
  data and runtime claims remain retained after caller timeout or disconnect.
- Source, decode/cache copies, credential tables and storage readback have
  bounded owners but still require complete supervisor budget accounting.

## Validation and reconsideration

Reproduce local codec, storage and authorization tests with:

```sh
CARGO_INCREMENTAL=0 scripts/check.sh
CARGO_INCREMENTAL=0 cargo test --locked -p warper-config --test managed
CARGO_INCREMENTAL=0 cargo test --locked -p warper-control storage
CARGO_INCREMENTAL=0 cargo test --locked -p warper-control retained_configuration_ownership
CARGO_INCREMENTAL=0 cargo test --locked -p warper-service linux::configuration
```

The owner-dispatched privileged workflow must additionally pass the actual
installation API with root and controlled UID 1000, malformed/unsupported data
before storage, stale generations, Busy during retained/cloned leases, manager
reopen blocked until final lease drop, persistence and external-edit rejection.
Run only through `scripts/control_acceptance.py` on a disposable Linux VM with
its private mount/net/PID state, dedicated bus/resolver and independent cleanup.
The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41391328712)
passes at `5a62a65`, including those actual API/lifetime checks and independently
preserved host state. Evidence belongs under
`target/evidence/phase-1/configuration-ownership/` and
`target/evidence/phase-1/privileged-control-ci/run-41391328712/`.
Acceptance is scoped to this managed boundary. No macOS native installation,
running control handler or full service lifecycle is established.

Revisit this choice for additional backend imports, credential-reference editing,
format migration, native macOS authorization or changed memory/transaction
requirements. Required networking/lifecycle acceptance cannot be replaced by
these storage and API tests.
