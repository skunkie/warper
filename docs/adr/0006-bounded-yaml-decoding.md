<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0006. Bounded YAML decoding

- Status: accepted for the decoder boundary; schema validation pending.
- Date: 2026-10-30
- Related: [configuration contract](../configuration.md#decoder-boundary),
  [Phase 1](../implementation-plan.md#phase-1-workspace-contracts-and-headless-linux-slice).

## Context

The configuration contract rejects duplicate keys, aliases, anchors, custom
tags, nulls, multiple documents, and scalar coercion. A loader that silently
overwrites duplicate keys or expands aliases loses evidence needed to enforce
that contract. Source excerpts and decoded secrets must not enter diagnostics.
Offline input needs fixed admission bounds before trusting configuration limits.

## Alternatives

- Generic map loaders must prove duplicate/alias handling, bounded construction,
  and scanner-error redaction before their results can be trusted.
- Direct schema deserialization requires auditing those properties together
  with scalar coercion and field errors across both layers.
- A new YAML syntax parser would add unnecessary maintenance. Use an established
  parser for syntax instead.

## Decision

Use released **yaml-rust2 0.11.1**, defaults disabled, behind
[`warper-config::yaml`](../../crates/warper-config/src/yaml.rs). Consume pull
events rather than the generic loader. Input is already UTF-8; encoding
discovery is unnecessary. The dependency is MIT OR Apache-2.0. Its locked
arraydeque/hashlink/hashbrown/foldhash dependencies introduce no changes to
existing dependency versions or selections.

Permit Zlib only for the exact transitive **foldhash 0.2.0** package in
`deny.toml`. Its upstream LICENSE requires preserving the notice in source
distributions, marking altered source, and not misrepresenting origin. Retain
that actual notice when distributing dependency sources; do not relabel it MIT.
This allowance covers neither other packages nor future foldhash versions.
Revisit/remove it when yaml-rust2/hashlink changes the dependency or its license;
advisory, ban, and source checks remain enabled.

Reject source above 1 MiB before UTF-8 validation or parser construction. Count
keys and values against 65,536 nodes and stop recursion beyond depth 16. Reject
anchors before retaining values; never expand aliases or merge keys. Compare
string keys after decoding escapes before accepting a second value. Preserve
sequence order; mapping order has no semantic meaning.

Apply the [YAML 1.2.2 core scalar rules](https://yaml.org/spec/1.2.2/#1032-tag-resolution)
in the adapter. Preserve numeric spelling for later range checks, including
overflowing integers. Supported explicit tags must match their content/kind;
non-specific `!` disables scalar resolution. Nulls and custom/unsupported tags
fail. Consume one leading UTF-8 byte-order mark after source admission without
altering string contents.

Return adapter-owned values and typed errors. Third-party types and scanner
errors do not cross this boundary. Diagnostics contain static reasons and
bounded paths from schema vocabulary/indices; unknown key names are redacted.
Value Debug output is always redacted, including nested values.

## Consequences

The synchronous decoder owns its tree and releases partial allocations on
failure. It creates no tasks, reads no files/environment, and mutates no host
state. Source/node/depth bounds constrain construction but are not an RSS cap
or hard deadline. Future asynchronous clients must schedule decoding away from
networking executors.

A decoded tree is not a validated configuration. Required/unknown fields,
schema types, semantic ranges, IDNA, capabilities, paths, and CLI integration
remain subsequent work. No networking code may treat decoding as authorization.

## Validation and reconsideration

```sh
cargo test --locked -p warper-config
scripts/check.sh
cargo llvm-cov --locked -p warper-config --all-features --html
```

Decoder tests register canonical/original inputs and the migration fixtures.
Most migration fixtures are valid YAML; only duplicate-key is a decoder-level
rejection. Schema/migration/capability expectations remain unverified. Unit
cases cover tags, malformed input, scalar types/spelling, redaction, duplicate
paths, and admission boundaries. Raw evidence belongs under
`target/evidence/phase-1/yaml-decoder/`.

Native macOS compilation has not run locally. No native/privileged networking
gate changes. Reconsider for parser advisories, incorrect scalar/escape
handling, bound violations, or an incompatible required schema change.
