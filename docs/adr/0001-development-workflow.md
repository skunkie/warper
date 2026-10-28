<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0001. Contract-first implementation with stage-aware validation

- Status: accepted
- Date: 2026-10-26
- Related: [implementation plan](../implementation-plan.md),
  [development checks](../development.md), and
  [acceptance criteria](../acceptance.md).

## Context

The repository starts with design and schema examples. Its hardest choices
are stack capabilities, DNS/routing publication, and crash recovery.
Creating placeholder crates to turn a generic Rust workflow green would
hide whether those capabilities exist. Workflow and licensing errors still
need executable checks before a Cargo project is introduced.

## Alternatives

- Immediately scaffold every production crate and defer behavior checks.
  This adds structure without proving the networking assumptions.
- Keep all checks manual until production code exists. This leaves the
  workflow and handoff rules untested during the earliest changes.
- Validate infrastructure now and enable real Rust checks through a tested
  repository-stage detector when the workspace exists.

## Decision

Use the stage-aware approach. `AGENTS.md` defines repository conventions;
the configuration and lifecycle contracts precede their implementations.
ADRs record material choices and executable evidence closes phase gates.

Infrastructure CI runs REUSE, actionlint with ShellCheck, composite-action
lint and harness tests immediately. Stage detection rejects orphaned Rust
sources, missing lockfiles, and floating/malformed toolchain configuration.
Once a root workspace exists, CI adds strict Clippy/rustdoc, formatting,
dependency policy, default/all-feature tests, native release builds, and CLI
entry-point checks when applicable. Rust versions and external tools are
pinned, actions use full SHAs, and permissions remain read-only.

Use MIT for the project and SPDX/REUSE metadata for files. Credit Aleksandr
Khamis for the original WARP idea and retain that author's notice in the
project license. New project and development-file copyright uses skunkie.

The duplicate-version policy skips only the exact versions listed in
`deny.toml`. The wrapper comparison retains smoltcp 0.12 alongside 0.14,
and their dependencies retain heapless 0.8 alongside 0.9. Bitflags 1 is
used by the stack candidates alongside bitflags 2 in Linux socket tooling.
Syn 1 and 2 remain in procedural macro dependency chains alongside syn 3:
the former through Linux WireGuard peer tooling, the latter through BoringTun
and the wrapper. Windows-sys 0.52 remains in BoringTun and rustix dependency
metadata alongside 0.61 from Tokio's networking support; Windows is not a
supported target. These exceptions do not exclude whole dependency trees or
change advisory, license, or source checks. Reconsider each exception when its
dependency chain or the stack comparison changes, and remove it when no longer
needed.

## Consequences

- Planning-stage Cargo jobs are explicitly not run, without fake packages.
- Missing validation tools and incomplete Rust prerequisites fail clearly.
- Linux/macOS native tests remain distinct from privileged networking gates.
- No release publishing is added until a runnable artifact exists.
- Raw evidence stays in ignored `target/evidence/` or CI artifacts; durable
  decisions, reproduction instructions, and gate status stay in documents.
- Feature combinations and native targets gain checks when introduced;
  all-features and compilation alone do not establish runtime coverage.

## Validation and reconsideration

Run `scripts/check.sh` from a clean checkout with the tools documented in
the development guide. Stage-detector tests create disposable Git fixtures;
composite-action tests run the actual configured linter and check source
positions and exit statuses. Native jobs run when a workspace exists.

Revisit when a required tool changes behavior, a new feature/target needs a
different validation boundary, or actual networking acceptance can safely be
automated on a dedicated runner. Do not waive failed gates through silent
fallbacks.
