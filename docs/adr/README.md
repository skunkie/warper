<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Architecture Decision Records

Use ADRs for decisions with architectural, compatibility, operational, or
dependency-maintenance consequences. Routine implementation details do not
need their own record.

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-development-workflow.md) | Accepted | Stage-aware checks, contract-first implementation, licensing, and reproducible gates |
| [0002](0002-network-stack.md) | Accepted for Linux; native macOS pending | Direct smoltcp role adapters with BoringTun, bounded ownership, and explicit MTU limits |
| [0003](0003-dns-endpoint-routing.md) | Accepted policy; implementation pending | Separate DNS freshness from route grace and gate HTTPS/SVCB endpoint publication |
| [0004](0004-desktop-service.md) | Accepted direction; native implementation evidence pending | Tauri desktop, independent networking service, and a managed macOS app bundle |
| [0005](0005-macos-development-authentication.md) | Accepted policy; UX-05 evidence pending | Administrator-enrolled exact build identities for macOS local use without paid signing |
| [0006](0006-bounded-yaml-decoding.md) | Accepted; offline schema integration implemented | Bounded pull-event YAML decoding with redacted errors and explicit core scalar types |
| [0007](0007-linux-control-peer-identity.md) | Accepted boundary; service integration pending | Linux kernel UID snapshots and owner/root policy, with namespace and protected-endpoint gates |
| [0008](0008-initial-user-namespace.md) | Accepted for Linux admission | Guarded procfs namespace identity is mandatory before peer credentials; noninitial namespaces fail closed |
| [0009](0009-linux-runtime-ownership.md) | Accepted ownership boundary; service integration pending | Fixed protected Linux runtime directory and persistent nonblocking instance lease |
| [0010](0010-linux-owner-snapshots.md) | Accepted storage boundary; privileged integration pending | Fixed protected atomic owner snapshots with revision checks and uncertain-commit reporting |

Copy [the template](template.md) to the next unused four-digit number with a
short descriptive filename. Use `proposed`, `accepted`, `rejected`, or
`superseded` status, date, context, considered alternatives, decision,
consequences, and validation/reconsideration conditions. Link relevant
contracts and acceptance IDs. Never represent a planned experiment as a
completed evaluation.

Accept an evidence-dependent decision only when its required gate has
passed. Store raw per-run output outside tracked documentation; put exact
reproduction commands and meaningful limits of the evidence in the ADR.
When changing an accepted decision, update it explicitly or supersede it
with a new record and reciprocal links. Update affected contracts, code,
tests, and the phase ledger together.
