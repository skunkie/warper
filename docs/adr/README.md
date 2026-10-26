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
| [0002](0002-network-stack.md) | Proposed | Select adapters for host interception and active WireGuard dialing after executable probes |
| [0003](0003-dns-endpoint-routing.md) | Accepted policy; implementation pending | Separate DNS freshness from route grace and gate HTTPS/SVCB endpoint publication |
| [0004](0004-desktop-service.md) | Accepted direction; native implementation evidence pending | Tauri desktop, independent networking service, and a managed macOS app bundle |
| [0005](0005-macos-development-authentication.md) | Accepted policy; UX-05 evidence pending | Administrator-enrolled exact build identities for macOS local use without paid signing |

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
