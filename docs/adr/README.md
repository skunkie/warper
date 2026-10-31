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
| [0011](0011-production-socks5-tcp.md) | Accepted protocol boundary; service integration pending | Production core TCP setup and bounded SOCKS5 CONNECT over protected connector injection |
| [0012](0012-production-host-tcp.md) | Accepted scoped TCP boundary | Bounded host TCP adapter with retained runtime ownership |
| [0013](0013-service-tcp-relays.md) | Accepted relay boundary | Retained service TCP setup and relay tasks |
| [0014](0014-linux-tun-api.md) | Accepted scoped native API | Unnamed exclusive-lifetime TUN creation with collision preservation |
| [0015](0015-durable-connection-intent.md) | Accepted persistence boundary | Revision-bound durable connection intent with native root evidence |
| [0016](0016-bounded-linux-route-lookups.md) | Accepted read-only boundary | Bounded native IPv4 TCP observations without physical-path authority |
| [0017](0017-protected-network-journal-storage.md) | Accepted local storage boundary | Fixed bounded network snapshots with explicit pending/uncertain recovery |
| [0018](0018-native-journal-owner-context.md) | Accepted read-only evidence boundary | Pinned native boot, namespaces, instance and process-start context |
| [0019](0019-journaled-initial-tun-lifecycle.md) | Accepted scoped native lifecycle | Durable preparation, fresh descriptor ownership and verified TUN retirement |

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
| [0020](0020-journaled-initial-ipv4-address.md) | Proposed | Journaled exclusive IPv4 /32 assignment on an owned down TUN |
