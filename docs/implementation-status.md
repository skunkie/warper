<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Implementation Status

The repository contains contracts, schema examples, ADRs, licensing metadata,
executable development/CI harnesses, and a minimal Rust experimental workspace.
There is no production service or protocol adapter yet. Required networking
gates remain open.

## Phase Ledger

| Phase | Status | Evidence / next unmet gate |
| --- | --- | --- |
| Development infrastructure | Available | `scripts/check.sh` runs licensing, workflow/composite lint, shell lint, and harness tests; CI enables Rust jobs once workspace prerequisites exist |
| 0: Baseline and feasibility | In progress | Isolated probes under `experiments/` produce evidence under `target/evidence/phase-0/`. Direct smoltcp 0.14 preserves UDP and bounded packet behavior; a TCP adapter now admits dynamic/shared destinations into bounded asynchronous streams with queue rollback, retained-buffer permits, deadlines, cancellation, and reset errors. Active sockets work through loopback BoringTun peers; wrapper comparison remains rejected. Next: independent WireGuard peer, general UDP admission, production scheduling/contracts, kernel TUN and outage/MTU evidence |
| Contract gate before production dependencies | Pending Phase 0 | Complete `implementation-contracts.md` with selected APIs and source links |
| 1: Headless Linux service slice | Not started | Depends on feasibility, initial contracts, authorized control, and client-independent lifecycle |
| 2: Linux DNS and routing | Not started | Depends on fixed-CIDR lifecycle; NET-10/NET-11 cover grace/endpoint publication, and NET-12 requires global retained-state admission/renewal/exhaustion evidence |
| 3: Backends and IPv6 | Not started | WireGuard feasibility is already required in Phase 0 |
| 4: macOS networking and helper | Not started | ADR 0005 and UX-05 auth subset require actual ad-hoc bundled registration/enrollment/two-way IPC without paid signing; native networking/recovery/approval evidence also required |
| 5: Tauri desktop and release | Not started | Requires UX-01–UX-04 public packaging, full UX-05 local GUI/service/rebuild evidence, frontend checks, and production-mode exclusion tests |

The [stack ADR](adr/0002-network-stack.md) remains proposed. Packet probes
establish limited transport behavior, not NET-01/NET-05/NET-06/NET-07 or
the complete Phase 0 exit criteria. No native macOS evidence exists.
`tests/fixtures/configuration/cases.toml` captures parser and capability
expectations; executable production parser/CLI registration remains Phase 1.
TUN device provisioning is denied here even inside disposable namespaces;
its kernel gate remains unverified. This does not block independent
userspace peer and adapter experiments.

## Gate Evidence

Update this ledger when a phase or prerequisite changes status. Link the
relevant accepted ADR and stable evidence location; do not append routine
per-run validation history here. Capture the following in CI logs or ignored
`target/evidence/` artifacts:

- **Behavior delivered:** concrete observable behavior and affected requirement/phase.
- **Revision:** commit ID when available; otherwise identify the worktree state and changed files without creating a commit solely for this field.
- **Environment:** OS/architecture, compiler/dependency versions, isolation method, required privileges, peer setup.
- **Commands:** exact copyable commands and necessary nonsecret setup.
- **Results:** passed, failed, not run, or unsupported for each check. Record skipped tests and why; retain redacted logs/assertions/capture summaries with the run.
- **Failure/cleanup evidence:** injected fault, expected state, observed state, and remaining owned resources.
- **Limits and next gate:** remaining unsupported behavior, decision changes, and the next independently verifiable deliverable.

Never include live credentials, raw payloads, real-user network captures, or private keys in evidence. Clearly label controlled synthetic fixtures.
