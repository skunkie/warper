<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Implementation Status

The repository contains contracts, schema examples, ADRs, licensing metadata,
and executable development/CI harnesses. There is no Rust workspace or
protocol implementation yet. Required networking gates remain open.

## Phase Ledger

| Phase | Status | Evidence / next unmet gate |
| --- | --- | --- |
| Development infrastructure | Available | `scripts/check.sh` runs licensing, workflow/composite lint, shell lint, and harness tests; CI enables Rust jobs once workspace prerequisites exist |
| 0: Baseline and feasibility | Not started | Create minimal compiling workspace, register compatibility fixtures, run both stack-role probes |
| Contract gate before production dependencies | Pending Phase 0 | Complete `implementation-contracts.md` with selected APIs and source links |
| 1: Headless Linux service slice | Not started | Depends on feasibility, initial contracts, authorized control, and client-independent lifecycle |
| 2: Linux DNS and routing | Not started | Depends on fixed-CIDR lifecycle; NET-10/NET-11 cover grace/endpoint publication, and NET-12 requires global retained-state admission/renewal/exhaustion evidence |
| 3: Backends and IPv6 | Not started | WireGuard feasibility is already required in Phase 0 |
| 4: macOS networking and helper | Not started | ADR 0005 and UX-05 auth subset require actual ad-hoc bundled registration/enrollment/two-way IPC without paid signing; native networking/recovery/approval evidence also required |
| 5: Tauri desktop and release | Not started | Requires UX-01–UX-04 public packaging, full UX-05 local GUI/service/rebuild evidence, frontend checks, and production-mode exclusion tests |

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
