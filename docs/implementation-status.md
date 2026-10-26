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
| 0: Baseline and feasibility | In progress | Isolated probes under `experiments/` produce evidence under `target/evidence/phase-0/`. TCP/UDP candidates preserve dynamic/shared destinations, frozen metadata, bounded retained buffers/messages, expiry, and cancellation. A combined wake-driven runtime now runs both through bounded packet channels, library/lifecycle deadlines, rotating output priority, blocked-output expiry, explicit shutdown, and joined failure cleanup; evidence is indexed in `target/evidence/phase-0/runtime/README.md`. UDP admission evidence remains in `target/evidence/phase-0/udp/README.md`. Active sockets work through BoringTun and an independent Linux kernel WireGuard peer, including both inner families, empty datagrams, FIN, handshake-loss retry, and completed rekey (`target/evidence/phase-0/kernel/README.md`). Wrapper comparison remains rejected. Next: finalized initial production contracts, kernel TUN and outage/MTU/ICMP evidence |
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
peer and adapter experiments. Linux kernel WireGuard interface creation and
retirement work in disposable namespaces independently of the unavailable
TUN device; this does not establish host TUN interception.

WireGuard packet-level failure probes now cover bounded handshake staging,
transient TCP/UDP loss, setup/application-response deadlines, cancellation,
and outer socket release (`target/evidence/phase-0/outage/README.md`). These
same-library fixture observations do not close service/backend outage or
crash recovery acceptance, independent-kernel outage, or MTU/ICMP gates.

The explicit host MTU gate now reproduces oversized TCP retransmission after
valid ICMP too-big feedback and missing fragment reassembly in both families
(`target/evidence/phase-0/mtu/README.md`). Fixed 1280-byte segmentation,
ICMP port-unreachable generation, and WireGuard envelope limits are tested.
Bounded pre-admission IPv4/IPv6 fragment input now handles both orders,
overlap tombstones, atomic fragments, expiry, and transport checksum gating
(`target/evidence/phase-0/reassembly/README.md`). The same boundary now runs
after authenticated WireGuard decryption and inner-address checks, with
encrypted UDP fragment round trips, expiry, overlap rejection, and socket
release (`target/evidence/phase-0/wireguard-fragments/README.md`).
Dynamic PMTU/error propagation,
outgoing fragmentation, larger datagrams, and extension-header strategy
remain unresolved; the MTU gate returns nonzero and ADR 0002 stays proposed.

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
