<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Implementation Status

Phase 0 Linux role evidence includes integrated host-runtime PMTU; the
required expanded host gate also runs genuine router transitions. [ADR 0002](adr/0002-network-stack.md)
selects direct smoltcp role adapters and BoringTun within their declared
limits. Both full role gates have real controlled-peer and independent
cleanup evidence. This does not establish a production networking service
or native macOS support. Phase 1 has begun with backend-independent static
CIDR policy, offline paths, bounded YAML decoding and schema/semantic validation;
the CLI, runtime preflight, protocol backends and service remain unimplemented.

## Phase Ledger

| Phase | Status | Evidence / next unmet gate |
| --- | --- | --- |
| Development infrastructure | Available | `scripts/check.sh`: licensing, actionlint with ShellCheck, composite validation, Python harness tests, Rust formatting/Clippy/rustdoc/tests/release and dependency policy |
| 0: Baseline and feasibility | Complete for Linux | Both default `scripts/verify-feasibility.sh` role gates pass; closure artifacts are indexed at `target/evidence/phase-0/closure/README.md`; expanded PMTU gate evidence is under `target/evidence/phase-0/runtime-pmtu/README.md` |
| Initial Linux contract gate | Passed for the initial boundaries | Compile-checked TCP/setup, route-driver and task ownership in `experiments/initial-contract/`; real accepted-stream/TCP backend usage in host probes. Contract models cover ACK/recovery/rollback, task termination and NET-10–NET-12 boundaries, not production DNS acceptance |
| 1: Headless Linux service slice | In progress | Core supplies static policy, backend identity and offline paths. `warper-config` supplies Unix account lookup, bounded YAML decoding and typed schema/semantic validation; all catalog offline expectations have parser tests. Evidence under `target/evidence/phase-1/`: `configuration-paths/`, `native-identity/`, `yaml-decoder/`, `schema-validation/`. Next: offline check-config CLI/fixture registration, runtime preflight, authenticated control, durable Linux driver/journal and actual SOCKS5/TUN service lifecycle |
| 2: Linux DNS and routing | Not started | Production DNS parsing/transport, complete service-binding dependency gates, response handoff, route leases, retained-state admission and isolated NET-02–NET-04/NET-10–NET-12 acceptance remain required |
| 3: Backends and IPv6 | Not started | WireGuard feasibility is established; production SSH/WireGuard integration, physical transport protection, PMTU integration and all backend acceptance remain required |
| 4: macOS networking and helper | Not started | Native utun/route/DNS/recovery and ADR 0005/UX-05 exact-build enrollment and mutual authentication remain unverified; Linux evidence cannot substitute |
| 5: Tauri desktop and release | Not started | GUI/control lifecycle, native packaging, UX-01–UX-05, production-mode exclusion tests and public signing/notarization remain required |

## Phase 0 Exit Evidence

The [exit criteria](implementation-plan.md#phase-0-baseline-and-feasibility)
are met by the following inspectable artifacts. Exact revision/worktree hashes,
commands, environment, dependency lockfiles, logs, outcomes and per-run cleanup
belong to the ignored evidence package, rather than this durable ledger.

| Requirement | Evidence and scope |
| --- | --- |
| Minimal workspace | Exact Rust 1.99.1/2024 workspace with tracked lockfile, shared lints and stage-aware CI. Both role gates run the full repository check script before networking. |
| Configuration/reference baseline | Canonical examples and original-shaped/migration/capability fixtures under `examples/` and `tests/fixtures/configuration/`, with documented intentional fixes. Executable production parser/CLI registration remains Phase 1. |
| Host-facing interception | Packet probes plus isolated Linux kernel TUN TCP/UDP in both families, two distinct controlled backend listeners, original tuples, concurrent 64 KiB transfers, response after FIN, empty/unequal/maximum datagrams and bounded queues. |
| Host failure and sizing | TUN adapter SIGKILL followed by fresh traffic, independent bridge joins/interface removal, supported kernel IPv4 fragments, bounded input reassembly, fixed 1280-byte segmentation and ICMP port-unreachable. The raw-stack PMTU failure remains a separate negative control; runtime and routed TUN PMTU are required gate scopes. |
| Active tunnel role | Actual smoltcp TCP/UDP through BoringTun and an independent Linux kernel WireGuard peer, both inner families and outer families, handshake-loss retry, completed rekey, sustained loss/recovery, exact FIN/bytes, no lost-UDP application replay and independently verified cleanup. |
| MTU feasibility | Local/kernel/routed MTU scopes demonstrate retained TCP adaptation in all four inner/outer combinations without repeating application writes. Queue-busy and ownership tests retain the original reservation. The host runner additionally retains two real kernel TCP flows across genuine 1500→1400→1280 router feedback, with entropy retry and unchanged ingress. General production path attribution is not inferred. |
| Decision and initial interfaces | Accepted ADR 0002; source-linked section 6 of `implementation-contracts.md`; executable route-driver/failure/task/DNS ownership models, with bounded deterministic state and controlled time. |
| Evidence package | Default gate logs and nested run directories, `target/evidence/phase-0/README.md`, closure and runtime-PMTU indexes/source snapshots, coverage review and controlled TUN workload measurements. Earlier failed/limited runs remain archived. |

## Retained Constraints and Later Gates

- The default host link MTU is 1280. The experimental TCP runner supports link
  MTUs through 1500 and actual downward PMTU discovery to 1280. Raw smoltcp still
  ignores feedback (`--raw-mtu-check`), while `--mtu-check` and
  `--tun-pmtu-check` must pass actual adapter/runtime and kernel-router evidence.
  Below-range feedback explicitly fails the selected flow. Upward probing and
  per-path throughput optimization remain capability extensions.
- Inner reassembly is bounded to 1280-byte packets with supported plain IP
  headers. Larger datagrams, outgoing inner fragmentation and general IPv6
  extension headers remain unsupported. Unsupported operations never select
  direct traffic or a different backend.
- A conservative 1280-byte WireGuard inner link requires at least 1340 bytes
  of IPv4 outer path or 1360 of IPv6 outer path. Smaller paths fail explicitly.
  Outer-fragment experiments are separate evidence, not a production policy.
- Physical socket/route protection, continuous network-change handling,
  short-quote correlation, router trust, concurrent/asymmetric path sizing and
  production interface migration must be finalized before their implementation
  depends on them. The detailed contract experiments preserve their limits.
- DNS contract models consume prevalidated endpoint sets and explicitly model
  references/budgets; they are not a DNS parser, resolver or atomic platform
  route manager. Production NET-10–NET-12 and complete retained-allocation
  accounting remain open. No full networking acceptance ID is closed here.
- Native macOS compilation, networking, entropy, helper registration, exact
  identity enrollment, mutual peer checks and UX-05 were **not run**. They stay
  open without blocking independent Linux work. Release signing evidence cannot
  replace the no-paid-account development authentication gate.
- The service, managed configuration, authorized control, durable instance
  ownership/journal, startup rollback and recovery remain Phase 1 work.
  Experimental fixed seeds and public synthetic keys are not production inputs.

## Gate Evidence

For each changed gate, preserve behavior, revision/worktree, environment,
copyable commands, pass/fail/not-run outcomes, failure/cleanup observations,
limits and next unmet requirements under `target/evidence/` or CI artifacts.
Keep successful and failed runs distinguishable. Never record live credentials,
raw user configuration or user packet payloads. Gate completion needs no human
approval; proceed to the next applicable independent increment.
