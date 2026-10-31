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
CIDR policy, offline paths, bounded YAML/schema validation and the check-config
CLI. Linux kernel peer checks and owner/root authorization are implemented as a
control boundary with mandatory initial-user-namespace admission. A bounded versioned
frame codec now carries version-2 lifecycle revision/instance fences, validates
before allocation and bounds total I/O with deadlines
and cancellation. A production SOCKS5 TCP
adapter now uses the promoted core TCP boundary with bounded negotiation,
credential handling and stream admission. A production host TCP adapter and
wake-driven runtime now preserve core metadata and half-close with bounded
queues, native Linux seeds and retained-stream accounting (ADR 0012).
Pure service preparation now validates the narrow static IPv4 capability and
payload budget before composing the real adapters. Session handling, physical
protection, native host preflight and a running control service remain open. A fixed Linux runtime-directory lease now pins
protected state and holds a persistent nonblocking lock; it is not yet
integrated with a network-instance lifecycle. The endpoint adapter now performs
intent-backed publication, kernel-authorized acceptance and explicit owned
retirement. A protected owner store supplies administrative revisioned snapshots.
Real privileged CI now verifies root ownership/enrollment, owner/foreign peers
and endpoint retirement; explicit pending inspection/discard preserves committed enrollment, while
service integration remains open. Linux client endpoint
admission now pins protected state and verifies a real root peer before exposing
a bounded connection. A bounded service relay set now retains/joins TCP workers independently of
clients, enforcing selected-backend setup, idle/absolute expiry and cancellation.
A Linux durable connection store now records accepted intent with native boot
and instance IDs, revision/operation fences, explicit resync and pending discard;
actual handler and network application remain open. No service executable exists yet.

## Phase Ledger

| Phase | Status | Evidence / next unmet gate |
| --- | --- | --- |
| Development infrastructure | Available | `scripts/check.sh`: licensing, actionlint with ShellCheck, composite validation, Python harness tests, Rust formatting/Clippy/rustdoc/tests/release and dependency policy |
| 0: Baseline and feasibility | Complete for Linux | Both default `scripts/verify-feasibility.sh` role gates pass; closure artifacts are indexed at `target/evidence/phase-0/closure/README.md`; expanded PMTU gate evidence is under `target/evidence/phase-0/runtime-pmtu/README.md` |
| Initial Linux contract gate | Passed for the initial boundaries | Compile-checked TCP/setup, route-driver and task ownership in `experiments/initial-contract/`; real accepted-stream/TCP backend usage in host probes. Contract models cover ACK/recovery/rollback, task termination and NET-10–NET-12 boundaries, not production DNS acceptance |
| 1: Headless Linux service slice | In progress | Static policy/configuration/CLI and Linux kernel peer checks have executable tests. Mandatory initial-user-namespace admission rejects real nested-root, counterfeit-procfs and same-procfs overmount cases (ADR 0008). A fixed protected runtime-directory lease verifies metadata/identity and retains a persistent flock inode (ADR 0009), with controlled SIGKILL/reacquisition evidence. A real endpoint adapter publishes/retires controlled sockets with durable intent and authorizes peers; a protected owner store now atomically persists revisioned enrollment under native administrative authorization. No service executable exists. Evidence under `target/evidence/phase-1/`: `configuration-paths/`, `native-identity/`, `yaml-decoder/`, `schema-validation/`, `check-config-cli/`, `linux-peer-auth/`, `user-namespace-admission/`, `runtime-ownership/`, `control-endpoint/`, `owner-enrollment/`, `control-framing/`, `socks5-backend/`, `host-tcp-adapter/`, `service-relays/`, `service-preparation/`. SOCKS5 has real controlled TCP/FIN evidence in both destination/physical families and a loopback workload baseline; journaled physical/TUN service integration remains open. Production TCP host/runtime tests cover original tuples, FIN, bounded queues and owner loss; the scoped native TUN API probe now passes actual kernel TCP. Pending enrollment recovery now compares pinned intent and committed state under renewed administrative authorization; the owner-dispatched root recovery gate passes. Pure service preparation now admits static IPv4 SOCKS5/TCP with explicit effective flow capacity and aggregate buffer reservations, without file reads, name resolution, sockets or host changes. Durable connection intent now supplies revision/instance fencing and bounded inspection/discard; positive native persistence CI passes at `ed834b5`. Next: session handlers, native host preflight, Linux driver/journal and actual SOCKS5/TUN service lifecycle |
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
- Native workspace builds/tests now pass on Linux x86_64/aarch64 and macOS
  aarch64 in [CI evidence](https://github.com/skunkie/warper/actions/runs/41181399851).
  Native macOS utun/route/DNS, service entropy integration, helper registration,
  exact identity enrollment, mutual code-identity checks and UX-05 remain
  **not run**. Release signing evidence cannot replace the no-paid-account
  development authentication gate.
- The service, managed configuration, authorized control, durable instance
  ownership/journal, startup rollback and recovery remain Phase 1 work.
  Experimental fixed seeds and public synthetic keys are not production inputs.

## Privileged Linux CI boundary

An owner-dispatched `privileged-control` job builds the actual root control
probe and runs the private namespace/state/resolver/bus harness on a standard
hosted Ubuntu VM. PR/push events cannot start it, and reusable callers inherit
the owner-dispatch restriction. It preserves the initial user namespace and
uses real root, owner and foreign peers without an authentication bypass.
Failure/cleanup logs and exact revision/probe hashes upload as
`linux-control-<commit>` artifacts.

Local harness tests, workflow lint and compilation establish harness readiness,
not root service acceptance. The actual
[owner-dispatched CI gate](https://github.com/skunkie/warper/actions/runs/41181399851)
passes at `8722e57`: initial-user-namespace root ownership, bootstrap enrollment,
actual owner/foreign peers, policy replacement/removal, reopened snapshots,
endpoint retirement and independently preserved host state. Raw artifacts are
retained under `target/evidence/phase-1/privileged-control-ci/run-41181399851/`.
This closes those native Linux boundaries, not the authenticated service API. Full
Phase 1 TUN/SOCKS application traffic, journaled startup rollback, service/client
lifecycle and required service-manager integration remain open.

The subsequent [client endpoint gate](https://github.com/skunkie/warper/actions/runs/41188150779)
passes at `d7a99c6` on native Linux x86_64/aarch64 and macOS aarch64 workspace
checks, including owner-dispatched privileged Linux control acceptance. Ordinary
owner/foreign clients now use the public pinned endpoint connector and verify
the actual root service; changed socket mode is rejected before connection.
Artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41188150779/`. This adds client
admission evidence; recovery additions need their own fresh root run.

The [enrollment recovery gate](https://github.com/skunkie/warper/actions/runs/41188500176)
passes at `122e3ed`, including partial-intent recovery through public native root
authentication and denied ordinary-peer inspection. Host state is independently
preserved; artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41188500176/`. Recovery CLI/API
handlers and live service policy revocation remain integration work.

The [prepared-adapter native CI gate](https://github.com/skunkie/warper/actions/runs/41190166009)
passes at `a930d88` on Linux x86_64/aarch64 and macOS aarch64 workspace checks,
including the existing privileged control/recovery fixture. This does not run
native TUN operations. ADR 0014 adds a development-only candidate TUN API probe
for the next owner-dispatched run; the subsequent native creation/collision/I/O/drop gate passes as described
below. Production journaled Linux driver and service gates remain open.

The [scoped native TUN API gate](https://github.com/skunkie/warper/actions/runs/41191632642)
passes at `e2e1f99`. Actual kernel TCP traverses a fresh TUN and the prepared
production host/SOCKS5/relay adapters, with exact 64 KiB request bytes, duplex
response and FIN. A separately owned TUN is preserved through collision and
packet handling; last-owner deletion and joined workers pass. The fixture proxy
verifies the original numeric CONNECT destination before mapping it to a local
target. Independent parent checks preserve host network, resolver and device
state; artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41191632642/`. ADR 0014 accepts
that scoped API. This is not a journaled Linux driver, protected physical NIC
path or authenticated daemon; those Phase 1 requirements remain open.

The [durable intent native gate](https://github.com/skunkie/warper/actions/runs/41196275017)
passes at `ed834b5`, including public root persistence/reopen, repeat suppression,
instance fencing, resync and partial pending discard. Existing peer/enrollment
and kernel TUN gates pass with preserved host state. Artifacts are retained at
`target/evidence/phase-1/privileged-control-ci/run-41196275017/`. Shared runtime
ownership now permits retained workers to keep the instance lock beyond listener
retirement; full service shutdown and journaled native work remain open.

## Gate Evidence

For each changed gate, preserve behavior, revision/worktree, environment,
copyable commands, pass/fail/not-run outcomes, failure/cleanup observations,
limits and next unmet requirements under `target/evidence/` or CI artifacts.
Keep successful and failed runs distinguishable. Never record live credentials,
raw user configuration or user packet payloads. Gate completion needs no human
approval; proceed to the next applicable independent increment.
