<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Implementation Status

Phase 0 feasibility and Phase 1's headless Linux service slice are complete.
The service and authenticated CLI forward static IPv4/SOCKS5 TCP through a
journaled, acknowledged TUN lifecycle. Administrative enrollment/import,
managed boot intent, online/offline recovery, foreground diagnostics and source
systemd installation have controlled native evidence. The final
[requirement and resource audit](phase-1-acceptance.md) maps every Phase 1
increment and exit to implementation, tests and inspected artifacts.

This is not a cross-platform release. Production DNS discovery, SSH/WireGuard,
IPv6, native macOS networking and Tauri remain later phases. Native ARM64 builds
are tested; privileged networking/systemd acceptance currently covers disposable
Linux x86-64 only. Phase 2's production DNS/route transaction gate is next.

## Phase Ledger

| Phase | Status | Evidence / next unmet gate |
| --- | --- | --- |
| Development infrastructure | Available | `scripts/check.sh`: licensing, actionlint with ShellCheck, composite validation, Python harness tests, Rust formatting/Clippy/rustdoc/tests/release and dependency policy |
| 0: Baseline and feasibility | Complete for Linux | Both default `scripts/verify-feasibility.sh` role gates pass; closure artifacts are indexed at `target/evidence/phase-0/closure/README.md`; expanded PMTU gate evidence is under `target/evidence/phase-0/runtime-pmtu/README.md` |
| Initial Linux contract gate | Passed for the initial boundaries | Compile-checked TCP/setup, route-driver and task ownership in `experiments/initial-contract/`; real accepted-stream/TCP backend usage in host probes. Contract models cover ACK/recovery/rollback, task termination and NET-10–NET-12 boundaries, not production DNS acceptance |
| 1: Headless Linux service slice | Complete for the verified Linux slice | [Closure audit](phase-1-acceptance.md): actual application TCP/FIN through selected SOCKS5/TUN, failed-start restoration, detached clients, explicit Down, authorization, bounded ownership, recovery, equivalent diagnostics and installed systemd lifecycle. Full native matrix and all privileged gates pass at `687b293` in [CI 41597810149](https://github.com/skunkie/warper/actions/runs/41597810149). Inspected evidence is under `target/evidence/phase-1/lifecycle-tracing/`. Linux ARM64 privileged acceptance and native macOS networking are not claimed. |
| 2: Linux DNS and routing | In progress | Core bounded DNS names, longest-domain selection and bounded packet adapters are implemented. Selected/direct TCP and direct UDP DNS include shared request admission, query budgets and original deadlines; protected UDP lifecycle has native evidence. Listener integration, complete service-binding dependency gates, response handoff, route leases, retained-state admission, resolved integration and isolated NET-02–NET-04/NET-10–NET-12 acceptance remain required |
| 3: Backends and IPv6 | Not started | WireGuard feasibility is established; production SSH/WireGuard integration, physical transport protection, PMTU integration and all backend acceptance remain required |
| 4: macOS networking and helper | Not started | Native utun/route/DNS/recovery and ADR 0005/UX-05 exact-build enrollment and mutual authentication remain unverified; Linux evidence cannot substitute |
| 5: Tauri desktop and release | Not started | GUI/control lifecycle, native packaging, UX-01–UX-05, production-mode exclusion tests and public signing/notarization remain required |

## Phase 2 DNS Foundations

`warper-core::dns` implements bounded names and domain selection;
`warper-service::dns` implements bounded packet validation and explicit
selected-backend/direct TCP exchange. Raw checks, coverage, controlled peer
results and release workloads are under
`target/evidence/phase-2/{domain-policy,packet-adapter,tcp-transport,direct-tcp}/`.
The packet adapter's native matrix and disposable Linux regression manifests
are retained under its `ci-41607466058/` directory. These establish scoped
protocol compatibility and existing Linux lifecycle regressions, not native
DNS/route acceptance. Service preflight still rejects DNS configurations.
The next integration gate is bounded listener ownership;
endpoint validation, leases, route publication and resolved integration remain
required before domain discovery can be enabled.
The route query distinguishes TCP/UDP tuples. ADR 0025's source/device-bound UDP
mechanism passes in [CI 41611452768](https://github.com/skunkie/warper/actions/runs/41611452768)
at `4cdce8e`, with real datagram boundaries and a competing TUN /32 in the private
physical-peer fixture. Inspected raw manifests/logs are under
`target/evidence/phase-2/bound-udp-egress/ci-41611452768/`. This establishes the
Linux x86-64 virtual routed socket mechanism. The production datagram connector
now bounds queues, retains native ownership, reports truncation and invalidates
on changes. Its expanded production gate passes in
[CI 41618257779](https://github.com/skunkie/warper/actions/runs/41618257779)
at `edadf71`, including inspected lifecycle assertions and a controlled workload.
All four probe manifests exit zero without timeout and preserve host state;
raw copies are under `target/evidence/phase-2/protected-udp/ci-41618257779/`.
Direct UDP DNS and same-upstream TCP retry are now implemented with one request
permit and a shared query budget. Their native composition gate passes in
[CI 41671110746](https://github.com/skunkie/warper/actions/runs/41671110746)
at `b8e8c52`: 100 same-upstream UDP-to-TCP retries under competing capture,
source/query validation, original admission and attempt accounting, and no
private-interface drops. All four isolated probe manifests exit zero without
timeout and preserve host state; the installed idle service gate also passes.
Inspected manifests and workload logs are under
`target/evidence/phase-2/udp-dns/ci-41671110746/`.
Raw checks belong under `target/evidence/phase-2/udp-dns/`. Resolver discovery,
listener ownership, byte admission and full service integration remain open.

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

The Linux service now has a bounded read-only IPv4 TCP kernel route query
(ADR 0016), with real loopback/source/interface and kernel-rejection tests.
It does not authorize physical sends, publish routes or supply a monitored path
lease. The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41210002931)
passes at `e23a88b`, including the private-namespace query and existing kernel
TUN/control fixtures with independently preserved host state.
Evidence is retained under `target/evidence/phase-1/linux-route-lookup/`.

The native change monitor subscribes to link/address/route/rule events with a
bounded kernel queue and permanently invalidates on changes or uncertainty.
Native subscription/owner-loss and bounded parser tests pass locally; actual
private-namespace link-change acceptance passes in
[owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41210806096)
at `07db97c`, including dropped pending waits and preserved host state. Evidence is retained under `target/evidence/phase-1/linux-change-monitor/`.
It does not close physical socket binding, snapshot consistency or the driver.

Native link inspection now shares the bounded read-only route transport and
retains name/index/alias/MTU/flags/kind for future ownership comparisons. Native
loopback name/index tests and malformed/mismatched metadata tests pass locally.
[Owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41211693343)
passes isolated TUN inspection at `bc04a62`, including foreign identity
preservation and independently preserved host state. This is not a
journal ownership proof or production mutation driver. Evidence is retained
under `target/evidence/phase-1/linux-link-lookup/`.

The protected network journal storage boundary (ADR 0017) supplies bounded,
revisioned snapshots, exact staging checks and explicit partial/uncertain
recovery. Private real-file tests pass; public native root storage execution passes
[owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41213342279)
at `44e889b` with preserved host state. Evidence is retained under
`target/evidence/phase-1/network-journal-storage/`. This is storage only: platform
journal meaning, native mutation/rollback and the running daemon remain open.

The native journal owner component (ADR 0018) pins network/PID namespaces and
records boot, instance and process-start identity while retaining runtime
ownership. Local real-procfs and bounded parser/classification tests pass.
Public root capture and foreign-thread namespace rejection pass in
[owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41215393408)
at `e7711c7`, including joined thread cleanup and preserved host state. Evidence is retained under
`target/evidence/phase-1/native-journal-context/`. Full platform journal meaning,
process liveness, object ownership and mutation/recovery remain open.

The initial journaled TUN owner (ADR 0019) implements durable preparation,
fresh down allocation, atomic requested naming and verified descriptor-based
retirement. Local codec and strict compile checks pass; actual journaled native
allocation/raced-conflict rollback, storage recovery and lifecycle workload pass
in [owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41220497788)
at `3b17c4a` with independently preserved host state. Evidence is under
`target/evidence/phase-1/journaled-tun/`. Address/UP/route/exemption transactions,
packet-worker integration, recovery and the running daemon remain open.

Blocking native-job ownership now bounds admission and retains work/results when
caller waits expire or disappear. Real blocking-worker tests prove cancellation,
deadline, owner loss, panic propagation and joined resource admission. Evidence
is under `target/evidence/phase-1/native-worker-ownership/`. The service supervisor
still must integrate these owners and drain them before shutdown; this is not a
running daemon or a completed native address/route driver.

The initial IPv4 address transaction (ADR 0020) now journals exclusive /32
assignment with no connected-prefix route, validates kernel ACK/readback and
supports verifying repetition and descriptor rollback. Local tests/read-only
inspection pass. Privileged address mutation, foreign preservation and rollback
pass in [owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41233000400)
at `51ddb3b`, with independently preserved host state. Evidence is under
`target/evidence/phase-1/journaled-ipv4-address/`. UP, capture routes, physical
exemptions, full recovery and daemon/control integration remain open.

The initial owned TUN activation now journals intent before changing only IFF_UP
and requires correlated ACK plus current link/address readback before commit.
The bounded native worker transport is shared with address assignment; prior
WTUN versions remain conservatively readable. Local checks and scoped
privileged activation pass in [owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41233600374)
at `ce5f4b2`, including the joined 20-cycle workload and preserved host state.
Evidence is under `target/evidence/phase-1/journaled-tun-activation/`. Capture
routes, endpoint exemptions, packet supervision and full recovery remain open.

The initial native packet port now shares only the original journaled descriptor
and retains runtime context. It bounds one read/write per direction and MTU,
returns typed failures and blocks explicit retirement while packet work survives.
Local cancellation/admission and boundary tests pass. Actual journaled-owner
TCP packet traffic/retirement and surviving-port runtime ownership pass in
[owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41234617793)
at `feaa91a`, with independently preserved host state. Evidence is under `target/evidence/phase-1/owned-tun-packet-port/`. The fixture's capture route
still does not establish production route ownership; the protected connector
has its separate evidence below. Daemon supervision/recovery remain open.

The bound TCP egress experiment (ADR 0021) now exercises source/device binding,
actual tuple route verification and an isolated peer under a competing capture
/32, with retained child cleanup and independent host-state checks. Native
socket bypass passes in [owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41235377897)
at `999e86f`, with independently preserved host state. Evidence is under `target/evidence/phase-1/bound-tcp-egress/`. A production
physical connector, continuous path invalidation and exemption ownership remain
open even if the candidate socket API passes.

The initial protected TCP connector now prepares deterministic route/link
selection and verifies fresh source/device-bound tuples per admitted connection.
It bounds lifetime slots and native queues, monitors both stream directions and
closes on change/loss without path/backend fallback. Local path/waker/error
checks pass. Actual production connector under capture, independent idle
invalidation and real kernel SOCKS5 integration pass in
[owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41239873952)
at `25396a0`, with independently preserved host state. Evidence is under `target/evidence/phase-1/protected-tcp-connector/`. Hardware
path evidence, full native budget admission, capture publication/recovery and
daemon/control integration remain open.

Host TCP admission quiescence now has a bounded retained command/result,
wait-cancellation-safe acknowledgement and active/retained flow snapshots.
It preserves accepted TCP traffic while resetting selected new SYNs and
aborting unpublished handshakes. Local controlled-peer lifecycle tests pass.
Native kernel rejection after acknowledgement passes in
[owner-dispatched CI](https://github.com/skunkie/warper/actions/runs/41241770521)
at `c077749`, with independently preserved host state. Evidence is under `target/evidence/phase-1/host-tcp-quiescence/`.
This is an admission barrier, not completed route withdrawal, response-grace
accounting or daemon shutdown/recovery.

The runtime now exposes its allocated capture policy and retained-flow lifetime
observation through a non-forgeable read-only reference. Weak ingress ownership
preserves required input-owner loss; quiescence and retained counts remain
observable after runtime stop and until application handles drop. Local
controlled lifecycle checks pass. Evidence is under
`target/evidence/phase-1/capture-policy-publication/`. This is an observation
boundary, not task/network readiness or native route authority; capture route
publication, drain/grace integration and recovery remain open.

## Gate Evidence

For each changed gate, preserve behavior, revision/worktree, environment,
copyable commands, pass/fail/not-run outcomes, failure/cleanup observations,
limits and next unmet requirements under `target/evidence/` or CI artifacts.
Keep successful and failed runs distinguishable. Never record live credentials,
raw user configuration or user packet payloads. Gate completion needs no human
approval; proceed to the next applicable independent increment.

A bounded read-only IPv4 route inventory now retains all tables and compact
route comparison metadata, including routes with unsupported selectors. It
requires complete correlated multipart termination and never returns a partial
result on interruption, loss or capacity exhaustion. Address inspection shares
the same bounded multipart transport. Local read-only kernel and malformed-input
tests cover the boundary; a private TUN fixture checks exact capture metadata.
Evidence belongs under `target/evidence/phase-1/linux-route-inventory/`.
The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41340340274)
passes at `6945401`, including exact private TUN capture-route metadata and
independently preserved host state. Artifacts are retained under
`target/evidence/phase-1/privileged-control-ci/run-41340340274/`.
Policy-rule inspection, journaled publication/retirement and recovery remain
open; an inventory is not ownership authority or a consistent monitored snapshot.

The initial IPv4 policy-rule classifier now distinguishes exactly the three
unconditional local/main/default rules from custom or incomplete layouts.
Complete bounded native read-only dumps and synthetic selector/duplicate/limit
tests cover inspection; the private TUN fixture checks its default layout.
The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41343062611)
passes at `a030484`, including custom-rule preservation, restored layout and
actual TUN/SOCKS TCP with independently preserved host state. Evidence is under
`target/evidence/phase-1/linux-rule-inventory/` and
`target/evidence/phase-1/privileged-control-ci/run-41343062611/`. It neither changes rules nor
closes capture publication, monitored consistency, retirement or recovery.

ADR 0022 accepts the scoped journaled static IPv4 capture batch boundary.
The owner now records full intent before exclusive kernel adds, verifies ACKs
and fresh monitored metadata, retains runtime ownership across failures, and
fences exact route withdrawal with quiescence/zero flow references. Changed
route keys are preserved. WTUN v4 keeps conservative legacy decoding with
bounded canonical batch records. The [owner-dispatched lifecycle gate](https://github.com/skunkie/warper/actions/runs/41344128654)
passes at `2c6a268`, including twenty three-prefix cycles, changed-route
preservation, joined retirement and independently preserved host state.
Artifacts are retained under
`target/evidence/phase-1/privileged-control-ci/run-41344128654/`.
Evidence belongs under `target/evidence/phase-1/journaled-capture/`. The
application-flow fixture now uses this owner as described below; actual new
traffic evidence, partial/uncertain failure injection, crash recovery, complete
native budget admission and full daemon lifecycle remain open.

The actual kernel TCP fixture now uses journaled capture publication, retains
the runtime before kernel routing, supervises capture changes, and quiesces with
a live accepted stream. It asserts that native withdrawal rejects that flow,
then preserves duplex bytes/FIN, drains the controlled output and joins native
withdrawal before runtime shutdown. The [owner-dispatched traffic gate](https://github.com/skunkie/warper/actions/runs/41344540549)
passes at `a339d36`, including exact real TCP/FIN and independently preserved
host state. Artifacts are retained under
`target/evidence/phase-1/privileged-control-ci/run-41344540549/`. Evidence belongs under
`target/evidence/phase-1/journaled-capture-traffic/`. Forced error-driven flow
draining, crash reconciliation and the real daemon remain open.

The host runtime now supports explicit forced flow cancellation while retaining
the quiescent policy/reset handler. Idle readers wake with Interrupted, driver
flows and bounded input buffers retire, and queued/application references remain
charged until final drop. Bounded output discard leaves its owner open. Local
IPv4/IPv6 controlled-peer tests include observer loss, unread buffered streams,
repeated cancellation and continued reset handling. Evidence belongs under
`target/evidence/phase-1/forced-flow-cancellation/`. Service integration must
still join relays/native I/O, release queued handles, drain packets/grace and
withdraw capture before stopping the mapping. Full daemon/recovery gates remain
open.

Native context now supplies read-only recorded-process observation with PIDFD
polling and bounded verified-procfs start ticks, including PID reuse, previous
boot separation and current-instance/foreign-scope fencing. Missing evidence
with a live descriptor remains uncertain. Local self and boundary tests pass;
a private root context peer adds real SIGKILL/reap and runtime reacquisition
for the next native run. Evidence belongs under
`target/evidence/phase-1/native-process-observation/`. The [native liveness gate](https://github.com/skunkie/warper/actions/runs/41384228624)
passes at `5adcf1b`, including real SIGKILL/reap and runtime reacquisition with
independently preserved host state. Artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41384228624/`.
Abandoned journal reconciliation now has scoped native evidence below.

The initial driver now has abandoned-journal retirement under native context
checks. It preserves live/uncertain owners and foreign or surviving keys, and
commits only ended ownership under the observed revision without native deletes.
A fresh-state recovery executable and owner-dispatched CI step cover actual
SIGKILL at prepared/allocated/enabled/captured stages, pending intent, foreign
claims, idempotence and fresh allocation. The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41387832176)
passes at `25f8933`, including request expiry/cancellation and independently
preserved host state. A modeled prior boot preserves current foreign state;
actual reboot recovery is not established. Artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41387832176/`; local evidence
is under `target/evidence/phase-1/abandoned-tun-recovery/`. Desired-state
restart, stale control endpoint recovery and full service supervision remain
open.

The ordinary-client credential reader now opens and validates the same regular
file descriptor, checks invoking-user/root ownership and private permissions,
bounds reads independently of metadata, and rejects observed descriptor changes.
It preserves UTF-8 content while removing exactly one final LF/CRLF. Controlled
file/FIFO/symlink, size, permission, decoding and read-failure tests exercise the
boundary. Evidence belongs under
`target/evidence/phase-1/client-secret-import/`. This does not yet provide the
authorized installation or import CLI. The managed format is described below.

The initial managed SOCKS5 snapshot now materializes defaults and normalized
values in bounded versioned data, with a separate UTF-8 credential table. Native
client import reads selected password files; service-side decode accepts only
canonical path-free configuration and performs no file reads. Public API tests
exercise round trips, 64 backends/maximum credentials, malformed/truncated data,
platform names, unsupported-backend validation before reads, and expansion over
node/byte budgets. Evidence belongs under
`target/evidence/phase-1/managed-snapshot/`. Protected atomic storage, generation
fencing, authorized installation and the import CLI remain open.

The Linux managed store now has a fixed `/etc/warper` slot with a distinct
generation envelope and 1 MiB capacity, sharing the journal's bounded atomic
storage implementation. Local fixed-root tests cover capacity, revision fencing,
slot magic/token separation, pending preservation, uncertain sync and replaced
parents. The private privileged fixture adds real root metadata, ordinary
owner/foreign read denial, reopen and pending recovery. The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41389748795)
passes at `37ea223`, including the shared journal, TUN traffic and crash-recovery
regressions with independently preserved host state. Artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41389748795/`; local evidence is
under `target/evidence/phase-1/managed-store/`. Service-side validation, administrative
installation and disconnected-session serialization remain open.

Native configuration ownership now decodes and pure-preflights approved data
before storage and requires a fresh administrative peer for installation. An
immutable generation lease retains context/runtime ownership and blocks
replacement through preparation/network/cleanup until its final drop. Local
runtime-claim tests also prove manager reacquisition stays blocked while a
retained guard exists and that it keeps instance ownership locked. Local
tests cover malformed/unavailable proposals and actual unprivileged peer
authentication. The native fixture adds the full install API with a controlled
ordinary peer, stale generations, retained/cloned leases, blocked manager reopen
until final lease drop, reopened approved state and external
replacement rejection. The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41391328712)
passes at `5a62a65`, including independently preserved host state and the existing
control/TUN/crash-recovery regressions. ADR 0023 accepts this scoped boundary.
Local evidence is under `target/evidence/phase-1/configuration-ownership/`;
artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41391328712/`.
The control session handler and full network supervisor still need to retain
these leases; this does not establish connected readiness or a service CLI.

Control framing now checks the actual monotonic deadline before every I/O poll,
so ready/resumed I/O cannot consume or emit bytes after expiry while runtime
timer readiness is still rounded to a later clock tick. Controlled-clock read
and write regressions fail without this fix. Evidence belongs under
`target/evidence/phase-1/control-frame-deadlines/`; this does not add session
handlers or daemon readiness.

The Linux control session owner now enforces Hello, increasing request IDs,
single-request sequencing, command access and correlated replies. Policy is
checked before read admission and freshly supplied after read completion for
dispatch; handlers still need commit-boundary authorization after queuing.
Controlled Unix peers cover owner permissions/revocation, malformed sequence,
deadlines, partial reads and abandoned writes without replay. A private native
root/owner fixture exercises the protected endpoint and administrative dispatch.
The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41395848365)
passes at `dddecb9`, including actual root/owner Hello and correlated status,
administrative access, and existing control/TUN/crash-recovery regressions with
independently preserved host state. Local evidence is under
`target/evidence/phase-1/control-sessions/`; artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41395848365/`.
Concrete service handlers, global
client/buffer admission and a running daemon remain open.

The native TUN direction guard now checks the actual monotonic deadline before
every device I/O poll rather than relying only on rounded timer readiness.
Controlled-clock tests cover ready and resumed submillisecond I/O, preserve
cancellation precedence and verify direction capacity is released on expiry.
The resumed regression fails without this fix. Evidence belongs under
`target/evidence/phase-1/packet-direction-deadlines/`. The
[owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41397467021)
passes at `79f427e`, including exact 64 KiB TCP, duplex traffic and response
after FIN through the real TUN, plus control and crash-recovery regressions.
All three isolated runs report no timeout and independently preserved host
state. Artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41397467021/`.

Linux control admission now independently bounds client ownership and retained
request buffers. Pure planning caps clients/requests at 64 and derives effective
request concurrency from the configured encoded-message and aggregate buffer
limits. Admitted sessions reserve before reading, and dispatched requests keep
their reservation after session drop until retained work releases it. Closing
admission wakes waiting reads without canceling accepted work. Managed
configuration validation rejects unsupported admission limits before storage.
Local Unix peers and controlled clocks exercise capacity exhaustion, retained
ownership, abandonment, malformed frames, cancellation and exact deadlines.
Evidence belongs under `target/evidence/phase-1/control-admission/`. The native
root/owner session fixture now uses this admission path. The
[owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41456708777)
passes at `99afd63`; control, real-TUN traffic and crash recovery all finish
without timeout and preserve independently observed host state. Artifacts are
under `target/evidence/phase-1/privileged-control-ci/run-41456708777/`. Concrete handlers, kernel queue/native
resource accounting, operation/event admission and the daemon supervisor remain
open.

The Linux service packet pump now owns independent original-device read/write
futures inside one retained task. Direction failures cancel and join the
sibling, and explicit stop differs from lost supervisor ownership. Read-idle
deadlines renew; writes have a bounded terminal deadline and no replay. Bounded
ingress exhaustion counts drops, pending-output cancellation counts discards,
and fixed histograms replace per-packet measurement allocations. Both ready
directions yield after at most eight packets to preserve supervisor progress.
Local in-memory transport tests exercise duplex bytes, exhaustion, write
uncertainty/failure, cancellation, idle renewal, owner/channel loss, invalid
input and always-ready fairness. The native TCP/FIN fixture now runs this pump
through route withdrawal and retains the stopped receiver owner until explicit
host shutdown is joined. The
[owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41466656225)
passes at `227a20f`: all three isolated fixtures finish without timeout and
preserve independently observed host state. The controlled 64 KiB TCP/FIN run
also records a fixed write-wait histogram, byte counts, CPU, peak RSS and drop
counters. Artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41466656225/`; local evidence
is under `target/evidence/phase-1/packet-pump/` and
`target/evidence/phase-1/packet-pump-lifetime/`. The complete CI matrix
also passes at that revision, including macOS and both Linux native targets.
Full network supervision, startup readiness, failure rollback and daemon/control
integration remain open.

The Linux network supervisor now retains the approved configuration through
native transitions, protected backend connectors, runtime/packet task results
and joined relay work. Startup waits for task polling before capture; Connected
requires acknowledged capture and live owners. Stop quiesces admission, bounds
graceful drain, forces remaining flows within the shared deadline and retires
routes before stopping the packet/runtime owners and closing the TUN. Failed
withdrawal or unresolved native work keeps ownership retained for cleanup.
Expected relay exhaustion rejects only the new flow and records its outcome.
Local tests cover task readiness/observer loss, capacity isolation, pure deadline
validation and bounded abort/join under a noncooperative-worker fault. The
native fixture adds canceled startup without journal mutation, rollback after
activation on an unusable physical backend path, retained approval fencing and
actual kernel TCP/FIN followed by explicit service stop. The
[owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41473128483)
passes at `8f86089`: all three isolated fixtures finish without timeout and
preserve independently observed host state. The supervisor fixture verifies
retirement with no retained host streams, then permits managed replacement
after the final supervisor lease drops. Artifacts are under
`target/evidence/phase-1/privileged-control-ci/run-41473128483/`; local evidence
is under `target/evidence/phase-1/network-supervisor/`. The authenticated daemon
controller, durable operation dispatch, administrative CLI/installation and full
client-detach/lifecycle acceptance remain open.

Control endpoint restart recovery now uses a bounded WCTL v1 intent with the
persistent lock identity and a frozen socket pathname identity. Publication
syncs Prepared before bind and Bound before listen. Recovery requires unique,
never-published runtime ownership; an Arc extracted from an old endpoint cannot
replace fresh flock acquisition. Local fixtures prove known stale retirement,
idempotence, foreign/changed/shared state preservation, legacy refusal and
record boundaries. The native fixture adds actual SIGKILL/reap and fresh
publication after recovery. The
[owner-dispatched privileged gate](https://github.com/skunkie/warper/actions/runs/41484467276)
passes at `85e2e6e`: all three isolated fixtures finish without timeout and
preserve independently observed host state. Its control log verifies actual
SIGKILL/reap, fresh-lock recovery, repeated retirement and fresh publication.
The later native build/test matrix passes on both Linux architectures and
macOS at `e3cffec` in the controller gate linked below. Evidence is under
`target/evidence/phase-1/control-endpoint-recovery/`, including downloaded CI
artifacts. This supplies a safe bootstrap boundary; the daemon, control dispatch
and administrative CLI remain incomplete.

The Linux `warper` client now implements native status, Connect/Disconnect
submission and bounded operation observation. It authenticates the fixed
protected endpoint before Hello and preserves output/wait options, service
instance and independent configuration/desired revisions. Lost acceptance,
observer cancellation and wait expiry retain the operation identity without
resubmission or a compensating Disconnect. Controlled duplex peers verify exact
requests, acceptance-only detach, terminal outcomes, mismatched identities,
service rejection and both I/O and pacing cancellation. Evidence is under
`target/evidence/phase-1/native-cli/`. No daemon is installed or exercised by
these client tests. Administrative import/enrollment/recovery commands, concrete
handlers, operation history and full native daemon/CLI acceptance remain open.

The serialized Linux controller now composes protected owner policy, managed
approval, durable connection intent and bounded operation history. It performs
fresh kernel peer authorization before dispatch, persists accepted intent before
returning service-owned actions, suppresses duplicate execution and late
superseded readiness, and distinguishes historical operation completion from
current session state. A one-record history can accept Disconnect by retiring
the superseded Connect only after durability; active records are otherwise
protected. Service shutdown does not convert an interrupted Connect to success.
Boot policy preserves same-boot Disconnect, restores matching accepted Up only
after reconciliation, and applies autoconnect separately on a fresh boot.
Local history, boot-policy, capacity and error-category tests pass. A disposable
native fixture adds actual owner replacement, pending-start cancellation,
retained approval and kernel TCP/FIN through controller actions. The
[owner-dispatched exact-commit gate](https://github.com/skunkie/warper/actions/runs/41509483848)
passes at `e3cffec`: all three isolated fixtures finish without timeout and
preserve independently observed host state. The controller log confirms real
kernel-peer authorization, owner replacement, durable idempotence, one-record
Disconnect, suppressed readiness, retained approval and kernel TCP/FIN. The full
native build/test matrix also passes. Raw artifacts and local review are under
`target/evidence/phase-1/controller-dispatch/`. The async daemon, control task
supervision, administrative CLI/recovery, installation and full daemon/CLI
acceptance remain open.

Control admission now applies changed plans to the existing quota owner rather
than replacing its pool. Outstanding frames retain their original byte charges
and client leases across session exit and queued work. Limit reductions wait
for those charges to drain; increases account for both old and new sizes.
Existing sessions obtain the current frame limit from their next reservation.
Controlled tests cover shrinking and expanding plans, retained client capacity,
closed/poisoned accounting and frame-limit refresh before body allocation.
Evidence is under `target/evidence/phase-1/control-reconfiguration/`. The daemon
must still compose this admission owner with its session and native-task queues.


The foreground Linux `warperd service` executable now owns a retained native
control actor, bounded request/event channels, joined authenticated client tasks
and an independent network supervisor. Listener registration uses a cloned owned
Unix listener; native metadata and peer checks precede framing. Client exit does
not signal the network owner. SIGTERM/SIGINT close admission, settle tasks and
retire the endpoint under retained native ownership. Fault tests cover pending
native work across cleanup deadlines, joined worker panics, lost network
ownership and preservation of primary failures. The new disposable fixture
launches the actual daemon and CLI, controlled kernel TCP/FIN, foreign denial,
client detach, explicit Disconnect, failed-start rollback and endpoint retirement.
The [exact-commit privileged gate](https://github.com/skunkie/warper/actions/runs/41526234900)
passes at `fe5962c`; all four isolated probe results report exit zero, no timeout
and preserved host state. Evidence is under
`target/evidence/phase-1/daemon-composition/ci-41526234900/`. Administrative CLI import/enrollment,
offline recovery, runnable service-manager installation and the final full Phase
1 acceptance audit remain open.


The Linux administrative CLI now submits generation-fenced normalized
configuration installation and revision-fenced owner enrollment/removal after
native service authentication. Import runs under the validated invoking account
in a separate process with normal account groups, bounded private pipe framing
and redacted failures. No root parent reads user-selected YAML or credential
paths, and uncertain administrative replies are never retried automatically.
Controlled client tests cover exact revision selection, owner presence, snapshot
payloads and lost acknowledgements. The actual daemon fixture now exercises
these CLI commands, including root-only credential denial, ordinary supplementary
group access and owner revocation. The [expanded privileged gate](https://github.com/skunkie/warper/actions/runs/41566836124)
passes at `5d8d37f`; all four isolated probes report exit zero, no timeout and
preserved host state. Downloaded evidence is under
`target/evidence/phase-1/admin-cli/ci-41566836124/`. Recovery commands and the full
Phase 1 audit remain open.


The headless Linux source installation now includes
`packaging/linux/warper.service` and `docs/linux-service.md`. systemd owns the
foreground root process and protected directory creation, preserves the runtime
lock inode across stops and allows the full native shutdown budget before forced
control-group termination. Installation, approval, readiness, update and removal
instructions are documented without deleting recovery state. Unit syntax is
validated against the built daemon path; installed idle-unit lifecycle
acceptance now has the exact-commit evidence below. Evidence belongs under
`target/evidence/phase-1/systemd/`. No release package or desktop is produced.

Endpoint recovery now exposes a read-only inspection boundary that repeats the
same fresh-lease, protected intent and recorded-socket checks as retirement.
It reports only Absent or Retirable and never removes or syncs files. Later
retirement performs fresh checks rather than trusting the observation. Controlled
tests cover preservation of stale publication and rejection of foreign changes;
the privileged SIGKILL fixture now verifies inspection before retirement.
The [expanded privileged gate](https://github.com/skunkie/warper/actions/runs/41568333593)
passes at `a7e3505`, including all four isolated native probes with exit zero,
no timeout and preserved host state. Evidence is under
`target/evidence/phase-1/endpoint-inspection/ci-41568333593/`. The offline recovery CLI still
requires composition with the protected stores and network journal.

An owner-dispatched installed-unit CI gate now exercises the actual source unit
and binaries on a separate disposable GitHub-hosted VM. It checks initial owner
access, explicit restart, SIGKILL/automatic recovery, stop, a subsequent start,
and persistent lock identity. The fixture refuses developer/self-hosted hosts
and existing installations, independently stops the unit/removes owned installed
files and verifies unchanged resolver identity/bytes. It approves no network
configuration; real TUN traffic remains covered by the separate isolated gate.
The [installed-unit gate](https://github.com/skunkie/warper/actions/runs/41568333593)
passes at `a7e3505` with no fixture or cleanup errors; its recorded commands
verify start, restart, automatic crash recovery, stop and independent removal.
The 140-test infrastructure suite also passes. Evidence is under
`target/evidence/phase-1/systemd/ci-41568333593/`.


The actual daemon traffic fixture now repeats kernel TCP/FIN after active
SIGTERM and after SIGKILL/reap with fresh service processes. It checks restored
same-boot Up intent, explicit Disconnect surviving another restart, and original
namespace route/interface state after active shutdown and final retirement.
The [expanded real-process gate](https://github.com/skunkie/warper/actions/runs/41569040009)
passes at `873b053`; the actual daemon result reports exit zero, no timeout
and preserved host state. Its log verifies active SIGTERM cleanup, SIGKILL
recovery, restored same-boot forwarding and persisted Disconnect. Evidence is
under `target/evidence/phase-1/daemon-restart/ci-41569040009/`. Offline administrative recovery,
foreground diagnostics and the final Phase 1 requirement audit remain open.

Stopped-service owner-intent recovery now requires an exclusive, freshly
acquired, never-published runtime lease rather than a synthetic control peer.
It pins/discards only unchanged pending intent and preserves committed policy;
publication permanently prevents offline recovery through that lease. Controlled
tests cover successful discard and refusal after endpoint publication/drop.
Network recovery now also exposes read-only committed-journal inspection with
the same process, boot, interface and route-absence checks as retirement.
Inspection does not change the journal and does not authorize later mutation.
The native owner and crash-recovery fixtures now exercise these boundaries;
the [expanded privileged gate](https://github.com/skunkie/warper/actions/runs/41571094798)
passes at `3a8a5b9`. All four isolated probe results report exit zero, no timeout
and preserved host state. Evidence is under
`target/evidence/phase-1/offline-owner-recovery/ci-41571094798/`.


`warperd recover --inspect` now acquires the actual exclusive stopped-service
lock, validates fixed protected committed/pending stores and reports only
retirement classifications and pending booleans. It starts no service/backend,
accepts no source path and does not rewrite, sync or discard records. Local
process tests reject ordinary users through the native authorization gate, and
output tests distinguish absent from dirty state. The actual daemon fixture now
executes inspection after shutdown and checks committed bytes, inode identity
and modification/change timestamps. The [expanded native CLI gate](https://github.com/skunkie/warper/actions/runs/41571905425)
passes at `6f995b5`; all four isolated probes report exit zero, no timeout and
preserved host state, and the full native build matrix is green. Evidence is
under `target/evidence/phase-1/offline-inspection/ci-41571905425/`.
Offline repair, online recovery, foreground diagnostics and the final Phase 1
requirement audit remain open.


`warperd recover` now retains the complete stopped-service preflight and all
four pending tokens through repair. It retires proven stale publication,
discards only unchanged unpublished intent, resyncs unchanged committed records
and repeats native ownership checks before journal retirement. Committed owner,
configuration and connection intent are preserved, and no backend starts. Owner
resync tests cover directory-sync uncertainty and refusal after publication.
The actual daemon fixture now exercises crash retirement, unsafe later-store
metadata refusal before any intent deletion, dirty inspection, repeated repair
and committed-record preservation. The [expanded privileged CLI repair gate](https://github.com/skunkie/warper/actions/runs/41574350951)
passes at `c3b5721` with exit zero, no timeout and preserved host state; the full
CI matrix is green. Evidence is under
`target/evidence/phase-1/offline-repair/ci-41574350951/`. Online recovery, foreground diagnostics
and the final Phase 1 requirement audit remain open.


Authenticated `warper recover [--inspect]` now uses the serialized native
controller. Inspection reports pending, required and busy flags without needing
ordinary Status reads. Repair refuses actual active/pending/retained network
ownership, validates all stores and replacement budgets before mutation, then
resyncs committed state and refreshes approval/admission only after other repair
steps complete. It preserves accepted intent and starts no backend. CLI tests
cover skipped Status, unknown flags and lost acknowledgement without retry;
actual owner-session/controller tests reject administrative recovery. The daemon
fixture adds idle repair, connected Busy refusal, unsafe later-store validation,
dirty configuration/connection inspection and preserved committed state. Local
checks pass; the [expanded native gate](https://github.com/skunkie/warper/actions/runs/41578551519)
passes at `499451e`, including all four isolated probes with exit zero, no timeout
and preserved host state. The full native build matrix is green. Evidence is
under `target/evidence/phase-1/online-recovery/ci-41578551519/`. Foreground diagnostics and the
final Phase 1 requirement/budget audit remain open.


`warperd run` now imports through the invoking-account materializer and uses
transient in-memory approval with the production Network supervisor. Synchronous
bootstrap validates before mutation, rejects pending state and shares the
service lock; it publishes no control endpoint or managed intent. Signals drain
the engine, preserving signal-observation errors alongside shutdown failures.
Presentation writes occur outside active forwarding, and verbose/debug summaries
contain aggregate counts. Unsupported backend import retains its capability
category through private IPC; ordinary materializers clear inherited capability
sets. Local parsing/authorization/signal tests and full checks pass. The daemon
fixture adds real foreground kernel TCP/FIN, instance exclusion, credential
access denial and preserved managed state. The
[expanded native gate](https://github.com/skunkie/warper/actions/runs/41584198598)
passes at `a681d6a`, with exit zero, no timeout and preserved host state in all
four isolated probes. The full native build/test matrix is green. Evidence is
under `target/evidence/phase-1/foreground-diagnostic/ci-41584198598/`.
The final Phase 1 requirement, platform and budget audit remains open.

## Phase 1 Closure Audit

The [requirement-by-requirement audit](phase-1-acceptance.md) closes the
headless Linux slice against the roadmap, exit criteria and section 8.4.
The final tracing implementation uses the already-locked `tracing` version and
retains at most 64 fixed lifecycle names, no event fields or payloads. It counts
contention/overflow without blocking forwarding and flushes after the command
returns. Desktop log streaming remains Phase 5 work.

The [final implementation gate](https://github.com/skunkie/warper/actions/runs/41597810149)
at `687b293` passes all native build/test jobs, privileged control/TUN/crash/daemon
fixtures and installed-systemd acceptance. All four probe manifests identify that
revision, exit zero, no timeout and preserved host state. The daemon fixture
checks actual lifecycle trace output in service and diagnostic modes as well as
real TCP/FIN, owner/foreign authorization, detached clients, explicit Down,
failed-start rollback, active TERM, KILL/restart, persisted intent and recovery.
The installed-unit result reports no errors. Inspected local artifacts are under
`target/evidence/phase-1/lifecycle-tracing/ci-41597810149/` and
`target/evidence/phase-1/lifecycle-tracing/systemd-ci-41597810149/`.

The resource audit distinguishes payload capacity from control byte admission,
bounded task/channel/native-worker metadata, snapshot/journal limits, operation
history and lifecycle tracing. It does not claim a total RSS cap. Local full
checks and focused tracing coverage/boundary tests pass. Disabled tracing span
callbacks and poisoned-lock defenses are not established by local coverage;
actual network transitions are established by the separate native gate.

No required Phase 1 increment remains open. Phase 2 must implement production
DNS transports, bounded retained lease/cache state, route publication and resolver
integration before claiming DNS discovery. Required SSH/WireGuard/IPv6, macOS
and desktop/release acceptance remain open in their assigned phases. The older
increment notes above record the constraints at those increments; the ledger
and closure audit describe current status.
