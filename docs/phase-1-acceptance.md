<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Phase 1 Acceptance Audit

Scope is the headless Linux slice in implementation-plan section 7, Phase 1,
and its definition of done in section 8.4. This does not close the full release
acceptance contract. The phase ledger remains authoritative for closure.

## Required increments and exits

| Requirement | Implementation and executable evidence | Finding |
| --- | --- | --- |
| Phase 1.1: compiling workspace, core/backends/service, explicit daemon, parser, shared control, thin CLI and checks | Root manifest/lock/toolchain; `warper-core`, `warper-backends`, `warper-service`, `warper-control`, `warper-config`, `warper-cli`; `scripts/check.sh`; native CI build/test jobs | Implemented, including strict default/all-feature checks and native release builds. |
| Canonical examples, migration/error fixtures and configuration behavior | `warper-config/tests/{schema,yaml_fixtures,managed}.rs`, `warper-cli/tests/commands.rs`, `tests/fixtures/configuration/`, `docs/configuration.md` | Offline validation registers the canonical backend schemas independently of narrower executable networking support. Managed import rejects unsupported capabilities before host mutation. |
| Redacted logging | `warper-service/src/telemetry.rs`, executable entry point and shared network supervisor; five focused tests; daemon fixture assertions | Bounded lifecycle tracing is implemented and locally checked. Native daemon and diagnostic trace assertions pass at `687b293`. No live desktop log delivery is claimed. |
| Phase 1.2: contracts, task/cancellation/resource limits, policy, lock, journal and platform driver | `docs/implementation-contracts.md`; core transport/routing; service preflight, relay, native worker, Linux context/transaction/TUN/network/controller modules | Concrete adapters implement the narrow post-feasibility contracts. Retained native work and uncertain cleanup remain owned rather than being reported as success. |
| Linux enrollment and authenticated control independent of GUI | Control runtime/Unix/session/admission modules; controller; actual daemon/CLI fixture; administrative import and installed-unit gates | Native peer checks, initial-user-namespace admission, protected stores and administrative owner enrollment have isolated evidence. No GUI dependency or caller-selected privileged file-read endpoint. |
| Phase 1.3: actual Linux TUN and selected SOCKS5 TCP for static CIDRs | `linux_network_probe`, `linux_daemon_probe`, `linux/{physical,supervised_network,controller_dispatch}` fixture modules | Real controlled kernel TCP reaches the selected SOCKS5 peer, preserves original destinations and FIN, and uses acknowledged journaled capture with physical endpoint protection. |
| Phase 1.4: duplex/FIN, detach, idempotency, authorization, cancellation, failed startup and shutdown | Host/runtime/relay tests; control history/session tests; native controller, supervisor and actual daemon fixtures | Unit fault/boundary tests complement real peers. Detached CLI requests do not own network cancellation; explicit Down and signals retire owned state. Failed starts and crash recovery are checked independently by the harness. |
| Runnable service-manager integration | `packaging/linux/warper.service`, `scripts/systemd_acceptance.py` | Actual installed idle-unit lifecycle, owner control, restart, forced crash, stop/start, removal and resolver preservation have disposable VM evidence. Active traffic is covered separately by private namespaces. |
| Equivalent foreground diagnostics | `warperd run`, `linux::diagnostic`, shared production `Network`; actual daemon fixture | The same forwarding supervisor handles real TCP/FIN. Transient approval holds the instance lock, publishes no control socket, preserves managed intent and stops on signals. |
| Explicit Phase 1 exit | Actual daemon fixture plus supervisor startup rollback fixture | Actual application traffic, failed-start restoration, surviving client exit, explicit Disconnect and unauthorized-control refusal all have native evidence. The final tracing gate also passes; no required Phase 1 increment remains open. |

The [foreground diagnostic run](https://github.com/skunkie/warper/actions/runs/41584198598)
at `a681d6a` has a green native build/test matrix and all four privileged control,
TUN, crash and daemon probe results with exit zero, no timeout and preserved host
state. Earlier material gates and artifact locations are indexed in
[the phase ledger](implementation-status.md). Raw local copies are under
`target/evidence/phase-1/`; CI artifacts identify the exact tested revisions.
The [tracing run](https://github.com/skunkie/warper/actions/runs/41597810149)
at `687b293` independently passes the full matrix, all four privileged probes,
and installed-systemd acceptance. Its inspected daemon log contains real
starting/connected/stopping/retired and failure events, with both executable
modes checked by the fixture. Probe manifests confirm the exact revision,
exit zero, no timeout and preserved host state. Installed-unit results contain
no errors. Local copies are under
`target/evidence/phase-1/lifecycle-tracing/{ci-41597810149,systemd-ci-41597810149}/`.

## Resource ownership audit

- `preflight::Plan::prepare` uses checked arithmetic for stack/runtime, relay,
  TUN I/O, setup and credential payload capacity, rejects budgets before network
  mutation and caps effective flows at the stack's supported slots. Boundary
  tests accept the exact budget and reject one byte less. Configuration allows
  at most 64 backends and 4096 capture prefixes in this slice.
- Control admission limits clients and retained maximum-size requests against
  a separate byte budget. Reply reservations are charged per client. Old frames
  keep their quota through reconfiguration and detached replies; a new admission
  owner cannot erase old charges. Daemon join metadata independently caps at 64
  client tasks, with 64-slot command/event channels and three retained notices.
- Native worker admission caps at four jobs. The control actor and active
  network supervisor each retain their reservation. Timeouts report uncertainty
  and retain work for a join rather than treating an observer timeout as
  cancellation of blocking kernel work.
- Operation history caps at 4096 records; eviction protects active operations
  and revision/instance fences reject stale replay. Managed encoded snapshots
  cap at 1 MiB, network journal payloads at 64 KiB. Approved configuration
  replacement is Busy while a supervisor retains its lease.
- Native inventories cap routes, rules and netlink message/datagram sizes;
  excessive or lost observations fail closed. Packet/runtime queues, relay
  workers and ingress/egress storage have independent fixed/admitted limits.
  Exhaustion counters and fixed histograms avoid per-packet measurement growth.
- Lifecycle tracing adds 64 static event names and a saturating loss counter;
  it retains no fields or payloads. Contention drops diagnostics without waiting.
  Output happens after the command returns, never on packet workers.

These are explicit ownership/admission bounds, not a total process RSS cap.
Allocator overhead, bounded parsed snapshots, kernel queues and task metadata
are distinct from the configured payload budget. The packet-pump and daemon
workload artifacts record their own conditions, byte counts, timing, CPU and
peak memory. The packet-pump gate measures pump drops; the daemon workload
explicitly labels kernel drops unmeasured. Neither is a general performance
claim or an acceptance result for future backends.

## Acceptance IDs and platform limits

| IDs | Phase 1 coverage | Remaining release coverage |
| --- | --- | --- |
| INFRA-01–03, CFG-01–02 | Repository harness tests, native checks and canonical parser/CLI fixtures | Keep synchronized as later capabilities are added. |
| NET-01, NET-04 | Static policy, selected backend metadata, CIDR precedence and physical endpoint protection | Dynamic DNS discovery, mixed routing and lease transactions in Phase 2. |
| NET-05–06 | Defined unsupported UDP behavior in the TCP-only slice, bounded TCP/FIN, stalled peers, cancellation and fixed adapter MTU | Production WireGuard UDP/rekey, full IPv6 and other required backends in Phase 3. |
| NET-07–08 | Journal mutation faults, foreign/change preservation, exclusive lock, native startup rollback, signals, KILL/restart and protected transport invalidation | DNS/native macOS integration and remaining release reboot/platform cases. |
| NET-09 | Actual CLI detach/restart, explicit Down, shared foreground engine and bounded observers | GUI lifecycle/log streaming in Phase 5. |
| UX-01–03 | Linux peer authentication/enrollment, malformed framing, lifecycle fences, retained operations, managed ordinary-user import, default-off fresh boot policy, same-boot restoration, persisted Down and explicit recovery | Native macOS identity/approval, desktop Explain/events, sleep/wake and full release platform scenarios. |
| UX-04 | Linux source systemd install/owner/restart/removal gate | Public packaging, updates and macOS signed/notarized distribution. |
| NET-02–03, NET-10–12 | Contract/feasibility models only | Phase 2 production DNS acceptance; not closed by Phase 1. |
| UX-05 | Not run | Required native no-paid-account macOS integration in Phase 4; Linux evidence cannot substitute. |

Native compile/unit/release jobs cover Linux x86-64, Linux ARM64 and macOS ARM64.
Privileged networking and installed-systemd acceptance currently cover Linux
x86-64 only. ARM64 privileged acceptance and macOS native networking are not
claimed. Later-phase capabilities return explicit unsupported results rather
than silently choosing direct transport. No host's normal resolver is changed
by Phase 1 networking or tests.

## Definition of done

1. Observable behavior is implemented in real adapters and executable service
   paths. Later-phase features are explicitly unavailable; no placeholder
   success is used for a required Phase 1 operation.
2. Configuration, managed import, control and driver contracts describe current
   behavior and limits. Exact toolchain/dependencies are locked. The Linux guide
   describes installation/recovery; desktop forms remain a future product
   contract with no YAML upload/editor.
3. Meaningful failure, boundary, cancellation and cleanup tests accompany each
   ownership boundary. Native fixtures use controlled peers and independently
   verify cleanup, not only exit status. New tracing has local boundary/coverage
   evidence and independent native daemon/diagnostic acceptance.
4. Full local checks passed for the tracing implementation; subsequent test-only
   refinements passed strict Clippy and focused coverage tests. CI independently passes
   the implementation commit's full native matrix and privileged fixture results.
5. Typed/redacted errors and bounded ownership are explicit. Workspace policy
   forbids new unsafe Rust. There is no GUI/root webview. Kernel filesystem
   stalls and unavailable native platforms are documented limitations, not passed
   checks.
6. The durable ledger and this audit identify evidence, limits and the next gate.
   All required Phase 1 increments and exits have evidence. Phase 1 is closed for
   the stated Linux slice; Phase 2 DNS transactions are the next phase. The
   broader release gates and unrun platform cases above remain open.
