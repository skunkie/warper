<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Acceptance Contract

These stable IDs identify required observable behavior. This document
defines expected results, not a report of completed runs. Follow the
[implementation plan](implementation-plan.md) and
[phase ledger](implementation-status.md) for prerequisites and status.

## Infrastructure

- **INFRA-01:** planning mode emits `rust=false`; orphaned tracked/untracked
  Rust sources/manifests fail; a root manifest requires nonempty regular
  lockfile and exact toolchain with formatting/lint components. Ignored
  generated files do not accidentally enable a workspace.
- **INFRA-02:** actionlint/ShellCheck findings in workflow and composite
  scripts fail checks. Composite findings identify original file positions;
  malformed layouts and missing linters do not become successful skips.
- **INFRA-03:** the local harness and CI cover the same applicable checks.
  Licensing/workflow checks run before Cargo exists; Rust quality/native jobs
  run after workspace introduction. Native build success is not reported as
  privileged networking acceptance.

## Configuration

- **CFG-01:** all canonical examples pass offline validation; defaults,
  normalized domain precedence, backend capabilities, migration errors,
  field paths, exit codes, and redaction match the configuration contract.
  No validation command mutates networking or exposes secrets.
- **CFG-02:** path/home selection, explicit false/zero distinctions, invalid
  CIDRs/keys, duplicate mappings/domains, inconsistent identities, partial
  credentials, and routing-mode conflicts have deterministic fixtures.

## Networking and Lifecycle

- **NET-01:** static and DNS-discovered flows reach the intended controlled
  peer with original destination metadata. Two backend instances dispatch
  independently. Physical captures verify endpoint exemptions and selected
  transports.
- **NET-02:** split/global DNS modes work; unmatched forwarding cannot loop
  through a local stub. Selected-backend timeouts, negatives, and unsupported
  operations do not query a direct resolver or choose a different backend.
- **NET-03:** no dynamic positive answer precedes internal handler
  publication, acknowledged kernel routing, and committed ownership. Delayed,
  failed, uncertain, and cancelled operations produce consistent rollback;
  parsed requests receive SERVFAIL when required routing cannot commit.
- **NET-04:** longest-prefix policy, static/mixed modes, shared-IP conflicts,
  alias-chain processing, A/AAAA answers, lease expiry, and active-flow
  retention follow the contract. Cached/TTL-ignoring clients remain an
  explicitly documented coverage limit.
- **NET-05:** WireGuard UDP preserves datagram boundaries and handles
  association expiry. Required TCP-only backends reject/drop unsupported UDP
  predictably. If SOCKS5 UDP is introduced, control-channel/relay lifecycle
  and unsupported fragmentation are also tested.
- **NET-06:** full-duplex transfers, half-close, stalled peers, bounded
  buffering, MTU/ICMP behavior, IPv6, cancellation, and sustained WireGuard
  traffic across handshake/rekey work within declared adapter limits.
- **NET-07:** failure after each startup mutation, graceful signals, SIGKILL,
  backend loss, and restart/reboot reconciliation preserve foreign state and
  restore owned changes where applicable. The independent harness verifies
  cleanup and joins application/peer tasks rather than trusting exit status.
- **NET-08:** a second instance cannot mutate/recover a live owner. Changed
  routes, DNS, interface identities, or network services cannot silently
  redirect physical transports into the TUN or cause blind recovery deletion.
- **NET-09:** foreground diagnostics and service-controlled networking use
  equivalent routing semantics. GUI/CLI detach, crash, or restart does not
  disconnect a session or start another TUN. Explicit Disconnect/service
  shutdown performs owned cleanup; slow observers cannot block forwarding.
  Classification remains optional telemetry.
- **NET-10:** zero- and short-TTL address answers keep their original/aged
  DNS TTL and are not cached beyond it. With a controlled clock, the first
  connection within `dns_route_grace_ms` uses the selected backend even after
  DNS freshness expires. Queued/partial output keeps pending references;
  handoff renews retention atomically, cancellation creates no fresh lease,
  concurrent successful answers can extend it, and flow closure does not
  discard unexpired grace. Final reference expiry retires owned state.
- **NET-11:** matched HTTPS/SVCB answers cover every exposed service endpoint
  before release, including hints used before delayed A/AAAA lookups finish,
  alternate priorities, related Additional addresses, AliasMode fallback,
  CNAMEs, and effective `.` target semantics. Verify physical captures for
  same-backend follow-up resolution in split/global modes. Unconfigured or
  cross-backend target names, disabled/unsupported families, static coverage
  gaps, loops, malformed data, dependency timeouts, address/query budgets,
  and route failure return SERVFAIL with no unsafe positive response or
  physical DNS fallback. Unrelated records cannot create routes. Exercise
  truncated UDP and TCP retry through the same endpoint gate.

- **NET-12:** with small injected global lease/cache/byte budgets, send many
  distinct names with long TTLs mapping to one IP/backend. Counts and retained
  allocations stay within budget even while kernel route count remains one.
  New discovery returns SERVFAIL before mutation/publication when required
  lease state cannot fit. Same-key renewals coalesce, and repeated renewals
  cannot accumulate unbounded stale timer nodes. Cache eviction leaves
  unexpired route/grace/flow ownership intact; optional cache insertion may
  be skipped. Concurrent reservations, partial failure/cancellation, and
  expired-state reclamation release exactly their own charges. Exercise both
  entry and byte exhaustion, positive/negative caches, and TTL-zero bypass.

## Service and Desktop UX

- **UX-01:** actual OS peer identity and enrollment/administrative policy
  protect local control. Unauthorized users, spoofed UID/PID/path/bundle IDs,
  malformed/oversized messages, generic file/shell requests, and incompatible
  API versions fail before mutation or metadata disclosure. The webview has
  only scoped Tauri capabilities and never runs as root. Test native macOS
  peer-signature verification; a claimed app identity is not authentication.
- **UX-02:** control availability, OS approval, session readiness, degraded
  state, recovery required, and stale observations remain distinguishable.
  Duplicate operations are idempotent, configuration generations are checked,
  and wait timeout/client loss does not cancel an accepted operation. Slow
  event consumers resynchronize within bounded buffers. Explain is read-only.
- **UX-03:** import/validation does not mutate networking. Approved normalized
  configuration/credentials are stored atomically without privileged reads
  of caller-selected paths. Active-session installation returns Busy. Reboot
  uses managed state without a logged-in home; fresh-boot autoconnect defaults
  off, same-boot recovery honors desired intent, and explicit Disconnect
  survives service restart. Test sleep/wake, failure, and multiple clients.
- **UX-04:** the macOS app contains the GUI and helper, both identified by the
  supported release-signing policy. On a clean macOS 13+ system, test service
  approval, denial/revocation, ordinary-user control, GUI quit, install location,
  signed/notarized download, update/version mismatch, explicit cleanup and
  unregistration, and reboot. Local/ad-hoc builds establish development evidence
  only. Linux packages require equivalent systemd/owner/uninstall tests.
- **UX-05:** local macOS bundled integration works without paid membership,
  an Apple-issued developer signing identity, or notarization credentials.
  On a disposable macOS 13+ system, verify the packaged GUI/helper signatures
  are ad-hoc, approve/register the actual bundled daemon, administratively
  enroll the owner and exact build identities per ADR 0005, and exercise
  authenticated status and Connect/Disconnect with controlled peers. GUI
  quit/reopen retains the session. Reject another user, an unapproved
  same-user executable, spoofed roles/identifiers, tampered code/resources,
  invalid/writable/symlinked manifests, and an impersonating helper; no secret
  or privileged request reaches the latter. Rebuild/re-sign: old pins reject
  the changed build until explicit stop/re-enrollment/re-registration, old
  connections lose access, and the newly enrolled build reconnects. Verify
  cleanup/unregistration and that production artifacts reject the development
  feature, manifest, and launch mode. A paid-signed run, standalone daemon,
  or UID-only authorization bypass cannot pass this gate. Native-spike
  auth results are partial evidence until the real service/session cases
  pass; record unrun cases explicitly.

## Environment and Evidence

Use synthetic domains, credentials, and local SSH/SOCKS/WireGuard/DNS peers.
Do not depend on live services or developer state. Linux acceptance uses a
disposable VM or network namespaces plus private mounts/state and a dedicated
resolver/bus. A network namespace alone is insufficient. macOS system
integration requires a dedicated VM/runner. Do not mutate the host resolver.

Each run must identify the tested revision/worktree, toolchain/dependencies,
OS/architecture, isolation, peer setup, exact commands, assertions, and
cleanup observations. Distinguish passed, failed, not run, and unsupported.
Place raw evidence under ignored `target/evidence/` or CI artifacts and
summarize material decision consequences in ADRs. Keep routine run history
in CI logs or commit messages.

A cross-platform release requires the specified Linux/macOS networking and
recovery evidence, all required backend capabilities, and applicable feature
checks. Optional work and mock-only tests cannot substitute for those gates.
