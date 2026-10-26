<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Implementation Plan: `warper` (Rust Alternative to WARP)

## 1. Scope and Compatibility Contract

Build a Rust networking service that selectively routes host traffic through SSH, SOCKS5, and WireGuard, with DNS-based route discovery, explicit CIDR routes, and a normal-user Tauri desktop client. Ship the client and service together in one macOS app bundle; retain a thin CLI for diagnostics and automation. The reference implementation is `~/projects/warp`. Deliver Linux first, then macOS; both platforms must pass actual networking tests before cross-platform support is claimed.

This is selective IP routing. DNS rules discover destination IPs; subsequent packets generally contain no domain identity. Shared IPs, existing DNS caches, application-managed DNS/DoH, and connections made before discovery limit domain-based routing. Do not advertise a system-wide kill switch or general leak prevention. Document these limits and the explicit CIDR alternative.

### 1.1 Reference Behavior and Intentional Changes

| Area | Original implementation | `warper` requirement |
| --- | --- | --- |
| Configuration | `~/.warp.yaml`, resolved through `SUDO_USER` | Preserve YAML for import/offline validation and foreground debugging; the service reads an approved managed snapshot at boot |
| SSH | Password authentication, TCP forwarding, DNS over forwarded TCP; insecure host-key acceptance | TCP forwarding and DNS over TCP; add key authentication and mandatory known-hosts or pinned-key verification |
| SOCKS5 | Optional username/password, TCP forwarding and DNS over TCP | Preserve TCP behavior; native UDP association is a separately tested extension |
| WireGuard | Userspace WireGuard device plus a userspace stack supporting TCP/UDP dialing | Preserve TCP/UDP and DNS through a userspace tunnel, with no secondary kernel WireGuard interface |
| Static `ips` | Installed at startup; any nonempty `ips` list suppresses DNS-derived routes for that backend | Preserve this default; expose an explicit routing-mode override for mixed routes |
| Domains | First matching backend; raw suffix comparison | Use normalized, label-boundary matching and longest matching domain; reject duplicate normalized domain assignments |
| IPv6 | YAML field is unexported; DNS-derived route extraction only handles A records | Honor `ipv6`; test IPv6 end to end and extract AAAA when enabled |
| DNS mode | Per-domain resolver configuration, or global forwarding with `serve_dns` | Preserve both modes with platform-specific installation, upstream capture, and rollback |
| Platform setup | Mostly macOS commands despite Linux build artifacts | Implement and validate separate Linux and macOS drivers |
| CLI/UI | Terminal UI owns the network lifetime; `--verbose` selects headless operation | Tauri GUI and thin CLI control a persistent service; quitting a client leaves networking active, and Disconnect is explicit. Legacy headless aliases apply only to foreground diagnostics |

Source anchors: `cmd/config.go`, `internal/service/service.go`, `internal/protocol/{ssh,socks5,wg}/impl.go`, and `internal/utils/sys/` in the reference tree. Turn the table into fixtures and acceptance cases before implementation. Preserve documented inputs where safe; document the host-key requirement, matching changes, and rejection of previously accepted invalid configurations as migration changes.

### 1.2 Initial Support Matrix

| Backend | TCP | UDP | Upstream DNS transport |
| --- | --- | --- | --- |
| SSH | Required | Unsupported in initial release | Length-framed DNS over a forwarded TCP channel |
| SOCKS5 | Required | Optional follow-up via native UDP ASSOCIATE | Length-framed DNS over SOCKS CONNECT |
| WireGuard | Required | Required | UDP inside the tunnel, with TCP fallback on truncation |

Unsupported UDP must produce a defined rejection/drop and a metric; never fall back to direct transport. QUIC selected for SSH or a TCP-only SOCKS server will not work through that backend. DNS over TCP remains available for those backends.

### 1.3 Required Release Scope and Optional Work

The first cross-platform release requires SSH TCP with host verification, SOCKS5 TCP, WireGuard TCP/UDP, captured IPv4/IPv6, static/dynamic/mixed routing, split/global DNS, tested Linux/macOS drivers, transactional recovery, headless operation, and the Tauri desktop/service UX. The public macOS release targets default Gatekeeper installation through Developer ID signing/notarization and an approved bundled helper with tested lifecycle. Local development can use an explicit ad-hoc signing setup without a paid identity or notarization. A Linux-only milestone may be delivered earlier but does not complete the cross-platform objective.

SOCKS5 UDP, SSH agent authentication, animation, protocol classification, capability-only operation, and additional DNS-manager integrations are optional follow-ups. They cannot replace required behavior or acceptance evidence. Self-forking daemonization, live networking hot reload, a terminal UI, Windows, a system-wide kill switch, and custom cryptography are outside the initial scope. Unsupported features must be explicit in capabilities, diagnostics, and documentation.

## 2. Engineering Approach and Architecture

### 2.1 Dependency and Stack Feasibility Gate

Do not commit to `tun2proxy` as a generic flow adapter. The inspected upstream uses `ipstack`; its public API centers on running a configured proxy. Neither that API nor a `smoltcp` wrapper is assumed to expose all required interception and dialing operations.

Evaluate pinned versions of `ipstack`, `netstack-smoltcp`/`smoltcp`, and any other justified candidate through small executable prototypes. Record license, maintenance, Rust version, supported platforms, transport semantics, and the exact APIs used. Avoid a fork or a local loopback SOCKS bridge unless the decision explicitly budgets for its maintenance or extra hop.

Two separate capabilities must be proven:

1. **Host-facing interception:** TUN packets become accepted TCP streams or UDP datagrams with original source/destination metadata; responses become packets back to the host. Dispatch two destinations to different backend instances. Verify FIN/half-close, cancellation, datagram boundaries, IPv4/IPv6, and bounded buffering.
2. **WireGuard-side dialing:** an active userspace IP stack creates outbound TCP/UDP sockets using the configured tunnel address. Its outbound packets enter BoringTun, and decrypted packets return to that stack. Verify real TCP and UDP exchange with a controlled WireGuard peer.

These are distinct stack roles and may need distinct adapters or stack instances. A passive transparent interception API is not evidence of outbound socket-dialing support. If either prototype fails, revise the stack choice before production routing or UI work.

### 2.2 Workspace and Dependency Direction

Use a Cargo workspace with independent `warperd` service, thin `warper` CLI, and Tauri desktop executables. Start with the modules needed by each phase; add control/client packages only when their real responsibilities are implemented. The target layout is:

```text
warper/
├── Cargo.toml                 # Workspace, exact toolchain and shared lints
├── Cargo.lock
├── AGENTS.md
├── LICENSE
├── README.md
├── docs/                      # Plan, contracts, UX, acceptance, status and ADRs
├── crates/
│   ├── warper-core/src/       # Config, backend contracts, TUN, DNS, routes, sys
│   ├── warper-proto/src/      # SSH, SOCKS5 and active WireGuard stack adapters
│   ├── warper-control/src/    # Redacted DTOs, operation/version/auth contracts
│   ├── warper-service/src/    # warperd: supervision, IPC, networking ownership
│   └── warper-cli/src/        # Thin warper control/validation/diagnostic client
├── client/
│   ├── src/                  # Desktop presentation and client state
│   ├── src-tauri/            # Normal-user native bridge and app packaging
│   └── pnpm-lock.yaml        # Introduced with the real frontend package
├── tests/                    # Config, control and isolated networking cases
├── scripts/                  # Stage-aware checks and future feasibility probes
└── .github/workflows/ci.yml
```

Dependency direction: protocol implementations depend on core contracts; the service constructs and supervises them. Shared control types are independent of privileged implementation and secret-bearing core configuration. GUI/CLI clients use the control contract; neither owns a network engine. Core imports neither backend implementations nor Tauri. Keep WireGuard-specific stack management in the backend, sharing lower-level adapters only where their APIs match.

### 2.3 Rust Conventions and Dependencies

- Use idiomatic Rust naming and explicit ownership, rather than treating a list of RFC numbers as an API design specification.
- Use Tokio for asynchronous I/O, timers, cancellation, and supervised tasks; avoid blocking the runtime with platform commands or stack polling.
- Use typed library errors (`thiserror`) and contextual application errors (`anyhow` or equivalent).
- Use `serde` with a maintained YAML parser selected and pinned during setup. Validate before privileged mutations; reject unknown fields with useful diagnostics.
- Use `tracing` with bounded, nonblocking UI log delivery and secret redaction. Diagnostic and panic output must not print credentials or private keys.
- Candidate dependencies include `hickory-proto`, `rtnetlink`, `russh`, `boringtun`, and a SOCKS5 client; finalize versions/features after the prototypes and compatibility review.
- Configure service and CLI targets explicitly as `warperd` and `warper`; the separate Tauri target is the primary desktop client. Commit lockfiles and document supported Rust/OS versions, native GUI dependencies, and managed service packaging.

Protocol references include SOCKS5 RFC 1928/1929, DNS RFC 1034/1035 and relevant transport/IPv6 extensions, SSH RFC 4251–4254, and the WireGuard protocol specification. Libraries implement wire protocols; application tests must still establish framing, authentication, lifecycle, and routing behavior.

### 2.4 Agent Handoff and Implementation Discipline

Read and follow [AGENTS.md](../AGENTS.md). The [configuration contract](configuration.md) defines accepted YAML/CLI behavior; [implementation contracts](implementation-contracts.md) define the interface decisions to close after feasibility. Use the [ADR index](adr/README.md), [development guide](development.md), and stable IDs in the [acceptance contract](acceptance.md). Keep the [phase ledger](implementation-status.md) current with gate status and evidence locations. These documents are specifications, not claims that the runtime already exists.

Infrastructure CI is available during planning: licensing, workflow/composite-action lint, shell lint, and executable harness tests. The tested repository-stage detector activates Cargo jobs only after a valid root workspace, lockfile, and exact toolchain exist; it rejects orphaned Rust sources instead of concealing them. See [ADR 0001](adr/0001-development-workflow.md). The stack-selection [ADR 0002](adr/0002-network-stack.md) remains proposed until the Phase 0 traffic gates pass. Keep routine run history in CI logs or commit messages and raw artifacts under ignored `target/evidence/`.

[ADR 0004](adr/0004-desktop-service.md) defines the service-first Tauri UX and bundled macOS helper. [ADR 0003](adr/0003-dns-endpoint-routing.md) defines DNS route grace and HTTPS/SVCB endpoint routing. It accepts the policy, while its implementation and acceptance gates remain pending.

[ADR 0005](adr/0005-macos-development-authentication.md) defines the
administrator-enrolled exact-build authentication mode for local macOS use
without a paid signing identity. UX-05 must verify it independently of the
Developer ID/notarized distribution tests.

Deliver small compiling increments with a working behavior and its failure paths. Create modules when needed rather than scaffolding every planned file. Advance automatically after each verifiable gate passes. If an environment-dependent check cannot run, record it as not run and continue independent work without presenting the affected gate as passed.

Material deviations require a decision record plus synchronized changes to the contract, plan, relevant fixtures/tests, and progress ledger. Do not silently weaken the support matrix, replace real forwarding with a mock, or describe an unsupported stub as a completed feature.

## 3. Configuration and Backend Contracts

### 3.1 Configuration and Privileges

[docs/configuration.md](configuration.md) is the canonical field/default/validation specification. Complete schema examples are [SSH](../examples/ssh.yaml), [SOCKS5](../examples/socks5.yaml), and [WireGuard](../examples/wireguard.yaml). Register these examples and compatibility/error fixtures in executable parser/CLI tests during Phase 1. No parser or CLI is implemented by this planning document.

- Import, offline validation, and foreground diagnostics use explicit `--config` or the invoking user's `~/.warp.yaml`, with validated identity/path handling. The installed service reads a protected managed snapshot and never relies on a logged-in home or `SUDO_USER` at boot. Ordinary control clients cannot redirect it to arbitrary files.
- Preserve `tunnel.name`, `tunnel.ip`, `tunnel.serve_dns`, `protocols`, `ipv6`, and existing backend keys. Add optional stable backend IDs, MTU, timeouts, SSH port/key/host-trust settings, and routing mode. Provide complete example configurations.
- Routing mode per backend: default to `static` when `ips` is nonempty and `dynamic` otherwise; an explicit `mixed` mode enables both. Reject contradictory modes and document migration. Domain queries still use their selected backend's DNS in static mode, without adding discovered routes.
- Require exactly one backend per protocol item and at least one usable backend. Validate addresses, normalized domains, CIDRs, overlapping assignments, key lengths, endpoint syntax, MTU bounds, authentication combinations, and tunnel address/subnet conflicts. IPv6 settings must agree with available backend tunnel addresses.
- A backend with domains must have explicit DNS upstreams in the initial release. Replace the original SSH remote `scutil` discovery with a documented migration diagnostic; do not assume the SSH server runs macOS.
- The service alone performs privileged network setup. Enrollment/configuration installation uses platform administrative authorization; normal GUI observation and Connect/Disconnect use the enrolled owner's authenticated local API. Before changing anything, preflight TUN access, route permissions, DNS integration, journal ownership, and backend trust.
- Treat Linux capability-only operation as a separate acceptance target. `CAP_NET_ADMIN` can authorize network operations but does not establish D-Bus/Polkit authorization for DNS changes. Document the required policy or privileged helper after testing it. Do not claim that `setcap` alone enables the whole application.

### 3.2 Transport and Lifecycle Interfaces

Define backend-neutral contracts before implementing backends:

- Stable backend ID, advertised address families and TCP/UDP capabilities, health, and limits.
- TCP connection creation returns asynchronous read/write halves with correct half-close and destination metadata.
- UDP uses explicit datagram send/receive operations with peer addresses and preserved message boundaries; never model it as an unrestricted byte stream.
- DNS forwarding uses those transports through a shared DNS transport layer, with per-request deadlines, framing, and typed errors.
- All connection setup and operations support cancellation, bounded buffering, idle/setup timeouts, and resource limits. Bound total flows, UDP associations, DNS requests, pending route operations, and logs.
- Backend startup, shutdown, and reconnect are explicit supervised operations. Use bounded retries with backoff and jitter; authentication and trust errors fail clearly. Never silently change backend or retry application payload after it may have been delivered.
- Existing flows retain their selected backend until termination. New flows use the current committed routing snapshot. Unknown TUN destinations and unsupported transports fail explicitly without direct fallback.

SSH must verify the server against approved imported host-trust material or an explicit pinned key before authenticating; missing/changed trust fails with instructions for configuring trust. Do not automatically accept unknown keys. Define password, encrypted private-key, and optional agent handling without exposing secrets.

SOCKS5 UDP, when implemented, must maintain the controlling TCP association, handle relay addressing and expiry, and reject unsupported fragmentation. Server capability failures cannot redirect datagrams outside the proxy.

### 3.3 Post-Feasibility Contract Gate

After stack selection, close the relevant decisions in [docs/implementation-contracts.md](implementation-contracts.md) before production implementation depends on them. Record concrete Rust types/signatures and source links for accepted flows, TCP/UDP transport, backend capabilities, DNS requests, stack adapters, route-driver transactions, physical egress, supervision, and metrics. Include ownership, cancellation, deadline propagation, resource accounting, error categories, and compile-checked usage.

The initial slice only needs its applicable interfaces, but later features must extend the contracts before introducing dependent implementations. Define the route transaction state machine, uncertain ACK reconciliation, multi-address rollback, and flow admission during commit. Keep third-party stack types behind adapters. This gate is validated with code and failure-injection evidence, not prose alone.

## 4. Packet Handling, DNS, and Routing

### 4.1 TUN and WireGuard Packet Loops

- Create a nonpersistent, owned TUN/utun interface and use the actual returned name/index. Start with a host-facing MTU of 1280; make it configurable only within the chosen stack/platform limits. Derive the WireGuard inner MTU from the outer path and encapsulation overhead; do not reuse an arbitrary 1480 default.
- Ensure the TUN owns a reachable local DNS address. Dispatch DNS addressed to that virtual endpoint within the userspace stack. Host-facing port 53 does not require a kernel listening socket if interception is entirely in the stack.
- Drive stack polling by readiness and next timer deadline, with bounded queues and fair scheduling. Test full-duplex TCP, half-close, UDP boundaries, large transfers, retransmissions, fragmentation/MTU behavior, and IPv6 ICMP behavior supported by the chosen stack.
- WireGuard owns an active userspace stack configured with its tunnel addresses and routes, a physical UDP transport, and a BoringTun tunnel state machine. Pump packets in both directions, service handshake/rekey/keepalive timers, drain pending network output, and validate accepted peer/address policy.
- Resolve and protect physical transport endpoints before enabling capture routes. Handle endpoint changes, reconnects, network changes, cancellation, and shutdown without leaking stack tasks or sockets. Define which operations the selected libraries provide and which adapters warper must implement.

### 4.2 DNS Selection and Forwarding

- Normalize configured domains and query names consistently (case, terminal dot, and documented IDNA conversion). Match exact domains or subdomains at label boundaries: `example.com` matches `a.example.com`, not `badexample.com`.
- Choose the longest matching configured domain; reject duplicate normalized assignments across backends. Once selected, that backend owns the request. Timeout, NXDOMAIN, and NODATA do not trigger a query to a different backend or public DNS.
- Implement UDP DNS and length-framed TCP DNS, including partial reads, multiple requests per TCP connection, EDNS size limits, truncated-response TCP fallback, response ID/question validation, malformed-packet handling, and bounded timeouts.
- Process A/AAAA records belonging to the requested answer and validated alias chain, including bounded CNAME follow-up where needed. For HTTPS/SVCB, also inspect the complete reachable service-binding endpoint set, as specified below. Do not inject arbitrary unrelated answer/additional records. Preserve response codes and valid negative answers.
- When `ipv6: false`, return a documented NODATA response to AAAA requests with no false authoritative/authenticated assertion. Reject explicit IPv6 capture configuration in this mode. This DNS policy does not disable host IPv6 or cover cached addresses.
- For unmatched queries in `serve_dns` mode, use explicitly configured direct upstreams or real upstreams captured from the platform before DNS changes. Never forward to the TUN DNS endpoint or a local stub whose new policy routes the request back to warper. Fail preflight if no loop-free upstream path can be established.
- Bootstrap backend endpoint names before installing DNS policy, using the preserved physical resolver path. Refresh them through that path and install transport exemptions before switching endpoints.
- Route installation failure returns SERVFAIL for a dynamic answer; never return that answer and allow the caller to proceed as if routing succeeded.

#### HTTPS/SVCB Endpoint Discovery

- Parse both record types using the chosen DNS library and RFC 9460 semantics. Follow CNAME and AliasMode dependencies with loop detection and the configured total budgets. ServiceMode `TargetName: .` uses the record's effective owner; AliasMode `.` denotes unavailable service and must not become an address target. Respect the protocol mapping for underscore/port-prefixed names and preserve service parameters rather than treating these records as CNAMEs for every query type.
- All non-root dependency names and effective targets must already be covered by configured domain rules whose winning backend is the original request's backend. Resolve every permitted dependency through that backend within the original request deadline. Reject unconfigured/cross-backend targets with SERVFAIL and a diagnostic identifying the missing domain policy. Do not install learned resolver domains or rely on the client resolving a foreign target through physical DNS; this restriction is required in split DNS mode.
- Before releasing a positive response, enumerate every client-usable address exposed by reachable service records: IPv4/IPv6 hints, relevant Additional A/AAAA records, and addresses from endpoint lookups. Cover all advertised alternatives/priorities, not only the preferred endpoint. Obtain missing target addresses through backend A/AAAA queries; do not assume the client waits for them before using hints. Include applicable AliasMode fallback endpoints. Unavailable-service records with no endpoints preserve their valid response semantics.
- Associate every address with the selected backend and the dependency path that justified it. Hint lifetime comes from its containing service record and aliases; resolved-address lifetime also includes the address chain. Apply shared-IP/static-route conflicts, response grace, and the same acknowledged route commit as ordinary address answers. Static mode requires existing winning static coverage for every exposed endpoint; mixed/dynamic modes may create routes.
- Malformed or ambiguous endpoint data, unavailable address families, dependency failures, budget exhaustion, and any uncommittable exposed endpoint fail the whole response with SERVFAIL. An IPv6 hint/related endpoint cannot pass unchanged when IPv6 capture is disabled. Do not hide unsafe endpoints by changing signed records, discard records to evade validation, switch backend, or forward a partially prepared answer. A valid negative dependency can be final only when no passed-through address depends on it; hints never bypass target-name/backend validation.
- If a size-limited UDP response is truncated, do not expose an unprepared endpoint in its retained records; TCP retry uses the same gate. A response containing only unrelated service data must not create routes or expand domain policy. Keep unmatched direct DNS forwarding behavior unchanged; its records do not become tunnel-discovered routes.

### 4.3 Route Selection and Commit Ordering

Maintain separate backend policy, DNS leases, active-flow bindings, and kernel capture routes. A prefix trie implements lookup; it does not define policy by itself.

| Conflict | Initial policy |
| --- | --- |
| Overlapping static CIDRs for different backends | Longest prefix wins; equal prefix assigned twice is a configuration error |
| DNS address covered by a static route for another backend | Return SERVFAIL and report the conflict; preserve the explicit static assignment |
| Same discovered address requested by different backends | Keep the current owner while its leases or active flows retain the address; reject the conflicting dynamic answer with a diagnostic |
| Multiple DNS names using an address through the same backend | Share one kernel route; distinct logical lease keys consume the global DNS-state budget, and repeated renewals of the same key coalesce |
| Existing foreign kernel route at the prefix warper needs | Fail or report an explicit conflict; never silently replace it |

Install static capture routes before enabling system DNS policy. For a new dynamic answer, serialize updates through one route manager:

1. Validate the answer, address ownership, policy, and transport exemptions.
2. Record recoverable intent and publish the internal destination-to-backend mapping before making its kernel route usable. Concurrent flows must never observe a capture route without a handler.
3. Add the capture route through the platform driver and await success/acknowledgement; record ownership and the committed journal state. Handle duplicate/concurrent additions idempotently.
4. Reserve a pending-response reference for every required route before making output available. Return the DNS answer only after all required addresses are committed. At host handoff, atomically exchange the pending references for leases covering the remaining dependency TTL or configured route grace, whichever is longer. If output stalls, recheck coverage before handoff within the original deadline. On failure, release only this response's reservations/changes without removing other leases or flow references; return SERVFAIL where a response can still be sent.

Linux uses Netlink acknowledgements; macOS uses checked driver operations. Correct ordering establishes the DNS-answer invariant, independent of command latency. DNS clients with previously cached answers fall outside that invariant.

Keep DNS freshness and route retention separate. Never inflate a wire/cache TTL or reuse a zero-TTL answer for another request. Each released address contribution retains routing until `handoff_time + max(remaining_dependency_ttl_ms, dns_route_grace_ms)`; the default grace is 30 seconds. Effective dependency TTL is the minimum along the relevant alias/service/address path and is recalculated after any output delay. Pending-response references prevent a gap while output is queued or while the first TCP/UDP flow is being admitted. Admission acquires its flow reference under the same serialized ownership rules before retirement can begin.

Same-backend concurrent answers extend applicable leases without resetting DNS cache freshness. Failed/cancelled answers contribute no new grace lease. Active-flow references retain ownership after timed leases expire, and closing a flow cannot prematurely discard an unexpired grace lease. Bound route entries and flow lifetimes; reject new discovery with SERVFAIL rather than evicting a protected route. After the final pending-response, timed lease, and flow reference expires, remove only the owned route and then its unused mapping. Connections initiated after that retention window, including delayed use of stale hints or TTL-ignoring caches, remain outside coverage.

Retained DNS state also has global limits independent of routes and in-flight
queries: `max_dns_lease_entries` (32768), `max_dns_cache_entries` (4096), and
`max_dns_state_bytes_total` (16 MiB). Apply the canonical lease key/admission
rules in the configuration contract. Reserve name/provenance/lease/index
capacity before mutation; coalesce renewals and bound expiry storage rather
than appending unlimited timer records. Cache eviction never removes routing
ownership. Reclaim expired state or skip optional cache insertion; return
SERVFAIL when required lease state cannot fit without evicting protected
ownership. NET-12 proves this with many names sharing one IP and long TTLs.

Before broad/static capture routes are installed, establish driver-specific physical transport exemptions for SSH/SOCKS/WireGuard endpoints and direct upstream DNS. Verify exemptions cannot accidentally tunnel those transports into themselves. Recompute them on network changes or stop affected forwarding until the safe path is restored.

## 5. Platform DNS and Transactional Recovery

### 5.1 Linux Driver

- Use `rtnetlink` for interface/address/route changes, recording route table, prefix, interface identity, priority, and ownership markers as available. Avoid overwriting existing host networking.
- Initial automatic DNS integration supports hosts with working `systemd-resolved`. For split DNS (`serve_dns: false`), configure route-only domains and disable default DNS routing on the TUN. For global forwarding, configure the catch-all routing domain and explain interaction with more-specific domains on other links.
- Set routing domains/default-route policy before publishing DNS servers and activating the link. Have the packet engine ready before the host can send DNS to it.
- Capture actual non-looping upstream resolver addresses and their link context; reading only `/etc/resolv.conf` is insufficient when it names a local stub.
- Detect unavailable resolved, authorization failures, or conflicting network-manager ownership before mutation. Provide a clear unsupported-integration error in the initial release; additional resolver managers need separate adapters and tests. Automatic `/etc/resolv.conf` replacement is out of scope.
- Use explicit `RevertLink` during orderly cleanup as applicable. Nonpersistent link disappearance aids crash cleanup, but verify its actual effects in abrupt-termination tests rather than relying on it for every resource.

### 5.2 macOS Driver

- Implement actual utun creation/naming and platform route operations. Use structured APIs where feasible; otherwise invoke tools with separate arguments and checked exit status, without shell interpolation.
- Preserve split DNS behavior through owned `/etc/resolver` entries or a proven SystemConfiguration equivalent. Refuse to overwrite existing conflicting entries. Snapshot original DNS state for global mode, including whether it was automatic rather than explicitly configured.
- Discover the active network service and real upstream resolvers; handle spaces in service names and network-service changes. Define exact snapshot, apply, and restore behavior in a platform decision record.
- Include the driver in the implementation roadmap and run native networking/recovery tests. A successful macOS compile is not a substitute for these tests.

### 5.3 Journal, Ownership, and Lifecycle

- Separate runtime locks from durable recovery state. Use a protected root-owned runtime directory (`/run/warper` on Linux, `/var/run/warper` on macOS), with the journal in a protected persistent state directory (`/var/lib/warper` on Linux, `/Library/Application Support/warper` on macOS). Persistent DNS changes must remain recoverable after reboot even if runtime files disappear. Validate directory/file ownership and permissions, refuse symlinks, and create files exclusively. Do not trust a shared predictable file in `/tmp`.
- Hold an exclusive instance lock before recovery or mutations. Initially allow one instance per host network namespace; include namespace identity on Linux. Record instance identity, boot identity where available, process start identity, interface identity, journal version, original values, intended changes, and committed resource ownership. Treat resource identities from an earlier boot as stale until verified against current state.
- Write recovery intent before each external mutation, then record completion; use atomic replacement and appropriate file/directory synchronization. Recovery must reconcile uncertain operations after a crash between mutation and journal update.
- Preflight and establish backend/stack readiness, transport exemptions, and interface state before publishing capture routes and system DNS. Roll back completed mutations in reverse dependency order on any failure.
- Service SIGINT/SIGTERM and explicit Disconnect trigger supervised DNS withdrawal, bounded flow drain/cancellation, owned route/interface cleanup, restoration, and backend shutdown. Closing or interrupting a GUI/CLI affects only that client. Persist desired state and distinguish same-boot service recovery from fresh-boot autoconnect policy; record incomplete cleanup for recovery.
- Panic hooks emit minimal redacted diagnostics; they are not async cleanup mechanisms. RAII provides best-effort handle release. SIGKILL/abort/power failure cannot run application cleanup.
- At startup, recover only after the lock proves there is no live owner. Validate the journal and verify that current resources still match the recorded owned changes. Restore saved settings only if the current value still matches the value warper installed. Preserve unrelated or subsequently changed host settings; report ambiguous recovery instead of deleting blindly.
- Provide an explicit recovery/inspection command using the same locking and ownership checks. If a crash leaves system DNS broken, recovery must not depend on resolving backend hostnames first.

## 6. Observability and Presentation

### 6.1 Service Control and Metrics

Follow the [service/client contract](service-and-client.md) and
[ADR 0004](adr/0004-desktop-service.md). The service owns networking under
systemd/launchd; the desktop and thin CLI are ordinary-user observers/controllers.
Use authenticated native local IPC, bounded operations/subscriptions, managed
configuration, and explicit owner/admin authorization. Control availability
and network-session readiness are distinct. Do not run a webview as root.

Collect byte totals, sampled rates, active TCP/UDP flows, DNS outcomes, route
conflicts, queue drops, reconnects, and backend health. Separate payload bytes
from transport overhead. Slow or closed clients must not affect forwarding.
The supervised service and foreground diagnostics emit redacted logs to
stderr; foreground mode is a development/recovery tool rather than the main UX.

### 6.2 Tauri Desktop

Replace the terminal UI with a Tauri 2 client. Provide first-run service
registration/approval, existing YAML import or guided configuration, Connect/
Disconnect, explicit startup preference, and health/traffic/routes/flows/logs.
Closing the window or quitting the desktop does not disconnect. Version
mismatch, recovery required, stale observations, DNS restrictions, and missing
SSH trust have distinct actionable states.

Use a narrow native Rust bridge, local bundled assets, explicit capabilities,
and CSP. Never expose generic shell/filesystem/privileged IPC access to the
webview. Keep UI preferences unprivileged and configuration installation
separate from editing. Render snapshots/events with bounded/coalesced updates
and measure idle/active CPU rather than promising a universal percentage.

macOS targets 13+ and bundles the desktop plus `warperd`. Registration through
SMAppService is distinct from embedding an executable. Native signing,
notarization, approval/revocation, upgrade and uninstall checks gate a public
release. Linux packages use the corresponding systemd/service authorization
integration. Do not create successful installer placeholders before runnable code.

### 6.3 Optional Protocol Classification

Classification is best-effort telemetry and never controls forwarding or access policy. Start with well-tested TLS, HTTP/1, HTTP/2 preface, and SSH recognition; return `Unknown` when evidence is insufficient.

Inspect bounded prefixes in both directions, handle signatures split across reads, retain message boundaries for UDP, and use deterministic matcher precedence. Forward bytes immediately; do not wait for classification. Any retained data is bounded and owned safely.

Add database, WebSocket, QUIC, and other signatures only with protocol-correct fixtures and documented confidence. PostgreSQL startup messages have a length before the protocol version; server-first greetings and variable-length headers cannot be reduced to the original fixed prefixes. Drop the zero-allocation and sub-10ns promises; measure the actual chosen implementation.

## 7. Execution Roadmap and Exit Criteria

### Phase 0: Baseline and Feasibility

1. Create a minimal compiling workspace and committed lockfile using the existing exact toolchain pin and Rust 2024 conventions. Inherit shared workspace lints in each package. Extend the existing stage-aware CI with checks for actual packages/features. Keep experimental packages under `experiments/`; add production packages only as they become useful.
2. Capture original-shaped configuration fixtures, backend capability cases, canonical examples, and explicit migration/error cases. Document reference behavior and deliberate fixes.
3. Build executable host-facing TUN interception and WireGuard-side dialing probes, including destination metadata, per-flow dispatch, cancellation, datagram boundaries, IPv4/IPv6, and WireGuard timers/rekey.
4. Record dependency versions, exact stack APIs, platform assumptions, observed limitations, and any necessary design changes. Complete the contracts needed by the first production slice.

#### Required Phase 0 Evidence Package

Phase 0 must produce the following artifacts; they do not exist at planning time:

- Runnable probes under `experiments/host-stack/` and `experiments/wireguard-stack/`, registered in the minimal workspace. Keep synthetic peer fixtures separate from production configuration.
- A `scripts/verify-feasibility.sh` harness with documented entry points `./scripts/verify-feasibility.sh host-stack` and `./scripts/verify-feasibility.sh wireguard-stack`. Each command prepares/uses a disposable test environment, runs assertions, verifies cleanup independently, and returns nonzero on failure. Document required tools/privileges and exact clean-checkout setup commands; do not mutate the live host resolver.
- `docs/adr/0002-network-stack.md` naming chosen packages/versions/features, both stack roles and APIs, reasons for selection, supported platforms/families, measured limits, rejected alternatives, and any adapter/fork maintenance cost.
- `target/evidence/phase-0/README.md` with exact commands, compiler/OS/environment, controlled peer configuration, outcomes, redacted logs or capture summaries, and reproducible cancellation/cleanup/rekey results. Dependency API inspection, mocks, and compilation alone do not satisfy the real-traffic gate.
- Updated `docs/implementation-contracts.md` with concrete interface sources/usage, and `docs/implementation-status.md` with phase/gate status and evidence locations. Preserve pass/fail/not-run outcomes in the artifact package and CI logs. Record native macOS evidence separately; Linux-only observations must not be generalized to macOS.

**Exit:** the minimal workspace passes its checks; both stack roles are demonstrated against controlled peers; required artifacts and the initial contract gate have inspectable evidence. No production architecture commitment is based solely on crate descriptions. Continue automatically into the next phase when these checks pass.

### Phase 1: Workspace, Contracts, and Headless Linux Slice

1. Extend the proven workspace with core/protocol/service packages, explicit `warperd` target, configuration parser/validation, shared control types, a thin diagnostic CLI, redacted logging, and CI checks. Register canonical examples and migration/error fixtures in executable parser/CLI tests.
2. Define backend and authenticated local control contracts, task/cancellation/resource limits, route policy, instance lock, journal, and platform driver interfaces. Implement Linux owner enrollment and control independently of GUI code.
3. Implement Linux TUN lifecycle and SOCKS5 TCP forwarding for a fixed CIDR in an isolated network namespace, with endpoint exemptions and rollback.
4. Verify full-duplex traffic, half-close, client detach, service operation idempotency, authorization failures, cancellation, startup failure, and service shutdown before changing the host's normal resolver configuration. Add runnable service-manager integration only when the service executable exists.

**Exit:** an actual application connects through the service-owned TUN and selected SOCKS5 backend; failed startup restores the namespace's original state. Client exit leaves the session running, explicit Disconnect cleans it up, and unauthorized control fails.

### Phase 2: Linux DNS and Route Transactions

1. Implement DNS transports, normalized matching, answer processing, globally bounded lease/cache metadata, route grace/conflicts, HTTPS/SVCB endpoint discovery, and acknowledged route publication before DNS replies. Close NET-10, NET-11, and NET-12 alongside the base routing cases.
2. Implement resolved split/global DNS integration and capture loop-free upstreams before mutation.
3. Exercise abrupt termination, uncertain journal operations, recovery, shared-IP conflicts, and unavailable DNS authorization.

**Exit:** controlled domain lookups lead to connections through the correct backend, unmatched queries take the preserved resolver path, and DNS/route failure tests pass without unintended direct fallback for intercepted flows.

### Phase 3: Complete Required Backends and IPv6

1. Implement SSH authentication/host verification and TCP forwarding; test missing/changed host keys and reconnect behavior.
2. Productionize the proven WireGuard integration, including timer-driven rekey, UDP, MTU, outage handling, and orderly shutdown.
3. Complete IPv6 across TUN capture, DNS, backend capabilities, routes, physical endpoint bypass, and ICMP/MTU handling. Reject unsupported combinations explicitly.
4. Optionally implement SOCKS5 UDP only if its capability/lifecycle tests are included; otherwise retain the documented TCP-only matrix.

**Exit:** all required matrix cells pass real peer tests, including long-lived WireGuard traffic across rekey and backend outages.

### Phase 4: Native macOS Networking and Recovery

1. Prove bundled-helper registration, administrator-enrolled exact-build/owner authentication, and two-way XPC in a native macOS 13+ spike with no Apple-issued developer identity or notarization credentials (ADR 0005 and the UX-05 authentication subset). Test changed-build rejection/re-enrollment and impersonating peers before depending on the transport. Then implement utun, routes, split/global DNS, resolver capture, and protected journaling through the macOS driver.
2. Run native acceptance tests for both DNS modes, all required backends, IPv4/IPv6, partial startup, SIGTERM/SIGKILL, recovery, and service changes.
3. Implement the Tauri native Service Management bridge and bundle layout; test approval/denial/revocation, client independence, and helper lifecycle. Document supported macOS environments and signing/authorization limitations.

**Exit:** platform networking/recovery and the no-paid-account bundled
authentication spike pass. Record the real GUI/session/rebuild cases still
needed for full UX-05; no partial native spike is reported as a completed
desktop/local-installation gate.

### Phase 5: Tauri Desktop, Packaging, and Release

1. Build the Tauri host and TypeScript frontend with narrow commands, bounded snapshots/subscriptions, guided import, connection controls, health/traffic views, routes/flows/logs, and explicit service approval/error states. Pin frontend tooling and add unit/type/lint/build checks when code appears.
2. Add protocol classification only after the data plane is stable.
3. Benchmark idle/active CPU, memory, throughput, connection latency, route-commit latency, DNS latency, and queue behavior with reproducible workloads.
4. Package Linux service/desktop installation and a macOS app containing the GUI plus service. Complete the real no-paid-account GUI/service lifecycle, rebuilt-build re-enrollment, and production-mode exclusion cases (UX-05). Separately, before public macOS distribution, verify embedded/enclosing signatures, notarization, clean installation, update/version compatibility, explicit cleanup/unregistration, and reboot (UX-01–UX-04). Publish setup/migration/recovery documentation and preserve MIT attribution.

**Exit:** networking remains correct with clients open, closed, or restarted; service authorization and native bundle lifecycle gates pass. Performance results and limitations are documented without unsupported guarantees.

## 8. Verification Strategy

### 8.1 Deterministic Tests

- Configuration fixtures for original inputs, deliberate migration errors, current-user/sudo path resolution, invalid domains/keys/CIDRs, and secret-redacted diagnostics.
- Domain normalization, exact/label-boundary/longest matching, duplicate assignments, and no cross-backend fallback for negative responses or timeouts.
- Route precedence, address conflicts, same-backend lease sharing, effective TTLs, zero/short-TTL grace, delayed/failed output reservations, static/mixed modes, active-flow ownership, concurrent additions, and rollback on partial commit.
- Global retained DNS-state count/byte admission with many names sharing one route, long TTLs, same-key renewals, bounded stale expiry nodes, safe cache eviction, concurrent reservations, and rollback accounting (NET-12).
- DNS TCP framing with partial reads/multiple queries, malformed messages, unrelated additional records, CNAME chains/loops, negative answers, EDNS limits, truncated UDP fallback, and disabled IPv6 behavior.
- HTTPS/SVCB AliasMode/ServiceMode, effective `.` targets, alternate priorities, IP hints, related/unrelated Additional records, same-backend configured dependencies, cross-backend/unconfigured target rejection, address-family failures, static coverage, and bounded dependency/query/address budgets. Delay A/AAAA resolution and kernel ACK independently to prove no advertised hint precedes coverage.
- Backend TCP half-close, cancellation, stalled peers, bounded queues, UDP boundaries, and unsupported-capability errors. SSH fixtures cover valid, unknown, and changed host keys.
- Journal ownership, locking, symlink refusal, corrupted/version-mismatched records, uncertain mutation reconciliation, foreign resources, reused interface identities, and later user changes.

Use fake clocks and fault-injecting drivers for route/DNS ordering and recovery transitions. Assert that no dynamic positive DNS answer is released before successful route acknowledgement and internal handler publication. Parser fuzzing is useful where warper adds parsing or response-processing logic beyond library validation.

### 8.2 Actual Networking Acceptance

Run Linux tests in disposable network namespaces with controlled DNS, SOCKS5, SSH, and WireGuard peers. Network namespaces do not isolate the host system bus or filesystem: DNS integration tests also need private mounts/state and a dedicated resolved instance/bus, or a disposable VM. Never point namespace tests at the host's resolved service. Run macOS tests on a dedicated VM/runner that can safely change network settings. Test harness cleanup must be independent of warper cleanup so failure does not damage the test host.

Required scenarios:

1. Static CIDR and DNS-discovered connections reach the intended peer; packet captures on controlled uplinks verify the selected transport and endpoint exemptions.
2. Both DNS modes work, unmatched DNS cannot recurse through the system stub, and matched backend failure does not query direct upstreams.
3. Concurrent queries/connections preserve commit ordering; delayed/failed kernel acknowledgement yields SERVFAIL and consistent rollback.
4. Same-IP backend conflicts, overlapping static routes, CNAME/AAAA answers, DNS TTL expiry, cached answers, and active-flow retention follow the documented policy and coverage limits. NET-10 verifies zero/short TTLs preserve first-connection grace without changing DNS TTL/cache semantics; NET-11 verifies HTTPS/SVCB hints and alternate endpoints cannot precede their routes, including split DNS and disabled IPv6.
5. UDP through WireGuard preserves datagrams; unsupported SSH/SOCKS UDP follows the rejection policy. If SOCKS UDP is enabled, test relay lifetime and control-channel closure.
6. Large transfers, half-close, stalled connections, MTU constraints, IPv6, and sustained WireGuard traffic across rekey work within declared limits.
7. Failure after each startup mutation, SIGINT/SIGTERM, SIGKILL, abrupt backend loss, and restart recovery preserve unrelated host state and restore owned changes where still applicable.
8. A second instance cannot mutate or recover a live instance's resources. Network-service/default-route changes do not create transport loops.
9. Foreground diagnostics and service-controlled operation share the same networking behavior. GUI/CLI detach or restart leaves sessions intact; slow observers cannot block traffic. UX-01–UX-04 verify authorization/state/public packaging; UX-05 independently verifies the no-paid-account bundled path and exclusion of development auth from production artifacts.

### 8.3 CI and Performance Evidence

- Keep local and CI commands aligned with `scripts/check.sh` and `docs/development.md`. Infrastructure checks run now. Once Cargo exists, run formatting, strict locked workspace Clippy/rustdoc, default/all-feature tests, dependency policy, and native release builds. Check supported feature combinations when introduced. Native jobs cover Linux x86-64/ARM64 and macOS ARM64; additional advertised targets need runnable evidence.
- Add isolated Linux networking tests as soon as the first vertical slice exists. Keep native macOS privileged acceptance distinct from compile/unit CI and require its evidence before a cross-platform release.
- Record compiler/dependency versions, hardware, OS, terminal, topology, flow count, packet sizes, run duration, and idle/active workloads with benchmarks. Report measured CPU, memory, throughput, latency distributions, and drops. Set performance budgets from those results; optimize only demonstrated bottlenecks.

### 8.4 Definition of Done for Each Increment and Phase

An increment is complete only when:

1. It delivers its stated observable behavior through real code. Required paths have no `todo!`, `unimplemented!`, fake success, or swallowed operational errors. Later-phase features remain explicitly unavailable and incomplete.
2. Interfaces conform to the applicable post-feasibility contract; configuration/CLI behavior and documented defaults match the canonical specification. Dependency versions/features and any design deviations are recorded.
3. Relevant tests establish behavior and meaningful failure boundaries, including cancellation/cleanup where the change owns resources. Mocks validate deterministic failure states; actual network behavior has the relevant isolated peer evidence before being claimed.
4. Checks appropriate to the change pass as documented in `docs/development.md`. For Rust increments, run formatting, strict locked workspace Clippy/rustdoc, default/all-feature tests, dependency policy, and release builds. Documentation-only changes do not require Rust compilation. Workflow/shell/harness changes require the infrastructure suite; every change needs licensing and whitespace review, including untracked files. Additional feature/platform checks run when affected. Unavailable environments/checks are explicitly recorded as not run, never passed.
5. The implementation has bounded resource ownership, typed/redacted diagnostics, and explicit unsupported-capability behavior. New unsafe code has a specific safety argument and targeted verification. Test environments clean up independently after both success and failure.
6. The phase ledger records status, limitations, the next unmet gate, and stable evidence locations. Raw artifacts/CI logs identify the revision/worktree, exact commands/results, environment, and cleanup observations. Update configuration examples, migration notes, ADRs, and user documentation when affected; keep routine per-run history out of tracked documents.

A phase is complete only when all its required increments and exit criteria have evidence. Required release features cannot be substituted with optional work. A build passing on macOS establishes build compatibility; cross-platform networking/recovery claims require native acceptance. No phase boundary adds a human approval requirement: continue within the authorized scope when the gate passes.

## 9. Dependency and Platform References

These references inform the feasibility work; recheck the exact pinned versions before implementation:

- [Tauri bundle packaging](https://v2.tauri.app/distribute/macos-application-bundle/), [macOS signing](https://v2.tauri.app/distribute/sign/macos/), and [Apple Service Management](https://developer.apple.com/documentation/servicemanagement/smappservice).
- [tun2proxy public API](https://docs.rs/tun2proxy/latest/tun2proxy/) and [upstream dependencies](https://github.com/tun2proxy/tun2proxy/blob/master/Cargo.toml).
- [netstack-smoltcp public API](https://docs.rs/netstack-smoltcp/latest/netstack_smoltcp/).
- [BoringTun tunnel API, timers, and output-draining contract](https://docs.rs/boringtun/latest/boringtun/noise/struct.Tunn.html).
- [systemd-resolved VPN integration and configuration ordering](https://github.com/systemd/systemd/blob/main/docs/RESOLVED-VPNS.md).
- [resolved D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html) and [authorization policy](https://github.com/systemd/systemd/blob/main/src/resolve/org.freedesktop.resolve1.policy).
- [DNS TTL/cache semantics, RFC 1035 section 3.2.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.1) and [service-binding targets and IP hints, RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html).
