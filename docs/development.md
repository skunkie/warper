<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Development

Start with the [implementation plan](implementation-plan.md),
[repository instructions](../AGENTS.md), and [ADR index](adr/README.md).
The [service/client contract](service-and-client.md) defines the Tauri
desktop, independent `warperd` service, local control, and managed bundle.
The current repository contains contracts, development infrastructure, and
experimental Rust stack probes.
Add Rust packages when a runnable experiment or implementation phase needs
them; do not create placeholder packages for CI.

## Local checks

From the repository root:

```sh
scripts/check.sh
```

`scripts/check.sh infra` runs infrastructure checks only.
`scripts/check.sh rust` runs stage detection and the Rust checks applicable
to the current stage. Missing validation tools fail explicitly. With no
root `Cargo.toml`, the harness reports that Cargo checks did not run.

Infrastructure checks require Git, Python 3.11 or newer, REUSE, actionlint,
and ShellCheck. CI pins actionlint and ShellCheck versions/checksums in
`.github/workflows/ci.yml`; use those versions to reproduce its findings.
Check local versions before comparing results:

```sh
python3 --version
reuse --version
actionlint --version
shellcheck --version
```

Install ShellCheck before invoking actionlint, which otherwise silently
omits embedded shell analysis. The same infrastructure commands can be run
individually:

```sh
reuse lint
actionlint -color
ACTIONLINT="$(command -v actionlint)" python3 -B -m unittest discover -s scripts
python3 -B scripts/lint_actions.py
shellcheck scripts/*.sh
scripts/check-repository-stage.sh
git diff --check
git diff --cached --check
```

The composite-action harness rewrites local action steps into
temporary workflows, runs actionlint with ShellCheck, and maps findings back
to action-file positions. Its tests require the explicit `ACTIONLINT` path
in CI so missing tooling cannot silently skip them. The repository-stage
tests exercise planning mode, untracked/tracked Rust files, ignored build
outputs, missing workspace prerequisites, and invalid toolchain pins in
temporary Git repositories.

Review untracked files as well: Git diff checks do not inspect them.
Handwritten files need SPDX copyright/license headers. Use explicit
`REUSE.toml` annotations for generated or noncommentable formats; preserve
actual third-party licensing when introducing dependencies or assets.

## Repository stages and CI

CI runs on pull requests, pushes to `main`, manual dispatch, and reusable
workflow calls. It uses read-only repository permissions, disables stored
checkout credentials, sets timeouts, and cancels superseded branch runs.
Actions are pinned to full commit SHAs; downloaded tools are version-pinned
and checksum-verified. Runner labels newer than actionlint's built-in list
are declared in `.github/actionlint.yaml`.

Licensing, workflow/composite lint, shell lint, and harness tests run during
the planning stage. The stage script emits `rust=false` explicitly until a
root manifest exists. It rejects Rust sources or nested manifests without
that root, and requires nonempty regular manifest, lockfile, and exact
toolchain pin before emitting `rust=true`. CI then enables real Rust jobs.

When adding Cargo, use Rust 2024, the exact `rust-toolchain.toml` pin, a
committed `Cargo.lock`, shared workspace lint policy inherited by each
package, and deliberate dependency features. The standard checks are:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo deny --locked check
```

Install cargo-deny at the version CI pins; its policy is `deny.toml`.
Dependency exceptions require a specific reason, scope, and review condition
in an ADR; no unrelated advisory or fork exceptions are inherited.

The native composite action tests default/all features and builds release
artifacts for Linux x86-64, Linux ARM64, and macOS ARM64 on matching runners.
It exercises `warper --help` and `--version` once the CLI package exists.
Other architectures must gain runnable target checks before being claimed.
Define relevant feature combinations when features are introduced rather
than assuming all-features testing proves every combination.

## Networking acceptance and evidence

Ordinary CI and local infrastructure checks do not create a TUN, change DNS,
or grant privileged access. The native build matrix establishes compilation
and test compatibility; it does not establish system integration.

The [acceptance contract](acceptance.md) defines controlled peers and failure
scenarios. Use a disposable VM, or Linux network namespaces with private
mounts/state and a dedicated resolver/bus. Never use the user's live resolver
or system journal. The test harness must independently clean up after the
application, including abrupt termination and partial startup.

### Phase 0 packet experiments

The workspace contains `host-stack` and `wireguard-stack` experiments, with
exact direct dependency pins and a shared bounded raw-IP peer device. The
existing stage-aware CI now runs real workspace checks and native tests.
These are experiments, not a runnable `warperd` or a finalized stack adapter.

From a clean checkout, install the exact root toolchain using rustup, then:

```sh
rustup show
cargo fetch --locked
cargo test --locked --workspace
./scripts/verify-feasibility.sh host-stack --packet-only
./scripts/verify-feasibility.sh wireguard-stack --packet-only
./scripts/verify-feasibility.sh wireguard-stack --packet-only --rekey
./scripts/verify-feasibility.sh wireguard-stack --kernel-peer
./scripts/verify-feasibility.sh wireguard-stack --kernel-peer --rekey
```

Tests require permission to bind loopback UDP sockets. On Linux, the harness
also requires Bash, Git, coreutils (`timeout`), util-linux (`unshare`),
iproute2, Python 3, and enabled unprivileged user/network/mount namespaces.
It builds before isolation and creates disposable namespaces. Packet-only
mode enables only loopback. Kernel-peer mode also requires a kernel with
WireGuard support and creates an owned `wg-feasibility` interface entirely
inside that namespace. The helper never touches resolver settings, the host
bus, or persistent host state. The timeout supervises the process group;
`unshare` reaps its child and destroys the namespace independently of the
probe's cleanup. The helper checks for a single-UID mapped user namespace
before network mutation, removes its kernel interface after success/failure,
and verifies removal using the link inventory.
Do not run against the live host network to work around isolation failures.

The default host probe injects controlled IPv4/IPv6 packets into direct
smoltcp 0.14 AnyIP interception. Two preconfigured destinations have separate
controlled echo handlers and fixed TCP/UDP socket slots. It verifies
original addresses, empty/unequal UDP replies, concurrent 64 KiB full-duplex
TCP exchanges with responses after request FIN, occupied-slot rejection,
stalled-reader backpressure, and idempotent cancellation. Buffers and
packet queues are bounded; its clock and packet steps are controlled.
It does not yet expose a general asynchronous accepted-stream API or
admit arbitrary discovered destinations.

The host executable additionally runs a separate asynchronous TCP adapter
probe. It admits policy-selected destinations from validated SYNs rather
than preinstalling a listener per destination, and verifies two sources
sharing a destination as well as distinct destinations. Connections stream
64 KiB through Tokio `AsyncRead`/`AsyncWrite`, preserve metadata, and finish
request FIN followed by backend response FIN. Unit tests add the reverse
half-close order, setup/idle/max-age boundaries, invalid input, queue
rollback, retained closed-stream budgets, slow-reader backpressure,
cancellation wakeups, and reset errors. Handler tasks are retained and
joined; the adapter owns no background tasks. Its driver is explicitly
polled with a controlled clock. This TCP candidate returns a typed unsupported
error for UDP; UDP admission has its own candidate boundary.

`udp_adapter.rs` separately admits UDP associations by original tuple, with
backend selection frozen on admission. `udp_probe.rs` checks dynamic/shared
destinations and two sources using actual smoltcp peers in both families.
Each association preserves empty, unequal, and maximum unfragmented payloads
(1252 IPv4 or 1232 IPv6 bytes at MTU 1280). IP/UDP validation precedes
allocation, including an explicit zero IPv6 checksum rejection beyond the
library parser's checks. Source port zero, non-unicast traffic, fragments,
and IPv6 extensions are outside this reply-oriented experiment.

Receive is asynchronous; reply admission returns typed queue/quota errors.
Independent bounds cover active associations, retained handles, accepted
queues, per-direction messages, globally retained payloads, and output
packets. Retained datagrams keep their quota after association expiry/drop.
Tests exercise reservation rollback, exact idle/age expiry, stale replies,
application drop, output backpressure, cancellation/drop wakeups, malformed
packets, and both families' MTU boundaries. Expiry withdraws owned queued
output before an association can be replaced. The candidate spawns no task;
the probe owns and awaits its futures, while the expiry-wakeup test joins its
bounded task. All timer-only cases use injected time. These adapter-only
probes do not establish production service scheduling; the separate combined
experiment follows below.
See [UDP boundary](implementation-contracts.md#8-experimental-udp-association-boundary)
for signatures and precise accounting limits.

The host executable also runs `runtime_probe.rs`, driving both candidates
through a single wake-driven runtime with bounded packet channels. It checks
concurrent 64 KiB TCP streaming and a trailer after FIN alongside empty,
unequal, and MTU-sized UDP in both families. Application I/O/drop wakes,
library poll deadlines, lifecycle timers, and packet/channel events schedule
progress; the runner uses no periodic polling interval. Packet output work
is bounded per turn and alternates protocols. UDP association priority
rotates under output pressure. Paused-clock tests cover idle sleeping,
TCP setup/idle and UDP expiry, blocked-output shutdown, capacity restoration,
application drop, channel-owner loss, and abort-and-join cleanup. A controlled
wraparound test ensures the peer consumes the final contiguous TCP slice
before waiting. These tests use the pinned Tokio `test-util` development
feature; release dependencies are unchanged.

The runtime owns no detached task. The fixture retains and joins the runner
and both controlled handlers, with bounded failure cleanup. Runtime failure
preserves typed causes and counters, closes ingress, cancels adapters, and
guards packet egress against release after shutdown. This is a scheduling
candidate, not the production supervisor or kernel I/O layer. Packet handoff
and retained-handle limits are specified in the
[combined runner boundary](implementation-contracts.md#9-experimental-combined-runner).

The wrapper comparison remains available explicitly:

```sh
cargo run --locked -p host-stack -- --wrapper
```

It checks the same basic address/datagram/FIN semantics through
`netstack-smoltcp` 0.2.4. Its exit is nonzero because the wrapper drops empty
UDP replies. Keep this failure as candidate evidence; do not suppress it
or change the packet expectation. The direct candidate is a separate
explicit experiment, with no fallback between candidates.

The WireGuard probe actively connects smoltcp TCP/UDP sockets through two
BoringTun peers and real loopback UDP, using published synthetic keys and
fixed inner addresses. It checks empty and unequal UDP datagrams, metadata,
and a TCP response after FIN in both inner families. `--rekey` additionally
runs IPv4 traffic for at least 135 seconds, checks a second handshake
initiation, a recently completed handshake, and continued replies. The
outer transport is IPv4 loopback. This peer uses the same implementation;
it does not prove interoperability with an independent WireGuard peer.
Polling every millisecond is experimental and is not a production scheduling
or performance claim. Run long-lived rekey inside a disposable environment.

The default WireGuard executable also runs `outage.rs` in both inner
families. Controlled outer-packet blackholes test setup loss and transient
established TCP/UDP loss. The application writes its TCP request once;
TCP retransmission restores it and preserves the response after FIN. A lost
UDP datagram is not replayed, while a distinct post-outage datagram arrives.
An explicit response deadline fails an established but unresponsive session;
a completed handshake alone is not application health.

The experimental owner groups stack, tunnel, and UDP socket. Setup,
response, lifetime, resource, and transport failures release that group;
cancellation is idempotent and preserves an earlier terminal reason. Tests
verify cleanup by rebinding the exact outer socket after expiry/cancel/drop.
Injected monotonic time drives owner deadlines; BoringTun's protocol timers
still use its real clock. The fixture's budgets are one second for setup,
ten seconds for lifetime, and explicit 100 ms/three-second response cases,
not implemented YAML defaults. Recovery has a bounded controlled-step and
wall-time budget. No background task is spawned.

Transport staging is capped at 64 IP packets before BoringTun's internal
256-packet silent-drop boundary. Immediate encrypted data releases its
reservation; queued plaintext stays charged until actual drain. Keepalives
do not release application reservations. Exhaustion is a typed failure;
the probe owner stops and releases resources without a fallback or replay.
A drain allows 64 queued packets plus the Done sentinel. A full-queue
regression verifies all 64 encrypted data datagrams reach the outer socket.
These are packet-level failure observations with controlled BoringTun peers,
not independent-kernel outage, endpoint-roaming, service crash, or general
NET-07 acceptance. See the
[active failure boundary](implementation-contracts.md#10-experimental-active-tunnel-failure-boundary).

The explicit `--kernel-peer` scope instead connects the same Rust active
stack and BoringTun client to Linux's independent WireGuard implementation.
The kernel peer has `10.66.66.10/24` and `fd66:66::10/64`, MTU 1280, and
allows only the client's two inner addresses. Its UDP listener uses an
OS-selected port; only loopback carries outer traffic. Configuration uses
the pinned Linux-only `wireguard-uapi` library, followed by readback of the
public key, peer count, allowed IPs, and listening port. Key-bearing messages
and device snapshots are never logged. This kernel interface is a test peer,
not part of the production userspace WireGuard backend.

Controlled standard-library TCP/UDP servers check addresses and synthetic
payloads, preserve empty datagrams, and return TCP response bytes after
request FIN. The probe retains and joins both server threads, bounds socket
waits, and checks their results alongside the client result. The first IPv4
case deliberately drops one handshake initiation and requires the library's
retry to recover within the ten-second setup budget. No application payload
is replayed by the harness. After EOF it continues pumping for a 100 ms
controlled loopback drain so delayed TCP acknowledgements are emitted before
replacing the fixture session. This is experimental fixture timing, not a
production shutdown guarantee. Long mode additionally checks at least 135
seconds of exchange, a second initiation, recent completed handshake state
on both implementations, and continuing heartbeat replies.

The kernel-peer CLI refuses the initial/broad user namespace and a preexisting
configured interface. It requires the helper-created single-UID namespace;
the kernel additionally enforces CAP_NET_ADMIN in the target network
namespace's owning user namespace. It is not invoked by ordinary Cargo
tests. On non-Linux platforms it reports an unsupported environment.
Missing kernel support or denied namespace operations fail explicitly; there
is no substitution with the same-implementation peer.

The required gate entry points are also available:

```sh
./scripts/verify-feasibility.sh host-stack
./scripts/verify-feasibility.sh wireguard-stack
```

They run the packet experiment but **return nonzero while the full gate is
incomplete**, even if the packet or kernel-peer experiment passes. Host-facing
TUN/utun traffic, distinct SSH/SOCKS backend instances, production contracts,
backend outage/crash cleanup, and MTU/ICMP acceptance are still
unimplemented or unverified. Kernel tests will require a disposable
TUN-capable Linux environment; native macOS gates require a separate runner.
The [network-stack ADR](adr/0002-network-stack.md) remains proposed.

The current development environment exposes a kernel TUN driver but has
no `/dev/net/tun` and denies creation of a temporary device node even in a
private tmpfs/user/network/mount namespace. Record the denied capability as
unverified TUN acceptance; do not change the live host to work around it.
Continue independent peer/adapter work while arranging a disposable
TUN-capable environment for that gate.

Each harness run writes environment/revision information, the lockfile,
build/probe output, exit status, and explicit unrun gates into a unique
directory under `target/evidence/phase-0/`. Its timeout is 20 seconds for
ordinary probes, 150 seconds for `--packet-only --rekey`, and 180 seconds
for `--kernel-peer --rekey`, including bounded handshake recovery and fixture
drain. The latter modes record rekey status separately. The evidence README
records commands and their scope. Full acceptance must extend the harness
before the gate can pass.

Raw logs, packet summaries, environment metadata, and comparison results
belong under ignored `target/evidence/` or CI artifacts, with synthetic peers
and redacted credentials. Keep reproduction commands, acceptance rules, and
decision consequences in documentation. Keep per-run validation history in
CI logs and commit messages. The [phase ledger](implementation-status.md) records which
gates remain open and where their evidence is produced.

## Release readiness

When real `client/` code is introduced, pin the package manager and lockfile,
and add frontend unit/type/lint/build commands here and in CI. Add Tauri's
Linux/macOS build prerequisites and native package checks at that point.
Existing Cargo checks alone do not validate a desktop distribution. Keep
the networking probes and independently runnable service useful without a GUI.

macOS local development can use ad-hoc signing without a paid Developer ID
or notarization; native Apple Silicon code still needs a valid signature.
Follow [ADR 0005](adr/0005-macos-development-authentication.md) for the
explicit `development-auth` build, protected administrative installation,
exact identifier/CDHash/owner pins, and re-enrollment after changed builds.
Real privileged integration uses the sealed installed app; ordinary frontend
hot reload uses an unprivileged fixture adapter. Production artifacts reject
the development mode, and normal per-operation authorization still applies.
Public default-Gatekeeper distribution targets Developer ID signing and
notarization, with helper
approval/update/uninstall tests; record unavailable release credentials or
native machines as missing evidence rather than blocking independent work.

UX-05 is a separate mandatory native gate on a disposable macOS 13+ system
with no Apple-issued developer signing identity or notarization credentials.
The native-spike phase must introduce a runnable
`scripts/verify-macos-development.sh --app PATH --owner USER` entry point,
document exact build/package/enrollment commands and OS approval steps, and
store observations under `target/evidence/macos-development/`. That script
does not exist yet. It must test bundle registration, owner enrollment,
two-way IPC, denied peers, tampering, changed-build rejection/re-enrollment,
and cleanup, then add actual service/GUI session cases when available. Record
partial or manual cases honestly. A paid-signed run or standalone launchd
test cannot close UX-05. Verify production artifacts separately without the
development feature; all-features test builds are not release artifacts.

Add publishing only after there is a runnable, tested artifact. Release
automation must call this reusable CI suite for the exact tagged revision,
validate versions and executable targets, and publish checksums. Limit write
permissions to publishing jobs and provide a manual build-only dry run.
Planning-only releases and successful placeholder deployments are excluded.
