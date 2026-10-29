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
./scripts/verify-feasibility.sh host-stack --tun
./scripts/verify-feasibility.sh host-stack --tun-crash-check
./scripts/verify-feasibility.sh host-stack --tun-fragment-check
./scripts/verify-feasibility.sh host-stack --mtu-check
./scripts/verify-feasibility.sh wireguard-stack --packet-only
./scripts/verify-feasibility.sh wireguard-stack --packet-only --rekey
./scripts/verify-feasibility.sh wireguard-stack --kernel-peer
./scripts/verify-feasibility.sh wireguard-stack --kernel-peer --rekey
./scripts/verify-feasibility.sh wireguard-stack --kernel-mtu-check
PATH=/usr/sbin:$PATH ./scripts/verify-feasibility.sh wireguard-stack --router-mtu-check
```

Tests require permission to bind loopback UDP sockets. On Linux, the harness
also requires Bash, Git, coreutils (`timeout`), util-linux (`unshare`),
iproute2, Python 3, and enabled unprivileged user/network/mount namespaces.
It builds before isolation and creates disposable namespaces. Packet-only
mode enables only loopback. The TUN scope requires an accessible
`/dev/net/tun` and permission to create an interface in the disposable user
and network namespaces. Its nonpersistent interface is closed and its removal
verified independently of the Rust runtime. The TUN crash scope kills the
experimental adapter after UDP traffic, after first joining the external
packet bridge, and runs fresh traffic with a new adapter on the same fixture
interface. It does not test service recovery or replay old application data.
The TUN fragment scope also lowers a private IPv4 route MTU to 1000 bytes and
checks kernel-generated fragments of an otherwise supported UDP datagram. It
does not establish native IPv6 fragmentation below IPv6's minimum link MTU.
Kernel-peer mode also requires a kernel with
WireGuard support and creates an owned `wg-feasibility` interface entirely
inside that namespace. The helper never touches resolver settings, the host
bus, or persistent host state. The timeout supervises the process group;
`unshare` reaps its child and destroys the namespace independently of the
probe's cleanup. The helper checks for a single-UID mapped user namespace
before network mutation, removes its kernel interface after success/failure,
and verifies removal using the link inventory.
Do not run against the live host network to work around isolation failures.

The explicit host `--mtu-check` scope currently returns nonzero with a typed
unsupported-PMTU diagnostic. It verifies fixed 1280-byte TCP segmentation,
ICMPv4/v6 port-unreachable responses, and valid too-big feedback quoting an
actual oversized TCP packet, then observes the subsequent oversized retry.
It records that the raw stack does not reassemble fragments with selected
features, then verifies the bounded pre-admission fragment boundary in both
orders. This closes only the supported fragment-input subset; dynamic PMTU
still fails explicitly.
`cargo run --locked -p host-stack -- --mtu-check` runs the same probe without
the namespace harness. Other host probes keep their narrower scope.

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

`reassembly.rs` normalizes bounded IPv4/IPv6 fragment input before TCP/UDP
handler admission, using smoltcp's public range assembler. Maximum
reassembled IP size is 1280 bytes; two slots and one-second nonrenewing
deadlines bound partial data and tombstones. Tests verify overlap rejection,
capacity preservation, conflicting lengths/protocols, gap limits, malformed
input, atomic IPv6 fragment independence, checksum gating, and timer cleanup.
The combined runtime also carries fragmented TCP data. A long-idle regression
ensures clocks advance to the packet's wake time before admission. Dynamic
PMTU, outgoing fragmentation, larger datagrams, and extension-header chains
remain outside this candidate.

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
default packet matrix uses both IPv4 and IPv6 outer loopback; the same-library
long rekey case retains IPv4 outer transport. This peer uses the same implementation;
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

WireGuard packet probes also check maximum unfragmented inner UDP payloads.
`path_mtu.rs` bounds encrypted output using a declared 1500-byte loopback
path budget and the actual outer address family before socket send. The
fixed 1280-byte inner MTU needs at least 1340 bytes over IPv4 outer transport
or 1360 over IPv6. This is an envelope check, not physical PMTU discovery;
insufficient budgets and oversized encrypted output return typed errors.

Controlled standard-library TCP/UDP servers check addresses and synthetic
payloads, preserve empty datagrams, and return TCP response bytes after
request FIN. The probe retains and joins both server threads, bounds socket
waits, and checks their results alongside the client result. The first IPv4
case deliberately drops one handshake initiation and requires the library's
retry to recover within the ten-second setup budget. No application payload
is replayed by the harness. In the non-rekey run, the controlled outbound
blackout remains active for at least 1200 ms and until a TCP retry with the
original sequence and the distinct lost UDP datagram have both been observed.
A 25-second workload and worker bound covers subsequent retransmission and
recovery. After the heartbeat, a separate inbound blackout remains active for
at least 1200 ms; the kernel worker confirms its TCP response write, and the
client discards a subsequent encrypted data datagram before receiving the exact
response after restoration. The encrypted datagram is not identified by its
inner payload. This is ciphertext suppression, not a disabled link or a
production outage detector. After EOF it continues pumping for a 100 ms
controlled loopback drain so delayed TCP acknowledgements are emitted before
replacing the fixture session. This is experimental fixture timing, not a
production shutdown guarantee. Long mode additionally checks at least 135
seconds of exchange, a second initiation, recent completed handshake state
on both implementations, and continuing heartbeat replies.

The separate kernel peer link-transition probe must run through the disposable
namespace helper; it changes only the helper-created WireGuard interface:

```sh
cargo build --locked -p wireguard-stack
PATH=/usr/sbin:$PATH timeout --signal=TERM --kill-after=2s 90s unshare --user --map-root-user --net --mount --fork --kill-child=KILL bash scripts/run-feasibility-isolated.sh kernel "$PWD/target/debug/wireguard-stack" --kernel-link-check
```

It checks interface down/up readback, loss of one UDP datagram, a single TCP
write with FIN, a post-outage handshake and recovery through the independent
kernel peer. Link-down removes the fixture's IPv6 address on the tested kernel;
the probe explicitly restores and verifies that address before proceeding. The
helper independently deletes its interface on exit. This is not a physical-link
or host TUN test. See contract section 25.

The private routed-path interruption fixture runs all inner/outer IP families in
its own user, network and mount namespaces. It requires `mount`, `umount`,
`nsenter`, `sysctl`, `ip`, `python3`, and permission to create those namespaces:

```sh
cargo build --locked -p wireguard-stack
for inner in 4 6; do
  for outer in 4 6; do
    PATH=/usr/sbin:$PATH timeout --signal=TERM --kill-after=2s 55s unshare --user --map-root-user --net --mount --fork --kill-child=KILL bash scripts/run-physical-path-isolated.sh "$PWD/target/debug/wireguard-stack" "$inner" "$outer"
  done
done
```

The helper interrupts and restores only its own router egress veth, verifies
interface state and its restored fixture IPv6 address, and cleans up links,
processes and a private tmpfs control directory. The client checks one TCP write
and FIN plus a lost UDP datagram, then an exact response and distinct heartbeat;
the independent peer checks counts and joins workers. A bounded set of typed OS
network errors may be counted during recovery. This is not a physical NIC, host
TUN, or production route-repair test. See contract section 26.

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
complete host TUN/utun acceptance, distinct SSH/SOCKS backend instances, production contracts,
backend outage/crash cleanup, and MTU/ICMP acceptance are still
unimplemented or unverified. Kernel tests will require a disposable
TUN-capable Linux environment; native macOS gates require a separate runner.
The [network-stack ADR](adr/0002-network-stack.md) remains proposed.

The sandbox may deny access to `/dev/net/tun`; an approved unsandboxed run
still uses disposable namespaces and must never change the live host to work
around missing device access. Linux TUN evidence does not establish native
macOS utun behavior or the complete host acceptance gate.

Each harness run writes environment/revision information, the lockfile,
build/probe output, exit status, and explicit unrun gates into a unique
directory under `target/evidence/phase-0/`. Its timeout is 20 seconds for
ordinary packet probes, 50 seconds for kernel-peer probes, 150 seconds for
`--packet-only --rekey`, and 200 seconds
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

The default WireGuard packet probe also runs `fragment_probe.rs`. The shared
`experiments/reassembly.rs` boundary normalizes decrypted inner fragments
before active-stack admission, following authenticated source and local
inner-destination checks. Both inner families, arrival orders, and directions
preserve maximum UDP payloads. Partial state expires on a transport pump even
without incoming packets; overlaps fail explicitly, and endpoint destruction
releases sockets with incomplete state retained. This does not establish outer
fragment handling, dynamic PMTU, or kernel-peer fragment acceptance.

The default isolated `wireguard-stack --kernel-peer` workload now includes
controlled outbound loss after TCP establishment and four UDP round trips.
One TCP request/FIN and one separate UDP message enter the ciphertext
blackhole. After restoration, stack retransmission completes TCP; the kernel
workers require the exact request/response and exactly five UDP messages,
including the distinct recovery heartbeat. The lost UDP payload is rejected
if replayed. Worker results are joined before success, and the namespace
harness removes and verifies the interface independently. `--rekey` still
adds a separate sustained workload with periodic heartbeats. This is limited
outbound-loss evidence, not general outage detection or crash recovery.

Default WireGuard packet probes now run all four inner/outer family
combinations over actual IPv4/IPv6 loopback UDP sockets. Encrypted fragment
round trips, expiry and overlap handling also cover both outer families.
Kernel-peer probes use IPv4 inner/outer and IPv6 inner/outer for the bounded
loss workload, then `--rekey` adds sustained IPv4 inner traffic over IPv6 outer
UDP. Endpoint family determines local socket family and declared header
budget; unsupported IPv6 socket setup fails explicitly. The unit workload
checks actual ciphertext delivery at the IPv4/IPv6 outer-size boundary.
These loopback tests do not establish physical routing or dynamic PMTU.

WireGuard packet probes also reserve one emitted UDP operation and send it to
a controlled closed port. `udp_feedback.rs` matches authenticated plaintext
ICMPv4/ICMPv6 port-unreachable quotes and returns a typed error. Matching stores
addresses, optional IPv4 identity and eight UDP header bytes; payload is not
retained. Tests cover minimum quotes, checksums, malformed and unrelated data,
second-reservation rejection, one-time delivery, cancellation and owner expiry.
The independent kernel scope repeats the closed-port probe in both families.
Its four bounded exchanges account for the longer 50-second harness deadline;
200 seconds covers those exchanges plus optional 135-second rekey. Dynamic
PMTU, concurrent UDP error delivery and host-side error synthesis remain open.

The explicit host `--mtu-check` scope now also tests a possible MTU control
strategy using released smoltcp APIs. Device capabilities are cached by its
interface; the probe rebuilds that interface at 1280 while retaining the
original established socket set. It first delivers/acknowledges part of one
8 KiB write at 1500, drops subsequent oversized output, and verifies a smaller
retry of the lost sequence, exact delivery, FIN and a reply. No application
write is repeated. Device reconfiguration refuses nonempty queues before
mutation; interface addresses, routes/lifetimes and any-IP policy are copied.
This interface-wide experiment is not automatic PMTU discovery, a production
migration API, or an asymmetric-path solution. Raw feedback still has no TCP
sizing effect; the command continues to return typed unsupported-PMTU failure.

`pmtu_feedback.rs` now connects that sizing action to one reserved outstanding
TCP data segment. The matcher retains addresses, IP identity/length, a
caller-selected reporter and the first eight TCP bytes with a nonrenewing
deadline. A different reporter cannot consume the reservation. Valid ICMPv4
fragmentation-required or ICMPv6 Packet Too Big feedback supplies the new MTU;
all four IPv4/IPv6 and 1280/1400-byte cases complete the retained transfer.
Only ACKs accepted by the reserved flow's TCP owner may retire the segment;
the supplied local and remote addresses and ports must match the reservation.
partial ACKs retain it, full ACKs account for FIN and sequence wrap. Unsupported
small/legacy-zero MTUs are typed errors. Corrupt or unrelated quotes cannot
resize; busy device queues preserve the reservation for retry within its
original deadline. Successful interface replacement consumes it once. This
does not authenticate the selected reporter and still leaves production path
attribution, multiple/asymmetric flows, outer
WireGuard PMTU and physical-path handling open; `--mtu-check` remains nonzero.

Default WireGuard packet probes now include encrypted inner PMTU feedback.
Shared matching, controlled ICMP construction and interface replacement live
in `experiments/{pmtu_feedback,pmtu_fixture,mtu_reduction}.rs`. A TCP-only path
fixture uses 1500-byte peers and a declared 1600-byte outer budget, drops
oversized decrypted data, and returns one encrypted too-big message from the
configured inner peer. The client applies 1280/1400 reductions to its existing
connection. All eight inner/outer-family/MTU combinations check exact 8 KiB
request, lost-sequence retry, FIN and response. TCP clock steps are controlled
at five milliseconds; fixture pacing sleeps at most once per four steps and
yields on the other turns. Each case has a twelve-second wall deadline;
loopback I/O and BoringTun timers remain real. Reservation
expiry/cancellation releases endpoint sockets and preserves typed failures.
The scoped larger-TCP fixture validates checksums/headers and cannot bypass
ordinary UDP size checks. These are inner feedback probes, not physical outer
PMTU discovery or independent-kernel PMTU evidence. Exact-source admission of
other inner routers and production state/path policy remain unresolved.

Use `scripts/verify-feasibility.sh wireguard-stack --outer-mtu-check` for the
Linux local outer-MTU scope. The guarded namespace helper sets only private
loopback MTU to 1400. Explicit no-fragment discovery and error-queue options
are read back on a dedicated connected socket. In all inner/outer family
combinations, one encrypted datagram must fail with local EMSGSIZE, a matching
kernel report must provide 1400, and the reduced budget must reject a distinct
oversized operation before socket send. A separate safe datagram must arrive
unchanged; failed application data is never replayed. Socket rebinding checks
cleanup. This scope rejects `--rekey` and requires wireguard-stack. Its success
also verifies local-feedback TCP adaptation: one 8 KiB application write and
FIN survive kernel rejection and TCP retransmission on the original connection.
The reduced inner limit reserves outer headers, encryption and padding (1328
bytes over IPv4 or 1312 over IPv6 at outer MTU 1400). Pending packet attempts
are retired only after validating the entire output queue as the same TCP flow;
queued input, mixed UDP, foreign flows, invalid checksums and clocks fail before
mutation. No inner feedback is generated. This is one serialized local path,
not remote/physical discovery or concurrent flow sizing. The full PMTU gate
remains open.

Use `scripts/verify-feasibility.sh wireguard-stack --kernel-mtu-check` to
repeat local outer-feedback TCP sizing against Linux kernel WireGuard rather
than another BoringTun peer. The dedicated private fixture has loopback MTU
1400 and WireGuard link MTU 1500. All four inner/outer family combinations
establish TCP, submit 8192 bytes once, recover through TCP retransmission after
validated EMSGSIZE/MTU 1400, preserve the tuple and complete FIN/response.
The joined kernel worker verifies exact request bytes and EOF; socket rebinding
and kernel handshake/counter readback accompany independently verified interface
removal. No synthetic inner feedback or larger same-library receive admission
participates. Wrong probe/scope/rekey combinations fail before build or setup;
probe failures still clean up, and cleanup failures cannot report success.

This Linux-only scope has the ordinary 20-second global probe bound and
per-connection six-second wall/worker deadlines plus 1000 controlled TCP steps. It does not run
long-lived rekey or remote-router/physical-path MTU discovery. The full PMTU
gate remains open; contract section 22 defines this evidence boundary.

The Linux `--router-mtu-check` scope uses a private routed topology and an
independent kernel WireGuard UDP peer. Client/router ingress is MTU1600;
router/peer egress is MTU1400. The first oversized encrypted send must succeed
locally before a real IPv4 fragmentation-required or IPv6 packet-too-big error
arrives. Matching requires the exact socket/destination, remote error origin,
expected router and quoted 16-byte public WireGuard data header. A single
nonrenewing one-second reservation bounds retained metadata. Missing or shorter
quotes, malformed/unrelated errors and unsupported paths cannot reduce budgets.
The fixture sends distinct oversized encrypted datagrams through the original
transport and a separate socket owner. It rejects the original socket's report
against the owner, including a synthetic copy with the owner's packet header.
It then holds a genuine report received by the owner, changes and restores the
owner's peer, and verifies that report cannot change the new path budget. A
new genuine report commits the new budget. A synthetic copy with the new
header also checks reader generation independently of header matching. The
kernel peer verifies that failed UDP payloads are not replayed.

The Linux `outer_owner` experiment constructs a private socket and serializes
operations through exclusive mutable access. Its peer transition revokes the
old reservation and reader before creating a new socket on the same local IP
and an ephemeral port; failed transitions stay unavailable until recovery. Up
to eight retired sockets stay bound until the owner is dropped; the next
transition returns a capacity error without changing the current flow. This
bounded fixture policy does not protect packets delayed beyond owner lifetime
or establish production retirement timing. Run its controlled loopback tests with
`cargo test --locked -p wireguard-stack outer_owner::tests`. The routed fixture
uses the owner for encrypted sends, genuine feedback, and a distinct application
datagram exchange after recovery. The owner does not replace the general
WireGuard transport or a native macOS implementation.
The original reader's snapshot checks still cannot detect an unowned socket
peer changed and restored between checks or concurrently reconfigured.

A separate synthetic short-quote probe requires Linux, Python 3, `unshare`,
and `ip`, with permission to create an isolated user and network namespace:

```sh
unshare --user --map-root-user --net sh -c 'ip link set lo up && python3 scripts/probe-short-icmp.py'
```

It injects ICMP errors on private loopback for both outer families and checks
error-queue metadata for quotes containing 0, 4, 8, 15, or 16 payload bytes.
It also injects a delayed error after two distinct synthetic sends and checks
that the queue retains the old header. The single-UID mapping guard does not
itself verify network isolation; the command creates that isolation. This synthetic fixture does not prove router
trust or support short-quote correlation.

The fixture deliberately enables and reads back no-fragment PROBE mode to avoid
cached PMTU suppressing repeated remote measurements; all sends still obey the
declared transport budget. A distinct oversized send must then fail before
socket I/O, and a separate safe message must complete on the same tunnel. All
four family combinations run; the peer verifies exactly twelve UDP datagrams
(four warmups, four owner exchanges and four safe messages). A 100ms gap between fresh sessions
spaces initiations for the reused kernel peer identity. This is fixture pacing,
not a production reconnection strategy.

The router uses `tc` netem to delay ICMP and ICMPv6 feedback by 100 ms on the
private client-facing link. The owner retires a reservation and sends a later
distinct packet before the old report reaches its error queue. It rejects the
old report and applies the later report. The test requires `tc` and the kernel
prio, u32 and netem facilities; it does not establish cross-session header
uniqueness or path attribution.

The client also has a second source-bound route over a separate veth to the
same router. Two socket owners send distinct oversized encrypted datagrams
before either reservation is retired. Each receives a genuine report from its
own router-facing address, rejects the other owner's report, and commits its
own reduction independently. All inner/outer family combinations run. Both
links converge at the same router and egress; this does not verify independent
physical NICs or concurrent stack resizing.

With the harness-provided private tmpfs control directory, the probe also
keeps both reservations outstanding while the harness lowers the second router
veth. After the harness acknowledges the interruption, the probe reads a real
Linux link notification and invalidates that owner, verifies it rejects new
sends, and commits the
unaffected path's report. The harness
raises the link and restores its IPv6 address; a replacement socket sends a
distinct datagram and commits its own new report. The harness owns link mutation
and independently removes its links and control mount even on failure. This
controlled sequence does not establish continuous monitoring, safe behavior
before the notification is processed, or physical
interface failure. Notification loss, truncation and malformed input fail
closed in the experimental owner.

Before traffic and after each restored link, route, rule, or address, the harness checks the
private client namespace kernel route lookup for both fixture sources and
destinations. It verifies one unicast result with the expected source, gateway,
and egress interface in each family. A failed lookup prevents the harness from
acknowledging restoration, so the probe does not replace its socket. Before
lookup, the checker subscribes to link, address, route, and rule notifications;
it rejects a queued notification or receive error after the queries. This does
not prove notification delivery ordering or cover changes after the check. A
separate private-namespace probe adds and removes an unrelated route between
queries and verifies that the checker rejects the snapshot. The
lookup does not model socket marks or a concurrent routing change, and is not
production path verification. For link, route, rule, and address recovery, each
candidate socket also undergoes a monitored lookup using its actual source and
destination UDP ports before the owner publishes it. Initial owners in the two-path and recovery scenarios also use that candidate
check. In the route/rule and address scenarios, each owner holds its own
subscription and checks it before sends, reads, and feedback. It invalidates on
a change or notification error. These separate scenarios do not monitor all
change classes together or supervise idle owners, and other fixture transport
sockets remain outside this check.

The harness also removes and restores the second source-specific default route
and, in a separate exchange, its policy rule while both owners have pending
reservations. The experimental Linux route
listener invalidates both owners on any IPv4 or IPv6 route or rule event, because it
does not attribute events to individual paths. Both reject sends until the
harness restores the route or rule and the probe replaces their sockets; distinct sends
then obtain their own reports. This conservative fixture behavior does not
establish route verification, event attribution, continuous monitoring, or
safety during the interval before event processing. A separate address-only
subscription observes removal and restoration of the second source address in
both outer IP families. Address events conservatively invalidate both owners;
the harness restores the address and dependent private routes before recovery.

`run-router-mtu-isolated.sh` owns the namespace anchor processes, veth links,
interruption supervisor and kernel-peer subprocess. Ready/stop files use a
private tmpfs directory;
a bounded supervisor and cleanup traps reap processes and verify link removal.
The peer helper independently removes its WireGuard interface. IPv4/IPv6
forwarding sysctls belong only to the private router network namespace. No host
resolver, bus or physical configuration is touched. Supply `nsenter`, `sysctl`,
`readlink`, `sleep`, `mount` and `umount` on PATH; `/usr/sbin` may be needed for
sysctl. The full
Phase0 gate remains open, especially short quotes, router trust and
concurrent/asymmetric physical paths. See contract section 23.

The routed scope also runs four retained TCP cases. The peer's WireGuard link
uses MTU 1500 so its advertised TCP MSS exercises the smaller routed outer path.
For each case, the client writes 8192 bytes once and closes sending; only the
first oversized TCP segment is encrypted/sent before waiting for its remote
report. Shared validation and the original interface sizing action execute
synchronously before releasing the reservation. Queue-busy retries preserve the
report reservation and both budgets; invalid quotes/MTUs cannot retire queued
TCP attempts. TCP retransmits from its unchanged send buffer under fresh
WireGuard counters at inner MTU 1328 (outer IPv4) or 1312 (outer IPv6).

The probe verifies the rejected sequence, original tuple, exact bytes,
FIN/response and a 100ms final-ACK pumping interval. The kernel peer accepts two
TCP connections per inner family, verifies the combined four TCP/twelve UDP
workload and 43044 application bytes, joins all four workers and rebinds its
listeners. Both client and peer have explicit wall deadlines; real monotonic
time drives TCP retries. The fixture's server/control/global bounds remain
15/16/20 seconds. This extends the existing `--router-mtu-check` scope; there
are no new flags. See contract section 24. General production migration/state,
router trust and minimum-size IPv4 quotes remain unresolved.
