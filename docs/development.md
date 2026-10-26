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
```

Tests require permission to bind loopback UDP sockets. On Linux, the harness
also requires Bash, Git, coreutils (`timeout`), util-linux (`unshare`),
iproute2, and enabled unprivileged user/network/mount namespaces. It builds
before isolation, creates disposable namespaces, and enables only their
loopback link. It never touches resolver settings, the host bus, or persistent
network state. The timeout supervises the probe process group; `unshare`
reaps its child and destroys the namespace independently of probe cleanup.
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

The required gate entry points are also available:

```sh
./scripts/verify-feasibility.sh host-stack
./scripts/verify-feasibility.sh wireguard-stack
```

They run the packet experiment but **return nonzero while the full gate is
incomplete**, even if the packet experiment passes. Kernel TUN/utun traffic,
two distinct protocol backend instances, independent WireGuard interoperability,
backend outage/crash cleanup, and MTU/ICMP acceptance are still
unimplemented or unverified. Kernel tests will require a disposable
TUN-capable Linux environment; native macOS gates require a separate runner.
The [network-stack ADR](adr/0002-network-stack.md) remains proposed.

Each harness run writes environment/revision information, the lockfile,
build/probe output, exit status, and explicit unrun gates into a unique
directory under `target/evidence/phase-0/`. Its timeout is 20 seconds for
ordinary packet probes and 150 seconds for the explicit WireGuard
`--packet-only --rekey` case. The latter runs the same disposable namespaces
and records rekey status separately. The evidence README records commands
and their scope. Full acceptance must extend the harness before the gate
can pass.

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
