<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Development

Start with the [implementation plan](implementation-plan.md),
[repository instructions](../AGENTS.md), and [ADR index](adr/README.md).
The [service/client contract](service-and-client.md) defines the Tauri
desktop, independent `warperd` service, local control, and managed bundle.
The current repository contains contracts and development infrastructure.
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

When Phase 0 introduces `scripts/verify-feasibility.sh`, its entry points and
peer setup must be documented here. Until it exists and passes, the
[network-stack ADR](adr/0002-network-stack.md) remains proposed.

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
