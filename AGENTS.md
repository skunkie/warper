<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Repository Agent Instructions

## Project scope and workflow

- Build a Rust implementation of selective SSH, SOCKS5, and WireGuard tunneling. Follow `docs/implementation-plan.md`, `docs/acceptance.md`, and the current phase's exit criteria before expanding scope. The required and optional support matrix is part of the contract.
- This repository currently holds design documents, configuration examples, and development infrastructure. Do not add placeholder Rust code to satisfy CI; add crates when an experiment or phase needs them. Begin with a minimal compiling workspace and executable feasibility probes, then a real headless networking slice.
- Use the Go implementation at `~/projects/warp` as a behavioral reference without modifying it. Preserve the documented YAML inputs where safe, record intentional fixes, and preserve the externally defined SSH, SOCKS, DNS, and WireGuard protocols.
- Keep routing policy, stack adapters, protocol implementations, system configuration, and presentation separate. Start with few crates and introduce abstractions when concrete responsibilities justify them. Keep core independent of backend implementations; the service constructs and supervises them.
- Follow `docs/service-and-client.md` and ADR 0004: Tauri is the primary desktop, `warperd` owns networking, and GUI/CLI clients use authenticated local control. Closing clients never implicitly disconnects; no webview runs as root. Distinguish service availability, OS approval, and network readiness.
- Preserve unrelated user changes. Report what changed, which checks ran, and any checks that could not run. Do not report skipped checks as passed. Do not stage, commit, publish, or change unrelated repositories unless authorized.
- Continue automatically when a phase gate passes; gates do not require human approval. If an environment-dependent gate cannot run, leave it unverified and continue independent work without silently bypassing it.

## Contracts and architecture decisions

- Define configuration and CLI behavior in `docs/configuration.md` before implementing it. Keep defaults, validation errors, examples, parser/CLI tests, and migration diagnostics synchronized.
- Finalize applicable interfaces in `docs/implementation-contracts.md` against executable feasibility evidence before production modules depend on them. Keep third-party stack types behind adapters and define task ownership, resource accounting, cancellation, deadlines, and error categories.
- Record architecture decisions under `docs/adr/` using its template and status conventions. Accept the stack-selection ADR only after the required real-traffic probes pass. Record context, alternatives, consequences, limitations, and reproduction commands; a proposal is not implementation evidence.
- Specify lifecycle conflicts, retries, route publication/retirement, partial failure, rollback, and uncertain operation recovery in the contract rather than leaving them to individual handlers.
- Keep `docs/implementation-status.md` as a durable phase/gate ledger with evidence locations and remaining constraints. Store raw runs under ignored `target/evidence/` and in CI artifacts; keep per-run validation history in CI logs or commit messages.

## Networking and lifecycle invariants

- Preserve original destination metadata, TCP half-close, UDP datagram boundaries, cancellation, and bounded queues. Never replay application payload that may already have been delivered.
- Select a backend deterministically. Unsupported UDP and selected-backend failures must not fall back to direct traffic. Do not accept unknown SSH host keys or expose secrets, packet payloads, or raw configuration in logs/errors.
- Publish the internal handler before making a capture route usable; await the kernel driver's acknowledgement and committed ownership before returning a dynamic positive DNS answer. Preserve active-flow references during rollback and retirement.
- Keep DNS cache expiry separate from route retention. Preserve zero TTLs and reserve a response/connection grace reference before releasing addresses. For HTTPS/SVCB, validate the entire reachable endpoint set, resolve dependencies through the selected backend, and commit routing before release; reject targets that cannot stay within that backend's configured DNS domains.
- Bound retained DNS lease/cache metadata independently of route and active-request counts. Coalesce same-key renewals, account for reserved names/provenance/index/timer capacity, and prove NET-12 without evicting protected routing ownership.
- Keep backend endpoints and direct DNS on a verified physical transport path. Do not forward unmatched DNS through a stub that routes back to the TUN. DNS discovery is selective IP routing and cannot establish a general kill switch.
- Validate before mutation. Lock instance ownership and journal intent before external changes; make cleanup/recovery idempotent and preserve foreign or subsequently changed host state. A panic hook is not asynchronous cleanup.
- Retain and join service tasks; surface their failures. Shutdown must cancel/drain flows within a deadline, withdraw DNS, remove only owned network state, restore applicable settings, and report cleanup failures alongside the initial error.
- Required production operations must perform real work. No `todo!`, `unimplemented!`, fake success, or swallowed errors on required paths. Later-phase features remain unreachable or return typed unsupported-capability errors and remain marked incomplete.

## Rust conventions

- Use standard Rust naming and rustfmt. Prefer descriptive domain terminology, focused modules, borrowed data where ownership is unnecessary, slices over references to concrete containers, and typed durations over ambiguous numbers.
- Group declarations by responsibility and lifecycle. Keep public operations near their helpers, implementations near their types, and unit tests near the code they exercise. Preserve meaningful field and destruction order; avoid unrelated reordering.
- Propagate recoverable failures using typed errors, `Result`, and `?`. Do not branch on error-message text. Avoid panics, `unwrap`, and `expect` in recoverable production paths; trusted constants, documented invariants, and test assertions may use them.
- Keep asynchronous work nonblocking. Do not hold synchronous locks across `.await` or acquire parent locks while holding inner resource locks. Move blocking work to appropriate workers and keep I/O outside broad application locks.
- Bound network waits, retries, queues, allocations, and idle readers. Make cancellation and shutdown release resources predictably. Retain task handles and surface worker failures.
- Prefer existing dependencies and released upstream fixes. Isolate any required network-stack fork and document why it is needed. Update dependency versions and `Cargo.lock` intentionally, without unrelated upgrades.
- When introducing Cargo, commit `Cargo.lock` and a root `rust-toolchain.toml` pinned to an exact released toolchain with rustfmt and Clippy. Follow Rust 2024 conventions and configure shared lint policy centrally when adding a workspace.
- Keep tunnel credentials and private keys out of logs, committed examples, and fixtures.
- Prefer safe Rust and established protocol/cryptographic libraries. New unsafe code needs an explicit safety argument, a narrowly scoped boundary, and targeted verification; do not implement cryptography locally.
- Preserve the primary error when cleanup or diagnostics also fail. Return typed errors instead of branching on message text.

### Source and field ordering

Use this order as a project default. Keep related code together and allow
exceptions when they improve readability or preserve behavior. Avoid
reordering unrelated code solely to apply this convention.

- In source files, put the license header first, followed by module
  documentation and module attributes, imports and module declarations,
  constants and statics, types with their related implementations, free
  functions, and finally unit tests. Let rustfmt sort imports and module
  declarations where supported; preserve macro-dependent ordering.
- Present public entry-point functions before their private helpers, keeping
  related functions together in workflow or reading order.
- Within an inherent `impl`, prefer constructors such as `new` and
  `with_config`, then public operations in workflow order, accessors, and
  private helpers. Keep trait implementations near the type, after its
  inherent implementation, and follow the trait declaration's item order.
- Group ordinary struct fields logically and match declaration order in
  constructors and other struct literals where practical. Preserve field order required by destruction, representation, or
  serialization behavior; do not alphabetize fields or methods by default.
- Test tables follow the explicit identifier, input, and expectation ordering
  in the testing section below.


## Testing and validation

- Add tests for observable behavior, including failure paths, boundaries, and state transitions. A bug regression test must fail without the fix. Avoid tests that only mirror implementation structure.
- Keep unit tests beside their implementation and public API and application-flow tests under `tests/`. Use descriptive `snake_case` test names and table cases when they improve clarity.
- Prefer Rust's native assertion macros. Assertion messages should explain intent or identify a case rather than repeat values the macro already reports.
- Use synthetic payloads, invented domains, and controlled local protocol peers. Automated tests must not depend on live proxies, public DNS, developer credentials, or the user's resolver configuration.
- Inject configuration and timing into tests. Avoid process-global environment mutation in parallel tests. Await tasks and join threads, checking results so background failures cannot pass unnoticed. Use a controlled clock for timer-only tests when practical. Tests that start application-owned services must verify shutdown and task cleanup; purely synchronous tests need no artificial lifecycle harness.
- Exercise route conflicts, delayed/uncertain ACKs, TTL expiry, retries, cancellation, abrupt termination, rollback, and recovery when modifying those behaviors. Review changed-code coverage; line coverage alone does not prove complete path coverage.
- Benchmark networking changes against reproducible controlled workloads, measuring latency distributions, throughput, CPU, memory, transferred bytes, and drops. Record environment and conditions in artifacts rather than claiming Rust is automatically faster.
- Run the checks appropriate to the change, as documented in `docs/development.md`. Documentation-only changes do not require Rust compilation. Workflow changes require actionlint with ShellCheck installed, and every change requires `reuse lint` and whitespace review.
- Host networking acceptance requires disposable namespaces with private mounts/state and a dedicated resolver/bus, or a disposable VM. Namespaces alone do not isolate the host system bus or filesystem. Never mutate the user's live resolver during automated tests. The harness must clean up independently of warper.
- Follow the definition of done in `docs/implementation-plan.md` section 8.4 and acceptance IDs in `docs/acceptance.md`. Missing native/macOS or privileged evidence remains explicitly not run.

### Assertions and coverage

- Use Rust's native `assert!`, `assert_eq!`, and `assert_ne!`; use
  `assert!(matches!(...))` for error variants and other pattern checks. Avoid
  hand-written comparisons followed by `panic!` or adding an assertion library
  for checks the standard macros already express.
- Assertion messages should explain why a check matters or identify the table
  case. Do not repeat values already shown by `assert_eq!` or `assert_ne!`.
- Join spawned threads and await spawned Tokio tasks, checking their results
  so worker panics fail the test. Check server-side expectations before the
  test ends; failures in detached workers must not pass unnoticed.
- Review coverage for changed code, including error and boundary paths. With
  [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) and the toolchain's
  `llvm-tools-preview` component installed, generate a report with:

  ```sh
  cargo llvm-cov --locked --all-features --html
  ```

  Inspect uncovered code alongside the assertions. Line coverage alone does
  not establish complete path coverage. Report unavailable coverage tooling
  rather than claiming coverage was checked.

### Fixtures and test doubles

- Use invented sample content and synthetic credentials in tests, fixtures,
  examples, and documentation. Scrub real sample content and secrets from
  recorded HTML or JSON before committing it. Preserve software and protocol
  names, required keys, and values that the behavior under test depends on,
  such as DNS record types and SSH identification strings.
- Preserve Unicode coverage with invented non-ASCII values. Build minimal
  payloads inline or in tracked fixtures, and create temporary files per test.
  Tests must not depend on a developer's `.env`, credentials, or local state.
- Use `sample` for an input when it needs distinguishing from its result.
  Use `test_*` or `fixture` for canned payloads; `fixture` can also name a
  prepared test setup. A prefix is required only when a bare name would confuse
  the input with the value under test; clear role names are also fine.
- A `test_server` serves canned responses. Descriptive names such as `login`
  or `server` are also appropriate. Call it a mock only when it verifies
  programmed request expectations.
- A `stub` implements a trait with fixed answers and records or asserts
  nothing. A `fake` is a working in-memory implementation. A `mock` verifies
  preprogrammed call expectations. These terms describe behavior, not generic
  synthetic data.

### Test names and tables

- Use descriptive `snake_case` names: `function_scenario` or
  `type_method_scenario` for a single unit, and plain behavior names for flows
  spanning several units. Follow the surrounding tests' naming shape.
- Share setup with table cases when it improves clarity; use separate test
  functions for scenarios needing distinct setup. No subtest framework is
  required.
- For structured tables, use a local `Case` struct and iterate as `case`.
  Put the case identifier first when one is needed, then inputs, then
  expectations named `expected` or `expected_*`. Keep fields alphabetical
  within each input and expectation group, in the struct and its rows.
- When a case has an identifier, include it in assertion messages so a failed
  row can be located. Put a case-specific comment above that row's first field.
  Small tuples are fine when their roles remain clear.

## CI and releases

- Keep `.github/workflows/ci.yml` usable on pull requests, pushes to `main`, manual dispatch, and reusable `workflow_call`. Its tested repository-stage harness explicitly skips Cargo jobs until the root manifest exists; a manifest without its lockfile or toolchain file must fail, as must Rust sources or nested manifests without a root workspace.
- Match local commands to CI. Add relevant contract, generation, feature-combination, and platform checks when their corresponding code is introduced. Do not use silent fallbacks to conceal failures.
- Pin third-party actions to full commit SHAs with release tags in comments. Pin downloaded tool versions and verify published checksums. Use least-privilege workflow permissions, explicit timeouts, and cancellation of superseded branch runs.
- Do not execute untrusted pull-request code with publishing credentials or use `pull_request_target` to build it. Pass event-controlled values through environment variables rather than interpolating them into shell code.
- Release automation follows a runnable artifact. It must invoke CI for the exact tagged commit before packaging or publishing, validate version tags, exercise supported targets, and publish checksums. Keep write permissions confined to publishing jobs; provide a manual build-only dry run.
- Document supported platforms and packaging before adding release jobs. Do not add a successful placeholder deployment or publish planning-only releases.
- Run `scripts/check.sh` for local infrastructure and stage-appropriate Rust checks. Workflow changes require actionlint with ShellCheck installed, composite action validation with `scripts/lint_actions.py`, and the Python harness tests. Shell script changes require ShellCheck. Native compile/tests are separate from privileged networking acceptance.
- Configure shared lints in root `[workspace.lints]` tables and inherit them in every package. Deny introduced warnings without broad allowances; check dependency policy with `cargo deny --locked check`. Add relevant feature combinations when their code exists.
- When introducing `client/`, pin its package manager/dependencies, commit its lockfile, and add frontend unit/type/lint/build checks plus Tauri native packaging checks. Add Linux GUI build dependencies then; do not add placeholder frontend jobs now. macOS public bundles need signed/notarized distribution and native helper lifecycle evidence; local development may use an explicit ad-hoc signing/test setup without a paid identity, never a blanket authorization bypass.
- Follow ADR 0005 for no-paid-account macOS integration: explicit development-only build/launch mode, administrator-enrolled exact code identities/owner, and mutual peer checks. UX-05 must run without Apple-issued developer signing identities; release-signed tests cannot substitute. Rebuilds require re-enrollment, and production artifacts must reject the mode. Missing macOS evidence leaves that gate open without blocking independent Linux work.

## Documentation and licensing

- Use American English and explain current behavior, constraints, and invariants. Put bug history and per-run validation results in commit messages or CI logs. Keep documentation commands and API names current.
- Use the terms defined in `docs/glossary.md` in the contract, code, and documentation. Prefer established terms from DNS, SSH, SOCKS5, WireGuard, and IP networking over invented ones, and update the glossary before introducing or redefining a domain term.
- Wrap ordinary prose near 80 columns where practical; keep paragraphs and bullets in this file on single lines so each rule remains a reviewable unit. Explain non-obvious reasons in source comments without narrating obvious code.
- Apply SPDX copyright and MIT license headers to new handwritten files. Preserve existing and third-party notices. Keep license texts in `LICENSES/`; add explicit REUSE annotations for generated files, binaries, and formats without comments when those files are introduced.
- Run `reuse lint`; do not label third-party assets MIT unless their actual license permits that attribution.

## Commit messages and history

- Use Conventional Commits: `type(scope): concise imperative summary`, lowercase after the colon and without a trailing period. Choose a concrete subsystem scope when appropriate.
- Keep one cohesive change and its supporting refactors and tests in one atomic commit. Every commit must pass the checks applicable to its contents.
- For nontrivial commits, add a blank line and body bullets explaining observable behavior, important implementation details, and relevant validation. Write complete sentences ending with periods; avoid file-by-file narration.
- When rebasing, amending, or squashing, keep `GIT_COMMITTER_DATE` equal to `GIT_AUTHOR_DATE`.
