<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0004. Tauri desktop with an independently supervised networking service

- Status: accepted product/architecture direction; implementation and native
  authorization/packaging evidence pending.
- Date: 2026-10-26
- Related: [service/client contract](../service-and-client.md),
  [configuration contract](../configuration.md), NET-09 and UX-01–UX-05 in
  the [acceptance contract](../acceptance.md).

## Context

Routing and DNS should survive closing the monitoring window. Running a
desktop webview with administrator privileges is unnecessary, and a GUI
child process is not a substitute for OS-supervised service installation.
macOS distribution should provide one app containing both client and helper.

## Alternatives

- Keep the network engine attached to a terminal UI. Closing it owns the
  routing lifetime and requires a terminal for normal use.
- Run an elevated GUI or spawn a helper as a regular sidecar. This couples
  presentation to privileges and does not establish persistent supervision.
- Use a normal-user Tauri client plus a separate Rust service, with native
  registration, authenticated local control, and explicit connection intent.

## Decision

Use Tauri 2 for the primary desktop; remove the TUI from required scope.
`warperd` owns networking, recovery, and reconnects. The desktop and optional
`warper` CLI share a typed control contract and never start a second engine.
Closing or quitting the GUI leaves routing active; Disconnect is explicit.

Bundle the macOS client and service in one `.app` targeting macOS 13+.
Register the bundled LaunchDaemon through SMAppService and represent OS
approval separately from connectivity. Use XPC on macOS and a protected
Unix-domain socket on Linux, with actual OS identity and scoped authorization.
Prove registration/enrollment/peer verification in a native spike before
production integration. The detailed service/client contract defines the
UX, lifecycle, security boundary, and packaging acceptance requirements.

[ADR 0005](0005-macos-development-authentication.md) defines the separate
no-paid-account local mode, with explicit administrative enrollment and exact
build pins instead of a stable developer identity. UX-05 must prove it;
release-signed installation tests do not substitute for that evidence.

The service reads approved managed configuration rather than a user's home
at boot. Existing YAML remains an import/offline-validation format. Treat
protocol correctness and intentional routing/security policies separately;
RFC conformance does not imply identical application behavior.

## Consequences

- There are independent GUI and service processes, rather than one executable
  owning a terminal session. Optional CLI tooling supports diagnosis and
  automation without becoming the main desktop experience.
- Add shared control types, a service executable, a thin control client, and
  the Tauri host/frontend only when their phases need them.
- Normal observation and Connect/Disconnect do not run the GUI as root.
  Enrollment, credentials, configuration installation, and recovery have
  explicit privilege/ownership rules; missing authorization fails clearly.
- macOS needs native Service Management integration, signing/notarization,
  and tested update/uninstall behavior. A Tauri app build alone is insufficient.
- Linux service/package integration remains required. GUI code adds native
  build dependencies and frontend checks when introduced.
- This supersedes the terminal-UI and single-executable product choices in
  the initial plan. It does not accept any pending networking stack choice.

## Validation and Reconsideration

Exercise NET-09 and UX-01–UX-05 with ordinary/unauthorized users, malformed or
incompatible messages, client exits, slow observers, duplicate operations,
service crash/recovery, sleep/wake, and explicit Disconnect. Native macOS
evidence must cover service approval/denial/revocation, signed-bundle first
launch, upgrade, uninstall, and reboot. Keep evidence in ignored artifacts
and record remaining gates in the phase ledger.

Revisit the transport or enrollment design if the native spike cannot
establish the required authorization boundary. Do not substitute a privileged
webview, unchecked caller identity, generic command execution, or implicit
configuration-file reads to get a prototype working.
