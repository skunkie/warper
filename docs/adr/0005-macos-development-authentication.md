<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0005. macOS development authentication without a paid signing identity

- Status: accepted policy; native implementation and UX-05 evidence pending.
- Date: 2026-10-26
- Related: [desktop/service decision](0004-desktop-service.md),
  [service/client contract](../service-and-client.md), and UX-05 in the
  [acceptance contract](../acceptance.md).

## Context

Local development must be usable without Developer ID certificates, paid
membership, or notarization. Ad-hoc signatures identify a specific build,
so the release policy's stable developer identity cannot authenticate them
across changed builds. The local mode still controls a privileged service
and therefore needs explicit code identity and owner authorization.

## Alternatives

- Require a paid distribution identity for all macOS integration work.
  This does not meet the local-development requirement.
- Accept any same-user process, claimed bundle ID, or ad-hoc-signed program.
  These do not identify an approved client build.
- Administratively enroll exact ad-hoc-signed builds in an isolated
  development installation, preserving OS peer identity and per-operation
  authorization.

## Decision

Use the final approach, with the following contract:

1. **Explicit build mode.** Compile local-integration executables with an
   opt-in `development-auth` feature that is absent from production artifacts.
   It is never a default feature or a fallback after release verification
   fails. The development helper also requires an explicit development launch
   mode. Imported YAML, an IPC request, or an environment variable cannot
   enable it in a production helper.
2. **Administrative enrollment.** A local administrative install tool/native
   authorization flow installs the selected packaged development app into a
   protected root-owned location and enrolls its actual code identities.
   Validate the installed copy, including bundle/resource signatures, after
   copying it; ordinary users cannot modify that copy while enrolled. The
   GUI itself still runs as its ordinary user. Enrollment is an explicit
   local operation, not an unauthenticated daemon method accepting file paths.
3. **Protected trust manifest.** Store a bounded, versioned manifest at
   `/Library/Application Support/warper/development/trust.json`. It contains
   installation/generation IDs, enrolled non-root owner UID, and exact signing
   identifiers and OS-reported CDHash values for desktop, CLI, and helper
   roles/architectures. Limit it to 64 KiB and eight code hashes per role.
   The file is root-owned, readable but not writable by ordinary users
   (0644 under protected directories), contains no credentials, and rejects
   symlinks, malformed entries, wildcard identities, and writable ancestors.
4. **Authenticate the running peer.** Enforce the enrolled identifier/CDHash
   requirements through public XPC/Security APIs on the actual connection or
   message sender; do not validate a caller-provided executable path or look
   up identity from a reusable PID. On macOS 13+, configure
   `NSXPCConnection.setCodeSigningRequirement(_:)` before activating each
   outgoing or accepted connection, or prove an equivalent C-XPC adapter.
   Independently check the connection's OS effective UID. A desktop peer must
   be the enrolled owner; an approved CLI may be that owner or root, with
   administrative operations still requiring their existing authorization.
   The role comes from the enrolled code identity, not a request field.
5. **Verify both directions.** Clients connect to the system-domain helper
   and require its enrolled code identity and root OS identity. Begin with a
   non-sensitive nonce/version exchange; verify the reply's actual peer
   before transmitting configuration or credentials. The helper verifies
   clients before disclosing state or executing operations. The native test
   must prove that an impostor receives no secret or privileged request even
   if an outgoing XPC message is delivered before a signing error surfaces.
6. **Rebuilds require re-enrollment.** Stop/disconnect the development service
   and clients before replacing their packaged code/resources. Rebuild and
   ad-hoc-sign the final bundle, then administratively replace the installed
   copy and its manifest atomically before re-registration/restart. Changed
   hashes fail until re-enrolled; no trust-on-first-use or automatic pin
   refresh is allowed. Drop old connections/generations rather than allowing
   a previously approved process to retain access to the new installation.
7. **Separate development from release.** Use distinct service identifiers,
   managed state, and trust/configuration stores. Retain the global network
   instance lock so development and production engines cannot compete. A
   production helper ignores development manifests and rejects development
   enrollment/mode switches. Real integration uses sealed packaged UI assets;
   live frontend development servers use unprivileged fixtures instead of
   acquiring privileged service access. Preserve normal code-integrity
   protections; do not broadly disable signing checks or injectability rules.

The development-only administrative command is
`warperd dev install --app PATH --owner USER`; it requires local administrator
authorization and a stopped/disconnected development instance. It copies and
validates the selected packaged app, resolves USER to a non-root OS UID,
and atomically enrolls the installed copy's exact identities. The development
LaunchDaemon uses `warperd service --development-auth`. Both the `dev` command
and `--development-auth` are absent/rejected in production artifacts. These
are implementation requirements, not existing commands; the native harness
must exercise them without running the GUI as root.

The native spike must verify every API used against the macOS 13 minimum.
Unavailable APIs or failed enforcement block that platform gate; they are
not reasons to fall back to UID-only or caller-claimed identity checks.

## Consequences

- Local bundled integration has no dependency on paid signing identities or
  notarization, while still requiring administrator service approval and
  explicit enrollment of trusted code.
- Changing code/resources requires another local administrative enrollment.
  The development harness must make that step reproducible; it cannot claim
  seamless identity continuity across ad-hoc builds.
- A development success is distinct from the Developer ID/notarized public
  distribution gate. Both have their own acceptance evidence.
- Privileged integration runs from a protected packaged copy. Fast frontend
  iteration remains possible through a nonprivileged client fixture adapter.

## Validation and Reconsideration

UX-05 is mandatory on a disposable macOS 13+ system without an available
Apple-issued developer signing identity or notarization credentials. It must
cover actual bundled registration/approval, administrative owner enrollment,
two-way authenticated IPC, client quit/reconnect, changed-build rejection and
re-enrollment, impersonation, invalid manifests, cleanup, and unregistration.
Production artifact checks must reject the development feature/mode.

Add the runnable harness during the native spike, not a successful placeholder
now. Keep commands and manual OS approval steps in the development guide;
store raw evidence under `target/evidence/macos-development/` or CI artifacts.
If the policy cannot be enforced using public APIs without a paid identity,
record that failed gate and revise the design explicitly before claiming
local macOS support. Independent Linux work can continue.

References: [Apple code identity requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements),
[NSXPCConnection peer requirements](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement%28_%3A%29),
and [Apple's XPC peer-validation guidance](https://developer.apple.com/forums/thread/681053).
