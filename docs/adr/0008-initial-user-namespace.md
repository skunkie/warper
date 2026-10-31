<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0008. Initial user-namespace admission

- Status: accepted for Linux namespace admission; full control integration pending.
- Date: 2026-10-31
- Related: [peer boundary](0007-linux-control-peer-identity.md),
  [local control](../service-and-client.md#initial-linux-peer-boundary), UX-01.

## Context

Peer UIDs are reported in the receiver's user namespace. Nested namespace root
must not be mistaken for the privileged host service. Linux may report overflow
UID aliases, so numeric credential validation alone cannot establish the trusted
namespace. Both client and service need admission before interpreting peers.

## Alternatives

- Comparing with PID 1 is insufficient when the PID namespace is nested.
- NS_GET_PARENT returning EPERM can also mean an ancestor is outside the caller's
  scope; it is not proof of the initial namespace. See the
  [namespace ioctl contract](https://man7.org/linux/man-pages/man2/NS_GET_PARENT.2const.html).
- Identity-looking uid_map text is not an initial-namespace identity proof and
  is vulnerable to a counterfeit proc view unless lookup itself is secured.
- Caller-provided anchors, namespace paths or environment overrides would let an
  untrusted launch context select its own authority. Do not expose them.

## Decision

Admit only the initial Linux user namespace, using the reserved kernel identifier
PROC_USER_INIT_INO / USER_NS_INIT_INO (`0xEFFFFFFD`). The identifier is present in
the [Linux 6.12 implementation](https://github.com/torvalds/linux/blob/v6.12/include/linux/proc_ns.h)
and newer [public nsfs definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/nsfs.h).
[systemd](https://github.com/systemd/systemd/blob/main/src/basic/namespace-util.c)
also uses initial namespace inode identifiers. Unknown or unverifiable evidence
fails closed; no uid_map, PID 1 or EPERM fallback is provided.

The safe released rustix 1.1.5 adapter in `warper-control::namespace` opens fixed
`/proc` with O_PATH/directory/nofollow/close-on-exec flags, verifies procfs and
directory metadata, and opens `thread-self/ns/user` using openat2 with BENEATH,
NO_XDEV and NO_MAGICLINKS. O_PATH/NOFOLLOW intentionally opens the final symlink
itself, without following its magic link. It verifies symlink type, procfs and
the same device, then reads that pinned link through readlinkat's empty-path
form into a 64-byte buffer. Truncation, malformed data, wrong filesystems,
submounts and noninitial identifiers reject admission. No caller path is accepted.

Every native `peer_credentials` call performs admission before socket inspection;
both authentication directions use it. The bare policy evaluator is crate-private
to prevent external consumers from bypassing native admission. Missing openat2
support returns a typed failure; the initial capability requires Linux 5.6 or
an equivalent supported backport. No new unsafe code or third-party fork is used.

## Consequences

The synchronous check uses bounded fixed metadata and closes owned descriptors
on every return. It performs no credential-file read, payload I/O, listener
creation, enrollment write or host network mutation. It does not prove mount,
PID or network namespace admission, socket ownership, liveness, capabilities,
code identity, protocol compatibility, or a completed control operation.

Rootless/containerized clients outside the initial user namespace are rejected
rather than given a weaker UID policy. Native integration must not change user
namespace between authorization and the corresponding operation. No cache/token
or process-global bootstrap flag can substitute for the per-credential check.
OS metadata calls are synchronous without a hard wall deadline.

Production-control networking acceptance must therefore use a disposable VM or
a privileged fixture that keeps the initial user namespace while separately
isolating mounts/network state and its resolver/bus. Rootless user-namespace
fixtures remain valid for stack probes and negative admission tests; do not add
a control-authentication bypass to make a service integration fixture pass.

macOS remains UnsupportedIntegration until ADR 0005 is implemented. Linux
protected endpoints, administrative owner storage, message bounds/versioning,
revocation and real service/networking operations remain open.

## Validation and reconsideration

```sh
cargo test --locked -p warper-control
cargo build --locked -p warper-control --example namespace
target/debug/examples/namespace --expect-initial
unshare --user --map-root-user --fork --kill-child=KILL target/debug/examples/namespace --expect-nested-root
unshare --user --map-root-user --mount --fork --kill-child=KILL bash -c 'mount --make-rprivate /; exec "$1" --expect-self-overmount-rejected' bash "$PWD/target/debug/examples/namespace"
scripts/check.sh
```

Native positive tests require initial-namespace access and socket inspection;
the restricted agent sandbox is not that context. The read-only initial probe
passes, and real namespace-local UID 0 is denied at all three peer entry points.
An independent timeout/group supervisor additionally verifies counterfeit procfs
and same-procfs overmount rejection inside disposable user/mount namespaces,
then verifies parent admission and owned temporary-directory removal. The mount
attack mode targets only the probe's own ns directory after proving nested root;
it must run in the disposable fixture, never a service or live host namespace.

Raw scripts, results, source hashes and cleanup checks are under
`target/evidence/phase-1/user-namespace-admission/`. No live resolver, bus, route,
protected owner record or host mount state was changed. The probes do not close
UX-01 or privileged networking acceptance. Native macOS and actual host UID-0
peer success remain unverified. Reconsider if kernel identifiers/procfs lookup
semantics change or container clients become a required capability.
