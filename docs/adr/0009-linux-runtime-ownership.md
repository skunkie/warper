<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0009. Linux runtime directory ownership

- Status: accepted for the ownership boundary; service integration pending.
- Date: 2026-10-31
- Related: [peer identity](0007-linux-control-peer-identity.md),
  [namespace admission](0008-initial-user-namespace.md), UX-01.

## Context

The future listener needs exclusive ownership before publishing an endpoint.
Deleting a lock pathname on shutdown lets another process lock a new inode
while an existing holder still owns the old one. Opening unchecked runtime
objects can follow a symlink or access a device before its type is validated.
No running service, protected owner store or listener exists yet.

## Alternatives

- PID files do not provide kernel lifetime locking or prevent PID reuse.
- Locking a socket pathname couples the lock identity to endpoint replacement.
- Removing existing sockets automatically mistakes uncertain crash state for
  verified ownership. Recovery must establish its own authority and evidence.
- Configurable runtime paths or rootless ownership overrides expand the native
  security boundary. Keep fixtures private to unit tests instead.

## Decision

Use `warper_control::runtime::RuntimeLease::acquire()` for the fixed
`/run/warper/service.lock` only. Admit the initial user namespace and require
actual effective UID 0. Provision `/run/warper` externally as root mode 0755;
startup does not repair or create that directory. Verify `/` and `/run` are
root-owned directories without group/other write access. Pin directory
handles and use openat2 beneath/no-symlink resolution. Allow the normal mount
at `/run`, but reject mount crossings beneath it, including the lock entry.
No environment, CLI/YAML path, caller FD or owner override is accepted.

Create a missing lock exclusively with mode 0600. For an existing entry,
inspect with O_PATH before opening for I/O, requiring an empty regular
root-owned file with mode 0600 and exactly one hard link. Reopen without
truncation, nonblocking and close-on-exec, then compare device/inode identity.
Acquire exclusive nonblocking flock and recheck pinned directory metadata,
parent/name identities and the named lock. Reject conflict or unsafe state;
never remove or repair it. An inherited restrictive umask can cause exact mode
validation to fail; do not mutate the process-global umask to hide this.

`revalidate()` repeats namespace/identity admission and ownership checks before
later mutations. A lease closes its descriptors on drop and never unlinks the
lock or removes the directory. Errors retain OS error kinds without paths or
file contents. No third-party types or raw descriptors cross the public API.
See the native [flock](https://man7.org/linux/man-pages/man2/flock.2.html) and
[openat2](https://man7.org/linux/man-pages/man2/openat2.2.html) contracts.

## Consequences

The lease retains four descriptors and no tasks, payload buffers, queues,
retries or blocking lock waits. Filesystem syscalls remain synchronous and
have no hard wall deadline. A later async service must isolate admission from
its executor and retain ownership of unfinished workers. No unsafe code,
credential-file read, listener, enrollment or host networking is introduced.
The persistent lock contains no PID, credentials or journal data.

Root is trusted. Advisory locking cannot stop an administrator that ignores
it, swaps mounts/paths or changes permissions between checks. Integration must
serialize its operations, keep credentials/namespaces stable and retain the
lease through cleanup. Independent mount/chroot contexts can have independent
runtime directories; this is not proof of initial mount/network namespace
admission or an already integrated network-instance lock. Those remain service
startup gates before host mutations.

No stale socket is removed. Journaled recovery, listener creation, client
endpoint validation, administrative owner enrollment and bounded/versioned
messaging remain separate increments. The API is Linux-only; macOS still needs
its native helper lifecycle and authentication.

## Validation and reconsideration

```sh
cargo test --locked -p warper-control
cargo llvm-cov --locked -p warper-control --all-features --html
scripts/check.sh
```

Private temporary-directory fixtures use the executing account's real UID and
are not constructors available to production callers. They verify independent
open-description contention, reacquisition of the same inode after release,
SIGKILL/reaping of a child holder, symlink and unsafe-mode rejection, missing
state, foreign ownership, hard links, nonempty locks and replacement/removal.
The subprocess gets its fixture through Command's environment without mutating
the parent's environment. It has a bounded readiness wait and a cleanup guard.
Native namespace probes additionally reject nested UID 0 before runtime access.

Evidence belongs under `target/evidence/phase-1/runtime-ownership/`. Positive
public UID-0 acquisition in a disposable initial-user-namespace fixture,
runtime submount rejection, native macOS and complete service/networking
acceptance remain unverified. Tests never provision or modify live `/run`.
Reconsider for a different installation layout, mount policy, filesystem
locking semantics or administrator recovery requirements.
