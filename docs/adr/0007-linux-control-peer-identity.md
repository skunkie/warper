<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0007. Linux control peer identity

- Status: accepted for the initial peer-check boundary; service integration pending.
- Date: 2026-10-30
- Related: [local control](../service-and-client.md#4-local-control-and-privilege-boundary),
  [initial interfaces](../implementation-contracts.md#6-initial-slice-contract), UX-01.

## Context

Local control must authorize the enrolled owner and administrator without
trusting a request's claimed UID/PID/path. Before any handler sends metadata or
accepts mutations, it needs real OS peer evidence and trusted service policy.
The current CLI remains offline; no control listener or enrollment store exists.

## Alternatives

- Socket filesystem permissions alone do not replace peer authorization and
  cannot identify an administrative action's caller.
- Caller-supplied identities or executable/PID names are not OS proof and can
  introduce spoofing and process-reuse races.
- Per-message credentials need bounded ancillary-message handling and different
  descriptor-delegation semantics; that is not implemented by this boundary.

## Decision

Use the existing pinned nix 0.31.3 safe APIs behind `warper-control::unix` on
Linux. Verify kernel socket type, address family and connection before reading
SO_PEERCRED. Expose only an adapter-owned UID snapshot with a private constructor,
not nix types or a deserializable claimed identity. Debug/errors reveal no UID,
PID, owner record or payload. Reject the reserved invalid UID value.

An immutable `OwnerPolicy` is supplied by a future protected state loader.
The owner may observe/operate; UID 0 may administer, including bootstrap before
owner enrollment. Foreign callers receive the same denial independent of owner
presence. Client verification requires a UID-0 service peer. This is not an
enrollment write, endpoint verification, version negotiation or complete API.

UIDs are relative to the receiver's user namespace. Linux can translate an
unmapped identity to an overflow UID; a numeric snapshot cannot disambiguate
that alias. See [user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html).
Trusted UID-namespace admission is now mandatory before either native endpoint
can construct peer credentials. [ADR 0008](0008-initial-user-namespace.md) records
the guarded procfs implementation and initial/nested/counterfeit/overmount
evidence. A UID-0 namespace peer is not automatically host root. Protected
endpoint ownership, enrollment and messaging remain independent gates.

On macOS the native adapter returns UnsupportedIntegration. UID-only checks
cannot satisfy ADR 0005's exact code-identity and mutual-authentication gates.

## Consequences

Functions synchronously inspect caller-owned descriptors without reading or
writing payload, spawning tasks, retrying or closing sockets. Callers retain
connection ownership and must deny/close on failure. There is no queue or frame
allocation and no network-round-trip deadline. Credential snapshots describe
connection establishment, not liveness or executable identity. An authorized
process can delegate its descriptor; this is not an executable sandbox.

Service integration must establish trusted namespace and protected endpoint
ownership, versioned bounded messages and durable administrative enrollment
before control requests or secrets are transmitted. Recheck current policy per
request and retire connections/subscribers on owner replacement. These remain
open implementation gates; CLI service operations remain unsupported.

## Validation and reconsideration

```sh
cargo test --locked -p warper-control
scripts/check.sh
cargo llvm-cov --locked -p warper-control --all-features --html
```

Controlled Linux socket pairs compare real credentials with the creating
process's effective UID, exercise owner authorization/service rejection, and
reject wrong-type, wrong-family and unconnected descriptors. Synthetic cases
cover administrator/owner/foreign decisions and reserved UID values. A public
API compile-fail test rejects a forged constructor. No host resolver, protected
store, listener path or networking state is modified. Restricted sandboxes may
deny socket inspection; preserve that failure separately from approved runs.

Evidence: `target/evidence/phase-1/linux-peer-auth/`. Native macOS, actual host
UID-0 host peer integration, namespace-overflow alias scenarios, persistent enrollment,
protected listener lifecycle and full UX-01 remain unverified. Reconsider for
descriptor-delegation requirements, namespace/identity semantics changes, or
new administrative authorization mechanisms before adding handlers.
