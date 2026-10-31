<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0011. Production TCP boundary and SOCKS5 setup

- Status: accepted initial protocol boundary; physical/TUN service integration pending.
- Date: 2026-10-31
- Related: [initial contract](../implementation-contracts.md#6-initial-slice-contract), NET-01, NET-06.

## Context

Phase 0 proved boxed async TCP ownership, half-close and request cancellation.
Production protocol implementations need that boundary in core without
importing experiments or packet-stack types. Phase 1 requires real SOCKS5 TCP,
while physical-path admission, TUN ownership and the service remain separate.

## Alternatives

- Importing experiments makes production depend on feasibility-only adapters.
- A protocol-owned default direct connector hides physical-path responsibility.
- The Go implementation redials setup through proxy.Direct. Preserve external
  SOCKS framing and configuration inputs, but use bounded single-attempt setup.
- Automatically offering no-authentication with configured credentials allows
  a downgrade. Offer exactly the configured method instead.

## Decision

Promote TCP metadata, boxed streams, capabilities, Backend and Request into
`warper-core::transport`. The service constructs an EndpointConnector with
verified physical-path protection; no default connector is supplied. Request
uses one absolute deadline and cancellation owner, with cancellation on owner
loss. Setup failures retain typed categories/I/O kinds and redact diagnostics.
The core imports no backend implementation or packet-stack type.

Implement `warper-backends::socks5::Socks5` using released Tokio async I/O and
[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html) /
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.html) framing. Advertise TCP and
both destination IP families, never UDP. Send the original numeric destination
and port; do not resolve it. Credentials are optional, nonempty 1..255-byte
fields with redacted Debug; offer only the selected method. Refuse downgrade,
invalid headers, authentication failure and unknown reply fields. Consume all
IPv4/IPv6/domain bound-address bytes before returning an application stream;
never resolve or use that bound name for routing.

A nonblocking semaphore reservation covers pending setup and the whole returned
stream lifetime, including half-close. Admission fails rather than queueing.
Physical connect and negotiation share the caller's deadline/cancellation.
Failure closes owned setup and releases its permit. No retries, fallback,
background dial tasks or application payload replay exist.

## Consequences

The adapter retains at most two 255-byte credential fields, a bounded auth
buffer (513 bytes), a numeric CONNECT buffer (22 bytes) and a bound-reply buffer
(257 bytes) during setup, plus allocator/protocol/OS socket overhead. Caller
admission and data-plane buffers are separate budgets. Constructor limits
outside the semaphore's supported range fail rather than panic. Established
idle/absolute lifetimes and copying/backpressure belong to the service relay.
Scoped IPv6 socket metadata that cannot be represented on the wire is rejected.

The injected connector is a required service capability, not evidence of
physical-path protection by itself. Endpoint exemption publication, socket
binding, network-change detection, TUN/journal integration and privileged
acceptance remain open. SSH/WireGuard production backends remain later work.

## Validation and reconsideration

```sh
cargo test --locked -p warper-core -p warper-backends
cargo run --locked --release -p warper-backends --example socks5_workload
scripts/check.sh
```

Controlled duplex probes exercise each reply/error category, exact destination
bytes, UTF-8 credential byte lengths, downgrade/authentication rejection,
bound-address variants, EOF, stalled/cancelled setup and permit lifetime.
Actual local TCP proxy/target peers cover all four destination/physical IP
family combinations with concurrent transfers and response after FIN; every
peer task is joined and its byte counts checked.

The fixed release workload records 100 synthetic 64 KiB echoes in batches of
four, latency distributions, process CPU ticks/RSS, application bytes and
loopback drop deltas. It uses real local proxy/target peers and checks tasks.
It is a loopback baseline in a shared namespace, not a TUN throughput result or
a Rust/Go speed claim. Record environment and raw results under
`target/evidence/phase-1/socks5-backend/` with source hashes and coverage review.
Native macOS and privileged end-to-end service evidence remain unverified.
