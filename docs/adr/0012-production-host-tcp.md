<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0012. Production host TCP owner

- Status: accepted initial TCP adapter; kernel/service integration pending.
- Date: 2026-10-31
- Related: ADR 0002, ADR 0011, contract section 28, NET-01.

## Context and alternatives

Phase 0 established direct smoltcp interception and wake-driven ownership with
controlled packet peers and isolated kernel TUN traffic. Production networking
needs a focused adapter that imports core policy and transport types, without
importing experiment modules. Making core depend on smoltcp would expose stack
lifetimes to protocol implementations. Promoting the whole experiment would
also expose unfinished UDP, PMTU and platform responsibilities together.

## Decision

Introduce `warper-stack` with a private bounded packet device and a TCP host
adapter. Select an immutable core policy once for each new flow. Export core
metadata and boxed asynchronous streams; keep stack types private. Preserve
both FIN directions and charge retired application streams until their last
handle drops. Purge adapter-owned delayed ingress for a retiring tuple before
its listener slot can be reused.

Use fixed MTU 1280 and at most sixteen flow slots. Reject fragments, IPv4
options, IPv6 extension headers and non-TCP packets explicitly. The initial
service must reject configurations requiring unsupported capabilities before
host mutation. Experimental reassembly, UDP and expanded PMTU support are not
promoted by this decision.

A single owned runtime future drives the stack through bounded packet channels,
application wakeups and stack/lifecycle deadlines. Advance the monotonic clock
before admitting delayed input. Bound each output turn to eight packets and
preserve lifecycle deadlines while the output consumer is blocked. Owner loss
is an error; explicit shutdown cancels flows and discards owned pending packets.
The service must retain and join the runtime task, packet I/O and relay tasks.

Construct opaque seeds using native nonblocking Linux entropy. Short reads and
OS failures are typed errors; there is no configured seed or weak fallback.
Other platforms return unsupported integration until their entropy boundary is
implemented. Synthetic seeds are confined to tests and controlled peer fixtures.

## Consequences and evidence

Payload-buffer reservations are calculable before allocation. They exclude
allocator metadata, kernel I/O, protocol relay and OS socket buffers, which the
service must budget separately. Admission reserves the accepted-flow queue
before creating a listener. Active socket slots and retained stream charges
have independent lifetimes. Unsupported or exhausted admission never falls
back to direct traffic.

```sh
cargo test --locked -p warper-stack
cargo llvm-cov --locked -p warper-stack --all-features --html
cargo run --locked --release -p warper-stack --example host_workload
scripts/check.sh
```

Controlled IPv4/IPv6 peers verify original tuples, backend IDs beyond sixteen
bits, exact 64 KiB transfers and response after FIN. Boundary tests cover queue
exhaustion, invalid input, cancellation, idle/absolute/setup expiry, reset,
application loss, consumer loss and joined owner abort. A negative control
removing the retirement purge fails the replacement-flow handshake regression.

The release workload records latency distributions, application bytes, packet
counts, queue drops, CPU ticks and process RSS for 100 in-process TCP echoes in
batches of four. The peer stack shares the measured process; this is neither a
kernel TUN baseline nor a Rust/Go comparison. Raw results, environment, hashes
and coverage review belong under
`target/evidence/phase-1/host-tcp-adapter/`.

Kernel TUN ownership, physical-path protection, authenticated service sessions,
configuration preflight, journaled rollback/recovery and service lifecycle
acceptance remain separate Phase 1 requirements. Native macOS integration and
later production protocols remain open.
