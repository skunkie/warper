<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0002. Userspace stack selection

- Status: proposed; packet experiments exist, but no production stack is selected.
- Date: 2026-10-26
- Related: [plan section 2.1](../implementation-plan.md#21-dependency-and-stack-feasibility-gate),
  [implementation contracts](../implementation-contracts.md), NET-01,
  NET-05, NET-06, and NET-07 in the [acceptance contract](../acceptance.md).

## Context

Two independent capabilities are required: accepting transparent TCP/UDP
flows from host TUN packets, and actively dialing sockets through a userspace
WireGuard tunnel. A library implementing one role does not prove it supports
the other. The choice must preserve original destinations, cancellation,
bounded buffers, half-close, and datagram semantics on Linux and macOS.

## Alternatives

Evaluate pinned versions/APIs of `ipstack`, `netstack-smoltcp`/`smoltcp`,
and any justified alternatives. A configured proxy runner is usable only if
its embedding/dispatch boundary meets the contract. A local proxy bridge or
fork requires explicit maintenance/extra-hop analysis. Do not infer accepted
capabilities from dependency names or README descriptions.

## Decision

Pending Phase 0. Fill in exact selected versions/features, role-specific API
calls, supported platforms/families, adapter responsibilities, and reasons
for rejecting alternatives after executable probes. Do not accept the ADR
until both role gates pass against controlled peers and the initial
implementation contracts have compile-checked usage.

### Experimental evidence and remaining selection work

The workspace pins `netstack-smoltcp` 0.2.4 (MIT OR Apache-2.0), `smoltcp`
0.12.0 (0BSD), and BoringTun 0.7.1 (BSD-3-Clause). Smoltcp 0.12 is deliberate
for this comparison: it matches the wrapper's dependency. It is not a
decision to use that older stack in production. Evaluate released smoltcp
0.14 and upstream fixes before choosing an adapter or maintaining a fork.
`deny.toml` permits the actual 0BSD dependency license; nothing is relicensed.

Sources and executable usage:

- [Wrapper 0.2.4 source](https://docs.rs/crate/netstack-smoltcp/0.2.4/source/src/):
  `StackBuilder::build`, `Stack` as packet sink/stream, `TcpListener` as
  `(TcpStream, source, destination)`, and UDP split read/write message
  operations are exercised by `experiments/host-stack/src/main.rs`.
  Enable TCP/UDP explicitly, use MTU 1280, channel depths 8, and TCP windows
  8192 bytes. The wrapper transitively enables smoltcp `std`, `log`,
  `medium-ip`, IPv4/IPv6, and TCP/UDP/ICMP sockets.
- [Smoltcp 0.12 sockets](https://docs.rs/smoltcp/0.12.0/smoltcp/socket/index.html):
  `Interface::context`, `tcp::Socket::connect/listen/close`, and UDP
  `send_slice/recv` create actual active flows. Both probes use the bounded
  `Device` in `experiments/packet_peer.rs`; direct features are `std`,
  `medium-ip`, `proto-ipv4`, `proto-ipv6`, `socket-tcp`, and `socket-udp`.
- [BoringTun 0.7.1 tunnel API](https://docs.rs/boringtun/0.7.1/boringtun/noise/struct.Tunn.html):
  `Tunn::new`, `encapsulate`, `decapsulate` (including empty-input draining),
  `update_timers`, and `stats` are exercised in
  `experiments/wireguard-stack/src/main.rs`. Default features are disabled;
  no kernel WireGuard interface or BoringTun device backend is used.

The wrapper's nonempty UDP and TCP response-after-FIN/shutdown checks work
with both inner address families. Its UDP writer silently discards empty
datagrams; the full host probe reproduces this as a deadline failure. It
therefore fails required datagram semantics and is not accepted unchanged.
Its TCP implementation also contains unbounded accepted-stream, socket
creation, and packet channels and creates sockets on SYN, so bounded public
channel/window knobs alone cannot establish bounded aggregate ownership.
Its runner contains an upstream unsafe `Send` implementation; our probe
runs on one Tokio thread and does not establish that boundary's soundness.

`ipstack` 1.0.1 (Apache-2.0) source inspection finds unbounded session,
acceptance, and outbound queues, plus internally spawned workers without a
public join operation. It is not in the workspace and has not been traffic
tested. This is an unresolved resource/supervision issue, not evidence that
its transport semantics fail. `tun2proxy` is not used as an embedding proxy
bridge. No local fork or extra-hop bridge has been introduced.

Active smoltcp sockets exchange TCP/UDP over real IPv4 loopback UDP between
two BoringTun peers, with IPv4/IPv6 inner traffic, empty datagrams, and
half-close. The optional sustained probe checks timer-driven rekey. These
experiments are portable Rust code, but observations so far are Linux ARM64
only; no macOS or independent peer claim follows. No throughput/CPU/RSS
performance budget is established. Library maintenance review, MSRV/platform
validation, larger transfers, fragmentation/ICMP, resource exhaustion,
cancelled/stalled traffic, and independent kernel-peer tests remain open.

Prototype ownership and limits are recorded in the
[contract progress](../implementation-contracts.md#6-experimental-boundaries).
Run `scripts/verify-feasibility.sh` as described in the development guide;
raw outcomes and exact environments belong in `target/evidence/phase-0/`.

## Consequences

Until accepted, keep experimental packages isolated from production-facing
interfaces. The adapters may differ by role; the production workspace must
hide third-party types behind the contracts needed by its next working
slice. Record any fork, unsupported behavior, or platform limitation before
dependent implementation begins.

## Validation and reconsideration

Phase 0 has an initial `scripts/verify-feasibility.sh` with documented
packet-only scope and clean-checkout setup. Required gate entry points are:

```sh
./scripts/verify-feasibility.sh host-stack
./scripts/verify-feasibility.sh wireguard-stack
```

These commands remain nonzero until all required evidence is implemented;
explicit `--packet-only` runs expose the narrower experiment result.
Artifacts go under `target/evidence/phase-0/`, with exact environment,
dependency versions, assertions, redacted traffic summaries, cancellation,
cleanup, IPv4/IPv6, and rekey results. Record native macOS evidence separately.
Revisit on a failed required capability, dependency API change, unsupported
platform behavior, or unacceptable maintenance cost.
