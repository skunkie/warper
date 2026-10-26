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

The workspace pins `netstack-smoltcp` 0.2.4 (MIT OR Apache-2.0), direct
`smoltcp` 0.14.0 (0BSD, upstream MSRV 1.91), and BoringTun 0.7.1
(BSD-3-Clause). The wrapper transitively retains smoltcp 0.12.0; this
duplicate is deliberate for candidate comparison. Direct host interception
and the controlled peers now use released smoltcp 0.14, without a fork.
`deny.toml` permits the actual 0BSD dependency license; nothing is relicensed.

Sources and executable usage:

- [Wrapper 0.2.4 source](https://docs.rs/crate/netstack-smoltcp/0.2.4/source/src/):
  `StackBuilder::build`, `Stack` as packet sink/stream, `TcpListener` as
  `(TcpStream, source, destination)`, and UDP split read/write message
  operations are exercised by `experiments/host-stack/src/main.rs` with
  `cargo run --locked -p host-stack -- --wrapper`.
  Enable TCP/UDP explicitly, use MTU 1280, channel depths 8, and TCP windows
  8192 bytes. The wrapper transitively enables smoltcp `std`, `log`,
  `medium-ip`, IPv4/IPv6, and TCP/UDP/ICMP sockets.
- [Smoltcp 0.14 sockets](https://docs.rs/smoltcp/0.14.0/smoltcp/socket/index.html):
  `Interface::context`, `tcp::Socket::connect/listen/close`, and UDP
  `send_slice/recv` create actual active flows. Both probes use the bounded
  `Device` in `experiments/packet_peer.rs`; direct features are `std`,
  `medium-ip`, `proto-ipv4`, `proto-ipv6`, `socket-tcp`, and `socket-udp`.
  The direct host candidate in `experiments/host-stack/src/direct.rs` uses
  `Interface::set_any_ip`, explicit default routes through its local
  interface addresses, fixed `SocketStorage`, and UDP `local_address`
  metadata. Those routes belong only to the userspace interface; no kernel
  route is modified.
- [BoringTun 0.7.1 tunnel API](https://docs.rs/boringtun/0.7.1/boringtun/noise/struct.Tunn.html):
  `Tunn::new`, `encapsulate`, `decapsulate` (including empty-input draining),
  `update_timers`, and `stats` are exercised in
  `experiments/wireguard-stack/src/main.rs`. Default features are disabled;
  no kernel WireGuard interface or BoringTun device backend is used.

The wrapper's nonempty UDP and TCP response-after-FIN/shutdown checks work
with both inner address families. Its UDP writer silently discards empty
datagrams; the explicit wrapper probe reproduces this as a deadline failure. It
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

The default host probe evaluates direct smoltcp 0.14 instead. Two fixed
destination-specific handlers each own one TCP slot and one UDP socket.
Concurrent 64 KiB streaming echoes use distinct payloads and append distinct
handler trailers after request FIN, establishing full-duplex transfer,
original addresses, and deterministic handler dispatch. Empty and unequal
UDP datagrams retain their boundaries and source metadata. An occupied
TCP slot rejects another source without displacing its established owner.
Stalling application reads fills the fixed receive window and stops sender
admission at the combined window/buffer bound. Cancellation is explicit and
idempotent, aborts/closes sockets, discards queued packets, and refuses new
input. The tests use a controlled clock and bounded packet steps.

This closes the immediate empty-datagram experiment gap without depending
on the wrapper's internal workers or queues. It does not select a production
adapter: destinations and slots are fixed before the run, handlers are
in-process controlled echoes, and there is no general asynchronous
accepted-stream interface or dynamic destination admission yet. General
admission, UDP overload accounting, ownership handoff, and supervised
production scheduling still need executable contracts and traffic evidence.

Active smoltcp sockets exchange TCP/UDP over real IPv4 loopback UDP between
two BoringTun peers, with IPv4/IPv6 inner traffic, empty datagrams, and
half-close. The optional sustained probe checks timer-driven rekey. These
experiments are portable Rust code, but observations so far are Linux ARM64
only; no macOS or independent peer claim follows. No throughput/CPU/RSS
performance budget is established. Library maintenance review, MSRV/platform
validation, larger/varied workloads, fragmentation/ICMP, aggregate resource
stress, WireGuard cancellation/outages, and independent kernel-peer tests
remain open. Packet-level admission, cancellation, and stalled-reader
observations do not close their kernel/application acceptance gates.

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
