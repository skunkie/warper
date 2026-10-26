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
  the candidate uses no BoringTun device backend. The optional independent
  peer fixture below configures a kernel WireGuard interface.

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

This fixed-destination comparison closes the immediate empty-datagram gap
without depending on the wrapper's internal workers or queues. A separate
TCP-only candidate in `experiments/host-stack/src/adapter.rs` now admits
selected destinations on validated SYNs and returns asynchronous accepted
streams. It preserves original tuples, per-run flow identifiers, and the
backend chosen at admission. Two sources sharing a destination occupy
distinct slots; duplicate SYNs retain their slot and identifier.

The adapter reserves lifetime-buffer and accept-queue capacity before socket
publication. An incomplete handshake has a setup deadline; accepted-stream
publication waits for handshake completion. Idle/max-age deadlines, reset,
application drop, and driver cancellation have explicit outcomes. Closed
streams retain their buffer charge until both driver and consumer drop
them, independently of reusable socket slots. Tests cover queue rollback,
both half-close orders, slow readers, and typed timeout/reset/cancellation
errors. `accepted_probe.rs` retains and joins controlled handler tasks.

This is an experimental TCP boundary, not a selected production adapter.
Production scheduling, aggregate integration stress, and kernel TUN traffic
remain unproven. Backend indices
and limits are synthetic prototype inputs, not implemented YAML/service
contracts. The [accepted TCP boundary](../implementation-contracts.md#7-experimental-accepted-tcp-boundary)
records concrete signatures, ownership, and remaining decisions.

The separate `udp_adapter.rs` candidate accepts dynamic UDP associations by
original tuple, freezes backend metadata, and publishes the first message
only after admission reservations succeed. It uses
[smoltcp 0.14 UDP representations](https://docs.rs/smoltcp/0.14.0/smoltcp/wire/struct.UdpRepr.html)
for validation/serialization, without binding one UDP socket per destination.
UDP has no transport handshake or half-close; association ownership and
deadlines belong to this adapter. A held datagram keeps its global quota
after its association is retired, and an application-held association keeps
its lifetime charge independently of reusable slots. Reply queues and output
packets are bounded, and expiry withdraws owned output before replacement.

Controlled active-stack peers verify empty, unequal, and maximum
unfragmented datagrams, original addresses, and dynamic/shared destinations
in both families. Unit tests exercise queue/quota rollback, retired ownership,
idle/absolute age, input/output saturation, and cancellation/drop wakeups.
The adapter rejects zero IPv6 UDP checksums explicitly because the library
verifier accepts them; omitted IPv4 checksums remain supported. Non-unicast
traffic, zero source ports, fragments, and IPv6 extensions are unsupported
in this reply-oriented candidate. It does not yet establish reassembly,
ICMP errors, production scheduling/fairness, kernel ingress, or supervised
backend integration. The [UDP boundary](../implementation-contracts.md#8-experimental-udp-association-boundary)
records the candidate API and its limits. Neither prototype selects a
production stack or closes the full host-facing gate.

`runtime.rs` now combines the two candidates as one owned Tokio future.
It uses the pinned library's `Interface::poll_at`, adapter lifecycle deadlines,
application wakers, and bounded packet channels to await progress without
a periodic poll interval. TCP bridging explicitly reschedules bounded
progress and registers application-drop wakes. UDP reply/drop wakes are
coalesced, protocol output alternates within an eight-packet turn budget,
and UDP association priority rotates under output pressure. Full output
defers transport work deadlines while lifecycle timers and shutdown remain
observable; restored capacity wakes the runner.

The combined probe verifies concurrent 64 KiB TCP plus a trailer after FIN
and empty/unequal/MTU-sized UDP in both families, then joins runner/handlers.
Controlled-clock tests establish idle sleeping, expiry without new packets,
blocked-output behavior, explicit shutdown, channel loss, and abort cleanup.
The peer drains both contiguous receive-ring slices before waiting; its
wraparound regression fails with only one read. Tokio's pinned `test-util`
feature is added only for development tests, without a dependency upgrade.
The [combined boundary](../implementation-contracts.md#9-experimental-combined-runner)
records precise API, ownership, and packet handoff semantics. This runtime
owns experimental queues/adapters, without kernel I/O, backend workers,
readiness barriers, or a production graceful-drain/recovery contract.

Active smoltcp sockets exchange TCP/UDP over real IPv4/IPv6 loopback UDP
between two BoringTun peers, with all four inner/outer combinations, empty
datagrams, and
half-close. An explicit kernel-peer scope now tests the same Rust client
against Linux's independent WireGuard implementation. Only its disposable
test namespace contains a kernel WireGuard interface; the candidate backend
remains BoringTun plus an active userspace stack. The kernel peer checks
actual TCP/UDP payloads, addresses, and empty datagrams in both families.
Long mode verifies continuing traffic and recent completed rekey on both
implementations. No userspace-library-only comparison is substituted for
that scope.

The Linux-only fixture dependency is `wireguard-uapi` 3.0.1 (MIT), used for
`WgSocket::connect/set_device/get_device` and `set::Device/Peer/AllowedIp`.
Its blocking netlink operations rely on the harness's process deadline, and
its setter does not expose a complete ACK contract. The probe compensates
with state readback and real traffic; neither is a production route-driver
contract. Older transitive netlink/builder packages remain isolated in this
test dependency and require reconsideration before any production use.
No dependency advisory exception or unrelated upgrade is introduced.

The client allows ten seconds for setup/retry, matching the canonical
connection budget, and explicitly proves recovery after dropping one
initiation. [Linux's handshake admission](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/noise.c)
includes per-peer timestamp and initiation-rate checks. The fixture keeps
driving packet/timer output for 100 ms after application EOF before replacing
a session, preserving delayed TCP acknowledgements. This controlled
loopback drain is not a general network shutdown guarantee.

The shared experimental transport bounds handshake staging at 64 IP packets,
below BoringTun's internal 256-packet silent-drop limit. Encapsulation reserves
before library admission; immediate encrypted IP output releases that charge,
while pending plaintext retains it until drained. Empty keepalives do not
release it. The bounded drain includes its final Done call. Resource and
accounting failures are typed and fatal to the controlled owner; no library
fork or application-payload retry is introduced.

`outage.rs` groups the active stack, tunnel, and outer socket under injected
setup/response/lifetime deadlines and explicit cancellation. Controlled
outer loss demonstrates TCP retransmission after one application write,
response-after-FIN preservation, and no replay of a lost UDP datagram.
Application response success remains separate from cryptographic handshake
completion. Tests verify socket release after cancellation, expiry, overflow,
unexpected-peer failure, and owner drop, and verify a full staging drain.
These cases are same-library packet experiments; independent-kernel outage,
endpoint changes, OS state recovery, and service supervision remain unproven.
The [failure boundary](../implementation-contracts.md#10-experimental-active-tunnel-failure-boundary)
records exact scope and limits. Production backpressure/error policy needs
finalization before a real backend depends on this prototype.

The optional sustained probes check timer-driven rekey. These
core packet experiments are portable Rust code; the kernel fixture is
Linux-only. Observations so far are Linux ARM64
only; no native macOS claim follows. No throughput/CPU/RSS
performance budget is established. Library maintenance review, MSRV/platform
validation, larger/varied workloads, fragmentation/ICMP, aggregate resource
stress, production WireGuard cancellation/outages, and supervisor integration
remain open. Packet-level admission, cancellation, and stalled-reader
observations do not close their kernel/application acceptance gates.

Prototype ownership and limits are recorded in the
[contract progress](../implementation-contracts.md#6-experimental-boundaries).
Run `scripts/verify-feasibility.sh` as described in the development guide;
raw outcomes and exact environments belong in `target/evidence/phase-0/`.

## Consequences

The MTU capability probe supplies executable negative evidence. Raw smoltcp
peers generate ICMPv4/v6 port-unreachable messages and respect a configured
1280-byte TCP link MTU. On a 1500-byte link, valid ICMP too-big feedback
advertising 1280 does not reduce subsequent oversized TCP retries. The
interface does not forward those errors into TCP PMTU state or provide a
public per-established-connection MTU setter. With selected features,
two-fragment UDP datagrams are not reassembled in either family/order.
`host-stack --mtu-check` consequently returns typed unsupported-PMTU failure.
This is an open required capability, not evidence for accepting the stack.

A bounded pre-admission adapter now uses released smoltcp's public
`storage::Assembler` and header parsers for a restricted fragment-input
subset. It owns fixed storage, expiry, and strict overlap policy, without
enabling the library's heap-growing reassembly implementation or introducing
a fork. Existing etherparse 0.16 defragmentation source was also inspected;
its growable pool/ranges and overlap merging do not provide this boundary's
policy directly. No dependency or feature change is made.

The candidate supports at most 1280-byte reassembled TCP/UDP packets, with
two slots, fixed range metadata, and nonrenewing one-second deadlines.
Overlap/conflicts discard the assembly and retain a bounded tombstone.
IPv6 atomic fragments are independent, following
[RFC 5722](https://www.rfc-editor.org/rfc/rfc5722.html) and
[RFC 6946](https://www.rfc-editor.org/rfc/rfc6946.html). Both fragment orders
feed actual UDP admission, and live TCP data traverses the combined runtime.
This is limited incoming reassembly, not outgoing fragmentation, larger
datagram support, or PMTU discovery. The [fragment boundary](../implementation-contracts.md#12-experimental-bounded-fragment-input)
records exact limits and failure policy; the stack decision remains open.

The shared transport validates a declared 1500-byte loopback outer budget
and rejects encrypted packets that exceed it before socket send. Fixed
1280-byte inner traffic needs 1340-byte IPv4 or 1360-byte IPv6 outer paths,
including WireGuard/UDP/IP overhead. Maximum unfragmented UDP traffic is
tested, while general path discovery, fragment handling, and ICMP-to-flow
propagation need an adapter/library strategy. The [MTU boundary](../implementation-contracts.md#11-experimental-mtu-and-icmp-boundary)
records exact scope. [RFC 1191](https://www.rfc-editor.org/rfc/rfc1191.html)
and [RFC 8201](https://www.rfc-editor.org/rfc/rfc8201.html) define relevant
path-MTU feedback; fixed link sizing cannot establish that behavior.

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

The bounded input implementation is now shared by host interception and active
WireGuard transport. After peer authentication and inner source/destination
validation, decrypted fragments enter independent per-transport assembly slots.
Encrypted probes cover both families/orders/directions, expiry without input,
duplicate-inner-fragment rejection, and outer socket release with partial state.
No dependency or stack feature change is required. This narrows the inner
fragment-input gap; outer fragmentation, dynamic PMTU, and production peer-error
isolation remain open. See the [decrypted input contract](../implementation-contracts.md#13-experimental-decrypted-fragment-input).

The independent Linux kernel-peer workload now covers controlled outbound
ciphertext loss after establishment in both inner families. Application TCP
bytes are admitted once, then stack retransmission recovers the request and
FIN; a separate lost UDP datagram is never resubmitted. Exact kernel-worker
payload/count assertions and joined cleanup support this narrow recovery
claim. This adds independent-peer evidence to the same-library failure probes;
full outage detection, roaming, and service recovery remain unproven.

Outer transport is now selected independently of inner addresses. Actual IPv4
and IPv6 loopback UDP sockets carry all four inner/outer combinations through
the active-stack and encrypted-fragment probes. The independent kernel peer
uses matching inner/outer families for loss recovery and IPv6 outer transport
for sustained rekey. The client binds the remote endpoint's address family;
the server applies the same outer-header budget. A real encrypted 1472-byte
datagram fits a 1500-byte IPv4 outer path but is rejected for IPv6 before send;
larger encrypted data is rejected for both families. This verifies declared
budgets and interoperability, not dynamic path discovery or physical bypass.

An experimental single-operation reservation now matches port-unreachable
errors after authenticated WireGuard decryption. It stores only IP addresses,
IPv4 identification where applicable, and the eight-byte UDP header. A typed
error consumes the reservation once; unrelated or corrupt feedback leaves it
intact. The operation owner controls deadlines and destroys it on cancellation
or expiry. Both inner families run through actual same-library and independent
kernel-generated errors. Minimum quotes preserve original IP lengths, following
[RFC 792](https://www.rfc-editor.org/rfc/rfc792.html) and
[RFC 4443](https://datatracker.ietf.org/doc/html/rfc4443#section-3.1).
This is restricted UDP error evidence, not general ICMP/PMTU support. Concurrent
operations, router-originated errors, host-side synthesis and error isolation
still need contracts. Identical datagrams cannot be distinguished from minimum
quotes; peer authentication does not prove a quoted packet's ultimate origin.

A sizing-control experiment now demonstrates a possible route around the
missing public TCP MTU setter without a fork. `Interface::new` captures device
capabilities; ordinary egress does not refresh that cached context. Replacing
only the raw-IP interface at the smaller MTU while retaining the original
`SocketSet` preserves a partially acknowledged TCP transfer, including a
smaller retry of the lost sequence, exact byte delivery, FIN and response in
both families. Device reconfiguration requires empty packet queues and keeps
pending data on refusal. The experiment copies addresses, routes/lifetimes
and any-IP policy, under the selected features' limited interface state.

This is an executable alternative to new TCP packet rewriting or a stack
fork, not an accepted production approach. Reduction affects the whole
interface and receive limit, and the fixture re-seeds interface randomness.
Production entropy/state transfer, multiple/asymmetric paths, queued UDP,
feedback validation, per-path budgets/expiry and WireGuard propagation still
need contracts and evidence. The raw ICMP negative control remains, the MTU
gate remains nonzero, and this ADR stays proposed.
