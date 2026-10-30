<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0002. Userspace stack selection

- Status: accepted for the initial Linux slice; native macOS validation pending.
- Date: 2026-10-30
- Related: [stack gate](../implementation-plan.md#21-dependency-and-stack-feasibility-gate),
  [initial contracts](../implementation-contracts.md#6-initial-slice-contract),
  NET-01, NET-05, NET-06, and NET-07 in the
  [acceptance contract](../acceptance.md).

## Context

Host interception and active WireGuard dialing are separate stack roles.
Both require original destination metadata, bounded ownership, cancellation,
TCP half-close, UDP datagram boundaries, and IPv4/IPv6. The selection follows
executable Linux TUN and independent Linux kernel WireGuard peer evidence,
including failures and cleanup. It does not assert production networking,
macOS integration, or completion of the referenced acceptance IDs.

## Decision

Use released **smoltcp 0.14.0** directly for both roles, with separate
adapters and stack instances. Use **BoringTun 0.7.1** for the WireGuard
protocol, behind an owned outer UDP transport. No fork, local SOCKS bridge,
or third-party stack type crosses the backend-neutral flow boundary.

| Dependency | Features / license | Selected use |
| --- | --- | --- |
| smoltcp 0.14.0 | Defaults off; `std`, `medium-ip`, `proto-ipv4`, `proto-ipv6`, `socket-tcp`, `socket-udp`; 0BSD | Host TCP interception, packet validation/serialization, active TCP/UDP tunnel sockets |
| BoringTun 0.7.1 | Defaults off; BSD-3-Clause | `Tunn` state machine, encryption and protocol timers |
| Tokio 1.54.1 | `io-util`, `macros`, `rt`, `sync`, `time`; host experiment also `net`; MIT | Owned host runner, bounded channels, asynchronous streams, timers |
| futures 0.3.32 | Defaults off; `std`, `async-await`; MIT OR Apache-2.0 | Host adapter wake registration and comparison fixtures |

The exact Rust toolchain is 1.99.1, edition 2024; shared lints, feature pins,
and dependency resolution are in the root manifest and lockfile. Upstream
smoltcp's declared MSRV is 1.91. The workspace's stronger toolchain pin is
the tested requirement. Platform fixture dependencies (`wireguard-uapi`
3.0.1, rustix 1.1.5, nix 0.31.3) are not selected production route drivers.
Kernel WireGuard is an independent test peer, never the service's backend.

### Configuration name normalization

Offline configuration uses **idna 1.1.0** with its compiled data, locked
idna_adapter 1.2.2 and ICU 2.4.0 dependencies. In
[`schema/fields.rs`](../../crates/warper-config/src/schema/fields.rs), UTS 46
processing is nontransitional, with `AsciiDenyList::STD3`,
`Hyphens::CheckFirstLast`, and `DnsLength::VerifyAllowRootDot`. Case/Unicode dots
normalize before removal of one terminal dot. Domain rules reject root/empty
names, IP literals, wildcards and underscores. Unlike full CheckHyphens mode,
internal `--` in ordinary labels remains allowed. Hosts accept bare IPs before
hostname normalization; physical and inner families remain independent.

`crates/warper-config/tests/schema.rs` locks case, Unicode/Punycode, sharp-s,
Unicode dots, label/name lengths and duplicate-assignment fixtures. The parser
catalog also preserves original-shaped routing defaults and redacts unknown key
names in diagnostics. Base64 key decoding reuses locked **base64 0.22.1**;
length/padding checks do not replace runtime cryptographic/host-trust checks.
No normalization library types cross the configuration boundary. This profile
applies to configured suffixes/hostnames, not DNS wire record names; service
labels such as `_service._tcp.example.test` must remain queryable later.

Revisit this profile and its compatibility fixtures when IDNA/ICU data changes
or required names cannot be represented. Reproduction:
`cargo test --locked -p warper-config --test schema`. Evidence belongs under
`target/evidence/phase-1/schema-validation/`; no backend networking gate is
closed by these parser tests.

### Host-facing role

[The adapter](../../experiments/host-stack/src/adapter.rs) validates selected
SYNs, reserves a socket and accepted-stream lifetime budget, installs a
listener on the original destination, and publishes a completed handshake.
It uses `Interface::new`, `set_any_ip`, `update_ip_addrs`, userspace default
routes, `tcp::Socket::listen`, `close`, and `abort`. The socket set remains
inside the adapter. `AcceptedFlow::into_contract` demonstrates the
stack-independent, `Send` asynchronous TCP stream boundary in controlled
packet and real TUN exchanges.

[The UDP adapter](../../experiments/host-stack/src/udp_adapter.rs) uses
smoltcp wire representations and preserves each original tuple and datagram,
including empty payloads. It owns associations independently of reusable
slots and freezes backend selection on admission. It rejects omitted IPv6
UDP checksums; IPv4's optional checksum remains supported.

[The combined runtime](../../experiments/host-stack/src/runtime.rs) uses
`Interface::poll_at`, lifecycle deadlines, application wakers, and bounded
packet channels. Its caller owns and joins the runtime and backend handlers;
the adapter does not create hidden workers. TCP and UDP output share bounded
turn budgets with rotating UDP priority.

The initial host link MTU defaults to 1280; the experimental TCP runner also
accepts a declared link MTU up to 1500. TCP egress PMTU is separate from link
ingress sizing. UDP retains its own 1280-byte packet limit (1252 IPv4 or 1232
IPv6 payload bytes), and bounded fragment reassembly retains its separate
1280-byte ceiling. Larger datagrams, outgoing inner fragmentation and general
IPv6 extension headers remain unsupported. Broader schema ranges do not bypass
adapter/platform capability validation before mutation.

**Raw smoltcp ignores TCP too-big feedback.** `--raw-mtu-check` preserves that
failing negative control. The selected adapter now handles downward discovery
in the actual owned runner: emitted segment identities are retained per flow,
ICMP matches a preselected reporter and the outstanding tuple/sequence, accepted
ACKs retire reservations, and valid reductions replace only cached TCP egress
capabilities. The physical link device, ingress MTU, socket set, application
queues and flow/backend identities stay intact. A shared interface uses the
minimum validated TCP budget, conservatively reducing other TCP paths too.

The runner independently retries transient seed/output unavailability at 10 ms
minimum intervals, preserves the original expiry, and rejects retired/stale or
unrelated reports. Permanent errors preserve their cause through joined runtime
shutdown. Fresh nonblocking OS entropy is used by the Linux TUN owner. No
application write is replayed. MTUs below 1280 explicitly terminate the selected
flow with an unsupported-operation error; upward probing is not implemented.

`--mtu-check` now verifies actual wake-driven runtime adjustment for concurrent
streams with 1280/1400 path budgets and a transient seed failure. The separate
`--tun-pmtu-check` uses an independent kernel TCP client and forwarding router:
after both flows transfer 16 KiB, the router lowers its route MTU from 1400 to
1280, producing genuine ICMP while the same streams complete exact 64 KiB
requests, responses and FIN. Both IP families run. Routes, TUN/veth interfaces
and the namespace anchor are private and independently retired. Both scopes are
required by the default host gate. `--adapter-mtu-check` remains a narrower
fixed-sizing/reassembly experiment and cannot substitute for either scope.

The [runtime PMTU contract](../implementation-contracts.md#27-host-runtime-pmtu-feedback)
records API, memory, cancellation, ACK, reporter and retry obligations. Native
macOS entropy/networking, arbitrary Internet router trust, upward discovery,
sub-1280 support and per-path throughput optimization remain separate explicit
capabilities; they are not inferred from these controlled Linux results.

### Active WireGuard role

[The active peer](../../experiments/packet_peer.rs) uses
`tcp::Socket::connect`, `send_slice`/`recv`, `close`, and UDP
`send_slice`/`recv` with explicit source addresses. The
[WireGuard owner](../../experiments/wireguard-stack/src/main.rs) uses
`Tunn::new`, `encapsulate`, `decapsulate` (including empty-input draining),
`update_timers`, and `stats`. It checks the configured outer peer and inner
address policy, rejects invalid encrypted data without ending a valid
session, and bounds handshake staging before BoringTun's internal queue.

Inner families and outer UDP families are independent. The conservative
outer budget reserves IP/UDP headers, 32 encryption bytes and 16-byte padding;
an inner 1280-byte link needs an outer path of at least 1340 bytes for IPv4
or 1360 for IPv6. Smaller paths fail explicitly. All encrypted sends must
respect the current budget; lost UDP application data is never replayed.
A declared MTU alone is not verified physical egress or dynamic PMTU discovery.

The Linux local/kernel/routed MTU probes demonstrate retained TCP resizing
from genuine local or router errors in all four inner/outer combinations.
They preserve one application write, exact bytes, retransmission, FIN and
response, without application replay. Busy queues retain the reservation
until both budgets and sizing can commit. This establishes feasibility of an
adapter mitigation, not general ICMP trust or per-path production integration.
Minimum quotes lacking a WireGuard header cannot correlate an operation;
they remain rejected. General router trust, socket/route generation recovery,
asymmetric paths, and shared-interface production migration remain later
adapter obligations. They cannot be replaced with silent fixed-MTU success.

### Ownership and measurable limits

The host experiments use at most 16 TCP slots (two by default), 8192-byte
stack rings per TCP direction, bounded duplex bridges, and separate lifetime
permits. Packet ingress/egress capacities are at most 64, with an eight-packet
output turn budget. UDP association/message/accepted queues and the global
datagram budget are independent. The shared packet peer has 64-packet queues,
8192-byte TCP/UDP rings, and eight UDP metadata slots per direction.

WireGuard staging is capped at 64 packets, below the library's 256-packet
internal limit. Receive/drain batches are bounded and include the final Done
call. Timers run during loss; setup, response, lifetime and cancellation are
separate. TCP retries remain in the original stack send buffer. These are
logical buffer limits, not RSS guarantees; library metadata, allocator and
kernel socket memory require separate production accounting.

Experimental fixed seeds and synthetic keys are fixture inputs. Production
constructors must use fresh OS entropy and approved secret material. The
Linux nonblocking entropy/resize failure path is exercised; macOS entropy,
physical route protection and service supervision still need implementation.

## Alternatives

- **netstack-smoltcp 0.2.4** (MIT OR Apache-2.0), with its transitive smoltcp
  0.12: the explicit `--wrapper` comparison fails empty UDP replies. Source
  inspection also finds unbounded internal channels and an upstream unsafe
  `Send` boundary not validated by single-threaded probes. Keep this pinned
  dependency only for the executable rejected comparison; do not use it in
  production.
- **ipstack 1.0.1** (Apache-2.0): source inspection identified unbounded
  acceptance/outbound queues and internally spawned workers without public
  join ownership. It was not traffic-tested; rejection concerns resource and
  supervision fit, not a claimed transport failure.
- **tun2proxy / an extra loopback proxy / a fork**: no demonstrated advantage
  over the direct role adapters. They introduce another dispatch/lifecycle
  boundary or ongoing fork maintenance. None is introduced.

## Validation and consequences

Run, from a clean Linux checkout with the tools in the
[development guide](../development.md#phase-0-packet-experiments):

```sh
./scripts/verify-feasibility.sh host-stack
PATH=/usr/sbin:$PATH ./scripts/verify-feasibility.sh wireguard-stack
```

Each gate runs repository checks and all its required real-traffic scopes,
keeps per-scope logs/lockfile/environment/source hashes, and stops on failure.
The host gate includes packet, kernel TUN, abrupt adapter death, supported
kernel fragments, and adapter MTU checks. TUN TCP flows reach two distinct
controlled backend listeners; these are not SOCKS5 or SSH implementations.
The WireGuard gate includes packet traffic, independent kernel peer/rekey,
and local plus remote-router MTU recovery. Disposable namespaces/private
mounts contain mutations; helpers independently verify interface/link cleanup.

The evidence index is `target/evidence/phase-0/README.md`, with final role
runs indexed under `target/evidence/phase-0/closure/`. The initial contract
models and failure-injecting driver are in `experiments/initial-contract/`.
They test protocol/ownership boundaries; they do not implement durable host
recovery, DNS parsing, authenticated control, or a networking service.
NET-01/NET-05/NET-06/NET-07 and NET-10–NET-12 remain production acceptance
requirements in their assigned phases.

Linux evidence cannot establish native macOS behavior. Keep native builds,
utun networking, helper authentication and UX-05 separate and unverified
until run. Revisit this decision if required production behavior cannot fit
these adapters, after a dependency/API change, or if a later platform requires
an unaffordable fork. No exception reduces the release support matrix.
