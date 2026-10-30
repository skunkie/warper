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

The selected **host MTU is fixed at 1280** for the first production slice,
as already specified by plan section 4.1. Its largest unfragmented UDP
payload is 1252 bytes for IPv4 or 1232 for IPv6. Bounded pre-admission
reassembly accepts supported fragments whose reassembled IP packet fits
1280 bytes. Overlaps, expired assemblies, excess retained state and larger
reassembled datagrams are rejected. There is no outgoing inner fragmentation
or general IPv6 extension-header support. Configuration values outside the
implemented adapter's range must produce an unsupported-capability diagnostic
before host mutation; the schema's broader syntactic range is not a promise
that every adapter supports it.

**Raw smoltcp ignores TCP too-big feedback.** The failing `--mtu-check`
remains a negative control, not a passing PMTU implementation. The selected
fixed host interface needs no runtime interface rebuild. The separate
`--adapter-mtu-check` verifies fixed segmentation, ICMP port-unreachable,
bounded input reassembly, and the experimentally demonstrated retained-socket
resize mitigation. Rebuild/feedback experiments do not authorize automatic
host MTU changes in production. Host configuration, route sizing, and any
later MTU extension must honor this limit explicitly.

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
