<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Implementation Status

The repository contains contracts, schema examples, ADRs, licensing metadata,
executable development/CI harnesses, and a minimal Rust experimental workspace.
There is no production service or protocol adapter yet. Required networking
gates remain open.

## Phase Ledger

| Phase | Status | Evidence / next unmet gate |
| --- | --- | --- |
| Development infrastructure | Available | `scripts/check.sh` runs licensing, workflow/composite lint, shell lint, and harness tests; CI enables Rust jobs once workspace prerequisites exist |
| 0: Baseline and feasibility | In progress | Isolated probes under `experiments/` produce evidence under `target/evidence/phase-0/`. TCP/UDP candidates preserve dynamic/shared destinations, frozen metadata, bounded retained buffers/messages, expiry, and cancellation. A combined wake-driven runtime now runs both through bounded packet channels, library/lifecycle deadlines, rotating output priority, blocked-output expiry, explicit shutdown, and joined failure cleanup; evidence is indexed in `target/evidence/phase-0/runtime/README.md`. UDP admission evidence remains in `target/evidence/phase-0/udp/README.md`. Active sockets work through BoringTun and an independent Linux kernel WireGuard peer, including both inner families, empty datagrams, FIN, handshake-loss retry, and completed rekey (`target/evidence/phase-0/kernel/README.md`). Wrapper comparison remains rejected. Next: finalized initial production contracts, kernel TUN and outage/MTU/ICMP evidence |
| Contract gate before production dependencies | Pending Phase 0 | Complete `implementation-contracts.md` with selected APIs and source links |
| 1: Headless Linux service slice | Not started | Depends on feasibility, initial contracts, authorized control, and client-independent lifecycle |
| 2: Linux DNS and routing | Not started | Depends on fixed-CIDR lifecycle; NET-10/NET-11 cover grace/endpoint publication, and NET-12 requires global retained-state admission/renewal/exhaustion evidence |
| 3: Backends and IPv6 | Not started | WireGuard feasibility is already required in Phase 0 |
| 4: macOS networking and helper | Not started | ADR 0005 and UX-05 auth subset require actual ad-hoc bundled registration/enrollment/two-way IPC without paid signing; native networking/recovery/approval evidence also required |
| 5: Tauri desktop and release | Not started | Requires UX-01–UX-04 public packaging, full UX-05 local GUI/service/rebuild evidence, frontend checks, and production-mode exclusion tests |

The [stack ADR](adr/0002-network-stack.md) remains proposed. Packet probes
establish limited transport behavior, not NET-01/NET-05/NET-06/NET-07 or
the complete Phase 0 exit criteria. No native macOS evidence exists.
`tests/fixtures/configuration/cases.toml` captures parser and capability
expectations; executable production parser/CLI registration remains Phase 1.
TUN device provisioning is denied here even inside disposable namespaces;
its kernel gate remains unverified. This does not block independent
peer and adapter experiments. Linux kernel WireGuard interface creation and
retirement work in disposable namespaces independently of the unavailable
TUN device; this does not establish host TUN interception.

WireGuard packet-level failure probes now cover bounded handshake staging,
transient TCP/UDP loss, setup/application-response deadlines, cancellation,
and outer socket release (`target/evidence/phase-0/outage/README.md`). These
same-library fixture observations do not close service/backend outage or
crash recovery acceptance. The independent Linux kernel peer now also verifies
controlled outbound loss in both inner families: TCP retry/FIN and exact bytes,
no lost-UDP replay, worker joins, and independently verified interface removal
(`target/evidence/phase-0/kernel-outage/README.md`). The independent workload
now maintains outbound suppression for at least 1200 ms and observes the lost UDP packet and a repeated TCP sequence before
recovery (`target/evidence/phase-0/sustained-outage/README.md`). A separate
inbound blackout now covers the independent peer's response write and discards
a subsequent encrypted data datagram before exact response/EOF recovery in both
families (`target/evidence/phase-0/inbound-outage/README.md`). Actual link down,
general inbound failure handling, roaming, service recovery, and MTU/ICMP gates
remain open.

The explicit host MTU gate now reproduces oversized TCP retransmission after
valid ICMP too-big feedback and missing fragment reassembly in both families
(`target/evidence/phase-0/mtu/README.md`). Fixed 1280-byte segmentation,
ICMP port-unreachable generation, and WireGuard envelope limits are tested.
Bounded pre-admission IPv4/IPv6 fragment input now handles both orders,
overlap tombstones, atomic fragments, expiry, and transport checksum gating
(`target/evidence/phase-0/reassembly/README.md`). The same boundary now runs
after authenticated WireGuard decryption and inner-address checks, with
encrypted UDP fragment round trips, expiry, overlap rejection, and socket
release (`target/evidence/phase-0/wireguard-fragments/README.md`).
Real loopback IPv6 outer UDP transport now complements IPv4 transport. Packet
probes cover all four inner/outer combinations; the independent kernel peer
covers matching families and sustained rekey over IPv6 outer transport
(`target/evidence/phase-0/outer-ipv6/README.md`). The encrypted-size guard
accounts for the actual outer family before socket send.
A single reserved UDP operation can now surface validated ICMP port-unreachable
feedback after WireGuard decryption, including real errors from the independent
kernel peer in both families. Minimum quotes, malformed/unrelated feedback,
one-time delivery, cancellation and owner expiry are checked
(`target/evidence/phase-0/udp-feedback/README.md`). A raw-IP sizing experiment
now replaces the interface while retaining established TCP sockets: partially
acknowledged bytes complete after reduction from 1500 to 1280, including FIN
and a response, with no application resubmission. Queued packets block device
reconfiguration; addresses, routes and any-IP policy survive
(`target/evidence/phase-0/interface-mtu/README.md`). A single reserved outstanding
TCP segment now matches validated too-big feedback and applies its advertised
1280/1400-byte reduction. ACK retirement (including wrap/FIN), expiry, malformed
quotes and queue-busy retry are covered
(`target/evidence/phase-0/matched-pmtu/README.md`). Production path attribution
and state-transfer policy are still missing. The same candidate now carries
inner too-big feedback through encrypted WireGuard in all inner/outer family
combinations, preserving exact TCP bytes/FIN and retiring reservations on expiry
or cancellation (`target/evidence/phase-0/wireguard-pmtu/README.md`). The larger
TCP/outer budgets exist only in a controlled fixture; ordinary UDP/fragment
limits remain tested. A Linux-only isolated outer probe now reads genuine local
EMSGSIZE/error-queue MTU reports for encrypted UDP, validates socket/destination
metadata, reduces the outer budget, rejects later oversized sends before the
socket, and delivers a distinct safe message without replay
(`target/evidence/phase-0/outer-errors/README.md`). The same isolated scope now
applies local outer feedback to a retained TCP connection, preserving 8 KiB,
FIN/response, tuple and retry sequence across interface sizing in all four
family combinations, without inner feedback or application replay
(`target/evidence/phase-0/outer-tcp/README.md`). A dedicated Linux kernel-peer
MTU scope now repeats all four family combinations using real kernel TCP and
WireGuard, verifies exact bytes/FIN/response and lost-sequence retry, joins its
worker, rebinds sockets and independently retires the interface
(`target/evidence/phase-0/kernel-mtu/README.md`). A three-namespace routed
fixture now matches genuine remote-router IPv4/IPv6 MTU errors to one encrypted
UDP operation in all four family combinations; it reduces the outer budget,
prevents later oversized sends, delivers distinct safe messages and verifies
peer counts plus independent namespace/interface cleanup
(`target/evidence/phase-0/router-mtu/README.md`). The same routed scope now
uses validated remote feedback to resize a retained TCP connection, preserving
one 8192-byte write, FIN/response, original tuple and rejected-sequence retry in
all four family combinations. Queue-busy retry retains the reservation until
both budgets and sizing commit; kernel workers verify the combined workload
(`target/evidence/phase-0/router-tcp/README.md`). A synthetic Linux loopback
probe shows that UDP-header-only ICMP quotes yield no UDP payload in the error
queue in either outer family; all lengths below 16 bytes remain rejected
(`target/evidence/phase-0/short-icmp/run.log`). Synthetic decoded-record tests
also reject a delayed report after commit, cancellation or expiry when the next
reservation has a distinct header; identical headers cannot be distinguished.
A synthetic Linux loopback error queue preserves the old header when its ICMP
report arrives after a later send. The routed kernel-peer fixture now holds a
genuine report after receipt, rejects it against a later distinct send, and
applies the later report in all four family combinations
(`target/evidence/phase-0/router-delayed/README.md`). Actual delayed packet
delivery and cross-session header uniqueness remain unverified. The current
routed fixture also uses two connected sockets and distinct budgets; matching
checks the local socket tuple and rejects a wrong-socket report even when its
header is made to match (`target/evidence/phase-0/router-sockets/README.md`).
A reader-lifetime token now distinguishes a new reader when a socket is closed
and its local tuple rebound; a loopback test exercises both families
(`target/evidence/phase-0/queue-generation/README.md`). Production ownership,
physical-path attribution, and reader replacement policy remain unresolved.
The experimental reservation API now takes the reader directly, binding its
local tuple and token together (`target/evidence/phase-0/reader-interface/README.md`).
The connected destination now also comes from that reader; matching accepts
no separate destination (`target/evidence/phase-0/reader-destination/README.md`).
Reservation and UDP/TCP feedback application now reject a currently changed
socket peer before mutation; loopback tests cover both families and wrong-reader
application (`target/evidence/phase-0/reader-peer/README.md`). Changes restored
between checks, concurrent reconfiguration, and replacement policy remain open.
An IPv4/IPv6 loopback test demonstrates that a changed-and-restored peer is
invisible to these checks (`target/evidence/phase-0/restored-peer/README.md`).
A separate Linux owner keeps its socket private, retires feedback before
reconnecting, and fails closed on an injected uncertain peer transition;
IPv4/IPv6 loopback tests cover returning to the original peer and fresh-reader
recovery (`target/evidence/phase-0/owned-peer/README.md`). The routed kernel-peer
fixture now sends encrypted traffic through the owner and rejects genuine
retired router feedback after a peer transition in all four family combinations
(`target/evidence/phase-0/owned-router/README.md`). This owner does not replace
the WireGuard transport. The routed fixture now also completes a distinct UDP
application exchange through that owner after recovery in all four family
combinations (`target/evidence/phase-0/owned-exchange/README.md`). Concurrent
transitions and production path attribution remain unverified.
Short-quote correlation, general router trust, concurrent/physical-path policy and error propagation,
dynamic PMTU, outgoing fragmentation, larger datagrams, and extension-header
strategy remain unresolved; the MTU gate returns nonzero and ADR 0002 stays proposed.

## Gate Evidence

Update this ledger when a phase or prerequisite changes status. Link the
relevant accepted ADR and stable evidence location; do not append routine
per-run validation history here. Capture the following in CI logs or ignored
`target/evidence/` artifacts:

- **Behavior delivered:** concrete observable behavior and affected requirement/phase.
- **Revision:** commit ID when available; otherwise identify the worktree state and changed files without creating a commit solely for this field.
- **Environment:** OS/architecture, compiler/dependency versions, isolation method, required privileges, peer setup.
- **Commands:** exact copyable commands and necessary nonsecret setup.
- **Results:** passed, failed, not run, or unsupported for each check. Record skipped tests and why; retain redacted logs/assertions/capture summaries with the run.
- **Failure/cleanup evidence:** injected fault, expected state, observed state, and remaining owned resources.
- **Limits and next gate:** remaining unsupported behavior, decision changes, and the next independently verifiable deliverable.

Never include live credentials, raw payloads, real-user network captures, or private keys in evidence. Clearly label controlled synthetic fixtures.
