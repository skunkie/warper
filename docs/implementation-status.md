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
| 0: Baseline and feasibility | In progress | Isolated probes under `experiments/` produce evidence under `target/evidence/phase-0/`. The combined runtime exchanges Linux kernel TUN TCP/UDP traffic in both IP families through two destinations (`target/evidence/phase-0/tun/README.md`). Active sockets work through BoringTun and an independent Linux kernel WireGuard peer, including both inner families, empty datagrams, FIN, handshake-loss retry, and completed rekey (`target/evidence/phase-0/kernel/README.md`). Wrapper comparison remains rejected. Next: finalized initial production contracts and remaining outage/MTU/ICMP evidence |
| Contract gate before production dependencies | Pending Phase 0 | Complete `implementation-contracts.md` with selected APIs and source links |
| 1: Headless Linux service slice | Not started | Depends on feasibility, initial contracts, authorized control, and client-independent lifecycle |
| 2: Linux DNS and routing | Not started | Depends on fixed-CIDR lifecycle; NET-10/NET-11 cover grace/endpoint publication, and NET-12 requires global retained-state admission/renewal/exhaustion evidence |
| 3: Backends and IPv6 | Not started | WireGuard feasibility is already required in Phase 0 |
| 4: macOS networking and helper | Not started | ADR 0005 and UX-05 auth subset require actual ad-hoc bundled registration/enrollment/two-way IPC without paid signing; native networking/recovery/approval evidence also required |
| 5: Tauri desktop and release | Not started | Requires UX-01–UX-04 public packaging, full UX-05 local GUI/service/rebuild evidence, frontend checks, and production-mode exclusion tests |

### Phase 0 exit audit

The [Phase 0 exit](implementation-plan.md#phase-0-baseline-and-feasibility)
requires the workspace checks, controlled-peer evidence for both stack roles,
the required evidence package, and the initial contract gate. The current
assessment is:

| Requirement | Assessment and remaining work |
| --- | --- |
| Minimal workspace and checks | Present. `scripts/check.sh` exercises the workspace, infrastructure and dependency policy. |
| Configuration and reference fixtures | Present as design and fixture cases; production parser/CLI tests belong to Phase 1. |
| Host-facing role | Partial. The Linux TUN fixture exercises two destination selections, TCP/UDP and both families; its handlers are experimental, and the explicit dynamic MTU check fails for both families. The TUN run does not establish macOS behavior or real protocol backends. |
| WireGuard-side role | Partial. Active TCP/UDP and rekey have been exercised against a Linux kernel peer; the packet and routed PMTU experiments have narrower ownership and transport limits than a finalized adapter. |
| Stack decision and evidence package | Open. ADR 0002 is proposed, so it does not yet select a production stack and its limitations. The default feasibility commands intentionally return incomplete after their packet probes, and the evidence index must identify the final gate runs and revision. |
| Initial implementation contracts | Open. Selected stack interfaces are not finalized or demonstrated by compile-checked production-facing contracts. The contract completion checklist also requires fault-injection evidence for driver acknowledgements, rollback, task termination, and DNS reference and retained-state boundaries. |

The explicit `host-stack --mtu-check` returns `UnsupportedPmtu`: raw smoltcp
continues oversized TCP retransmissions after too-big feedback. Interface
rebuild experiments show a possible mitigation but do not establish a safe
runtime feedback and ownership policy. Resolve or explicitly accommodate this
limitation in the selected adapter and its executable role evidence before
accepting the stack ADR; a successful UDP kernel-sender fixture does not resolve
it.

The [contract completion checklist](implementation-contracts.md#5-completion-gate)
asks for fault-injection evidence involving NET-10, NET-11, and NET-12 before
its gate passes. Those contract-level cases must be made executable without
claiming that the Phase 2 DNS and routing implementation has passed its full
acceptance. Production DNS/routing, physical-host recovery, and native macOS
acceptance remain assigned to later phases; missing native evidence must be
reported separately, not treated as a Linux test pass.

The [stack ADR](adr/0002-network-stack.md) remains proposed. Packet probes
establish limited transport behavior, not NET-01/NET-05/NET-06/NET-07 or
the complete Phase 0 exit criteria. No native macOS evidence exists.
The loopback fixtures use bounded readiness waits for dependent packets and
final ACKs; native macOS test results remain separate from Linux evidence
(`target/evidence/phase-0/macos-readiness/README.md`).
`tests/fixtures/configuration/cases.toml` captures parser and capability
expectations; executable production parser/CLI registration remains Phase 1.
The isolated Linux TUN fixture now exercises kernel TCP and UDP clients through
the combined runtime for both families and two destination/backend selections.
It verifies original tuples, empty and unequal datagrams up to the 1280-byte
TUN MTU in both directions, concurrent 64 KiB
TCP transfers to two destinations, data received before half-close and a
response after it, bounded bridge queues, explicit shutdown, and interface
removal (`target/evidence/phase-0/tun-boundary/README.md`).
The Linux fixture also forces kernel fragmentation of datagrams one byte above
the 1280-byte reassembly limit. Both fragment sets reach the bridge, no reply
arrives within the 200 ms observation, and a later supported datagram succeeds
for both destinations and IP families
(`target/evidence/phase-0/tun-oversized/README.md`). This is
bounded rejection evidence, not support for larger datagrams.
An isolated Linux IPv4 route with a 1000-byte MTU now forces kernel
fragmentation of supported 1252-byte UDP payloads. The combined runtime
reassembles and replies for two destinations while preserving payload and
metadata (`target/evidence/phase-0/tun-fragments/README.md`). This does not
establish native IPv6 fragmentation or production route handling.
The combined runtime's controlled-clock test also exercises two retained
fragment tombstones: distinct fragment sets are rejected before expiry and a
new datagram is admitted at expiry in both IP families. This does not establish
real-TUN overload behavior.
The isolated TUN crash fixture also joins the external packet bridge, kills
the experimental adapter after UDP traffic, and completes fresh TCP/UDP
traffic using a new adapter on the same fixture interface in both families,
then independently verifies interface
removal (`target/evidence/phase-0/tun-crash/README.md`). It does not restore
old flows or establish production service crash recovery.
This is limited feasibility evidence, not complete host-networking acceptance;
it does not exercise production backends, macOS, or the remaining MTU and
failure gates. The sandboxed environment denies TUN access; the isolated run
used the approved unsandboxed execution environment.

WireGuard packet-level failure probes now cover bounded handshake staging,
transient TCP/UDP loss, setup/application-response deadlines, cancellation,
and outer socket release (`target/evidence/phase-0/outage/README.md`). These
same-library fixture observations do not close service/backend outage or
crash recovery acceptance. The independent Linux kernel peer now also verifies
controlled outbound loss in both inner families: TCP retry/FIN and exact bytes,
no lost-UDP replay, worker joins, and independently verified interface removal
(`target/evidence/phase-0/kernel-outage/README.md`). The independent workload
now maintains outbound suppression for at least 1200 ms and observes the lost
UDP packet and a repeated TCP sequence before recovery
(`target/evidence/phase-0/sustained-outage/README.md`). A separate inbound blackout now covers the independent peer's response write and discards
a subsequent encrypted data datagram before exact response/EOF recovery in both
families (`target/evidence/phase-0/inbound-outage/README.md`). An isolated
kernel-peer WireGuard interface down/up probe now verifies a completed new
handshake, one TCP write with FIN, an unreplayed lost UDP datagram, a distinct
post-recovery heartbeat and cleanup in both families. The helper explicitly
restores the fixture IPv6 address lost on link-down
(`target/evidence/phase-0/kernel-link/README.md`). A separate three-namespace
fixture now lowers and restores a private router egress veth while an established
WireGuard path carries a single TCP write and one lost UDP datagram. Both
matching and cross-family IP paths recover without replay, with independent
peer and link cleanup (`target/evidence/phase-0/physical-cross/README.md`).
Actual physical NIC failure, general inbound failure handling, roaming, service recovery, and
MTU/ICMP gates remain open.

The explicit host MTU gate now reproduces oversized TCP retransmission after
valid ICMP too-big feedback and missing fragment reassembly in both families
(`target/evidence/phase-0/mtu/README.md`). Fixed 1280-byte segmentation,
ICMP port-unreachable generation, and WireGuard envelope limits are tested.
Bounded pre-admission IPv4/IPv6 fragment input now handles both orders,
overlap tombstones, atomic fragments, expiry, and transport checksum gating
(`target/evidence/phase-0/reassembly/README.md`). The same boundary now runs
with representable clock deadlines for new assemblies while preserving
existing assemblies near the clock limit
(`target/evidence/phase-0/fragment-deadline/README.md`). The boundary also runs
after authenticated WireGuard decryption and inner-address checks, with
encrypted UDP fragment round trips, expiry, overlap rejection, and socket
release (`target/evidence/phase-0/wireguard-fragments/README.md`).
The host TCP/UDP candidates now reject unrepresentable absolute-age deadlines
and bound their elapsed clock before converting to the stack's microsecond
representation (`target/evidence/phase-0/host-clock-bound/README.md`). This
does not establish all internal stack timer arithmetic or unify the separate
fragment and WireGuard clock ranges.
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
(`target/evidence/phase-0/interface-mtu/README.md`). A controlled shared-interface
probe now retains two simultaneous TCP flows and one UDP datagram across a
1500-to-1280 reduction in both families. Feedback quoting the other flow is
rejected before matched feedback triggers the reduction; deliberately lost
oversized TCP packets retransmit without application resubmission
(`target/evidence/phase-0/matched-shared-mtu/README.md`). With both flows
queued, a busy replacement now preserves the packet queue, both TCP send
queues, MTU, and reservation until a controlled retry
(`target/evidence/phase-0/busy-shared-mtu/README.md`). A controlled accepted-
stream adapter test now retains two distinct backend flow records and pending
application bytes across a direct interface rebuild, completing FIN and releasing
flow permits in both families
(`target/evidence/phase-0/accepted-interface-mtu/README.md`). With packets for
both accepted flows queued, a busy rebuild also preserves the output queue,
TCP send queues, MTU and flow ownership before delivery and retry
(`target/evidence/phase-0/accepted-busy-mtu/README.md`). This does not apply
feedback or exercise the production runtime or physical path attribution. The
TCP adapter now offers an experimental 1280–1500 MTU constructor; its
ingress limit follows the current device MTU. Controlled tests admit exact
1500-byte packets in both families and reject them at the default or reduced
1280-byte MTU (`target/evidence/phase-0/accepted-ingress-mtu/README.md`). It now
reports a typed `PacketTooLarge { mtu }` separately from resource exhaustion
(`target/evidence/phase-0/typed-ingress-mtu/README.md`); the runtime still counts
such rejection without emitting ICMP. A test-only response candidate now
validates exact packet length, checksum, supported headers, selected address
categories, and accepted flow ownership before constructing bounded feedback in
both families (`target/evidence/phase-0/owned-ingress-feedback/README.md`). It
has no TCP sequence acceptance, directed-broadcast verification, verified
reporter policy, or sender adaptation evidence. A test-only candidate now
queues bounded feedback with a one-second per-flow cooldown, preserving the
output queue and cooldown on refusal
(`target/evidence/phase-0/ingress-feedback-queue/README.md`). The candidate now
uses a separate bounded feedback queue and lease index. Handed-off responses
retain flow ownership and block tuple reuse until release; stale queued
responses are discarded (`target/evidence/phase-0/feedback-lifetime/README.md`).
A test-only bounded channel now reserves capacity before removing feedback;
full or closed output preserves the queued handle, and a received handle retains
its lease (`target/evidence/phase-0/feedback-channel/README.md`). A controlled
Unix datagram pair now delivers the exact feedback while the handle remains live (`target/evidence/phase-0/feedback-datagram/README.md`).
A separate Linux TUN fixture delivers synthetic too-big feedback to connected
UDP senders in both families. The kernel reports the reduced path MTU, refuses
an oversized send, and transmits a smaller datagram
(`target/evidence/phase-0/tun-udp-pmtu/README.md`). It does not exercise the
feedback candidate, TCP sender adaptation, or a retained flow lease. TUN
handoff of the candidate, kernel acknowledgement, and cross-instance lifetime
remain unverified. It is not wired to the runtime and does not establish a production
rate policy. UDP, production configuration and runtime integration
remain separately constrained.
A single reserved outstanding
TCP segment now matches validated too-big feedback and applies its advertised
1280/1400-byte reduction. ACK retirement (including wrap/FIN), expiry, malformed
quotes and queue-busy retry are covered
(`target/evidence/phase-0/matched-pmtu/README.md`). The matcher now requires a
caller-selected reporter and rejects a different source without consuming the
reservation (`target/evidence/phase-0/selected-pmtu-reporter/README.md`).
ACK retirement also checks the supplied flow tuple and rejects another flow
without consuming the reservation (`target/evidence/phase-0/pmtu-ack-flow/README.md`).
This is not reporter authentication or verification that an ACK was accepted
by the stack. Production path attribution
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
(`target/evidence/phase-0/router-delayed/README.md`). The routed fixture now
also delays router ICMP in transit and verifies that an old report arriving
after a later send cannot consume its reservation, across all four family
combinations (`target/evidence/phase-0/router-delivery/README.md`). Cross-session
header uniqueness remains unverified. The current
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
The experimental socket owner now rejects repeated or decreasing WireGuard
counters for up to eight receiver indices per socket, including after failed
sends or reservation retirement. A ninth index fails closed; successful socket
replacement resets the bounded history. Tests cover delayed stale feedback,
capacity, uncertain sends, and replacement in both outer IP families. The
controlled routed kernel-peer workload still passes in all four inner/outer
family combinations (`target/evidence/phase-0/owner-counters/README.md`).
Production session retirement, path attribution, and state across owner
destruction remain unresolved.
The physical-path and PMTU ownership proposal now defines generation
invalidation, independent budgets and fail-closed shared-interface sizing.
An interleaved loopback test keeps two owners' reservations live at once,
rejects a report from the other owner even with an identical header, and
verifies that a failed transition does not prevent the first owner from
committing its own feedback. This uses one loopback path and synthetic reports.
An isolated kernel-peer fixture now also sends distinct encrypted datagrams
through two source-bound veth links with overlapping reservations. Each owner
rejects the other's genuine feedback and reduces only its own budget in all
four inner/outer family combinations
(`target/evidence/phase-0/overlapping-routed-paths/README.md`). The links share
a router and egress;
independent physical paths and production route verification remain open.
The router fixture also lowers one owned veth with both reservations pending,
uses a Linux link notification to invalidate that owner, and commits the
unaffected owner's report.
After the harness restores the link, a replacement socket completes a distinct
operation in all four family combinations
(`target/evidence/phase-0/link-notification/README.md`). The fixture also
removes and restores a source-specific route with two reservations pending; an
experimental route listener conservatively invalidates both owners on any route
event, then replacement sockets complete distinct operations
(`target/evidence/phase-0/route-notification/README.md`). An intermittent
routed TCP tuple failure in an earlier run remains unexplained. The fixture
also removes and restores the source-specific policy rule, observing conservative
invalidation for IPv4 and IPv6
(`target/evidence/phase-0/rule-notification/README.md`). An address-only
subscription also observes removal and restoration of a source address with
both owners invalidated
(`target/evidence/phase-0/address-notification/README.md`). The harness also
checks source-bound route lookup results for both paths and families before
traffic and before each link, route, rule, or address restoration is
acknowledged (`target/evidence/phase-0/route-recovery/README.md`). A mismatch
prevents replacement in the fixture. A pre-lookup subscription rejects queued
network changes and notification errors during the queries. A real route
change between queries now rejects the snapshot in the isolated fixture
(`target/evidence/phase-0/route-snapshot-change/README.md`). Notification
ordering and the period after the check remain unverified. In the link, route, rule,
and address recovery cases, a replacement owner verifies the candidate
socket's actual UDP endpoints before publication; failure leaves it unavailable
(`target/evidence/phase-0/link-candidate/README.md`). Initial owners in these
two-path scenarios now require the same candidate check
(`target/evidence/phase-0/initial-candidate/README.md`). Other fixture sockets,
socket marks, actual socket routing, and race-free verification remain open.
In route/rule and address recovery scenarios, both owners retain link,
route/rule, and address subscriptions and poll before sends, reads, and
feedback; the link-interruption scenario guards only the affected owner
(`target/evidence/phase-0/combined-owner-monitor/README.md`). Changes or
notification errors invalidate guarded owners. In route, rule, and address
scenarios, a retained worker observes changes while the second owner is idle
and wakes the supervisor, which refreshes that owner and joins the worker
(`target/evidence/phase-0/idle-path-watch/README.md`). Observation and owner
invalidation are separate; idle supervision of other owners, unguarded fixture
sockets, and the poll-to-operation interval remain open. Route-event
attribution, continuous monitoring, route verification and the interval before
notification processing remain unverified. The bounded notification poll now
drains unrelated messages before reporting an empty queue and fails closed if
its work limit is reached
(`target/evidence/phase-0/notification-drain/README.md`).
The routed kernel-peer fixture additionally verifies same-socket counter
rejection and stale-report rejection before committing a distinct later
report in all four family combinations
(`target/evidence/phase-0/owner-same-socket/README.md`). The routed fixture
now also checks delayed network delivery before applying that report.
The owner now replaces its socket during peer transitions and retains at most
eight retired sockets until owner destruction. This prevents local port reuse
within the owner lifetime, changes the local port in both families, and returns
a typed capacity error before changing the active flow when full. Transition
setup failures stay unavailable until recovery. The routed kernel-peer fixture completes an
encrypted exchange after transition in all four family combinations
(`target/evidence/phase-0/retired-socket/README.md`). Earlier evidence showed
that reconnecting the same socket could accept a queued datagram after returning
to the original peer. This bounded experiment has no timer-based retirement;
delayed traffic after owner destruction remains unresolved: a loopback test
forces reuse of the released local port and shows that a datagram from the same
peer reaches the replacement socket in both IP families. A separate BoringTun
test rejects an old encrypted data packet both before and after a fresh
handshake with the same static keys, while accepting new session data. It does
not establish behavior across process restart. A separate in-process test
shows that an already seen handshake initiation is rejected by the original
BoringTun instance but elicits a response from a fresh instance with the same
static keys. In that controlled sequence a newer initiation establishes a
working session, and another replay of the old initiation is rejected without
preventing subsequent data. It does not show acceptance of old application
data or establish process-restart behavior. Socket-level ambiguity remains. Route
publication, concurrent transitions, and general WireGuard transport
integration also remain unresolved.
The experimental UDP transport now discards BoringTun's stale-initiation
timestamp error, completes the original handshake, and receives encrypted
inner data in both outer IP families. Other malformed input still returns an
error; dropping the endpoint releases its socket. A damaged initiation MAC is
also discarded without a response. A finite burst filling the per-pump packet
limit defers a queued valid initiation to the next pump, which responds in both
outer families. This does not establish fairness under sustained hostile traffic.
Production policy for other rejected datagrams remains undecided.
The experimental transport also discards datagrams from an unexpected outer
socket address before passing them to BoringTun. A local test sends a valid
initiation from a different socket, observes no response, and then completes
the initiation from the configured peer in both outer IP families. This does
not establish roaming support, sustained-load fairness, or production policy.
A synthetic data-shaped packet with no current session is also discarded before
a valid handshake in both outer families. A separate in-process loopback test
forwards genuine retired-session data from the configured peer before and after
a replacement handshake; neither packet enters the stack, and new data does.
Actual delayed delivery across process restart remains unverified.
The same-library transport also discards damaged encrypted data and replayed
data without ending the session. A loopback test delivers the original after a
damaged copy, rejects its replay, and accepts a fresh packet in both outer IP
families. It also rejects that packet after advancing beyond the receive window
and accepts subsequent fresh data. Other error categories and sustained hostile
traffic remain open.
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
