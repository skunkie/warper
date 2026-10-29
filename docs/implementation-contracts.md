<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Post-Feasibility Implementation Contracts

Status: acceptance checklist; concrete Rust signatures and selected library APIs are pending Phase 0. Complete this document against the selected stack before Phase 1 production modules depend on those interfaces. Prototype APIs may change while investigating feasibility.

## 1. Required Contract Deliverables

For every boundary below, record the exact Rust types/signatures and source paths, supported platform/family combinations, ownership and lifetime rules, cancellation behavior, deadlines, resource accounting, and error variants. Define adapter-independent interfaces in core; keep third-party types inside adapters. A diagram or prose alone does not satisfy the gate: add compile-checked examples or contract tests using real implementations where available and a fault-injecting driver for failure states.

| Boundary | Decisions that must be locked |
| --- | --- |
| Accepted flow | Flow ID; source/destination socket addresses; TCP or UDP kind; inbound metadata; admission result; release-on-drop rules |
| TCP dial/relay | Async stream/trait-object representation; `Send` requirements; split/half-close behavior; setup cancellation; no payload replay; partial-write handling |
| UDP association | Datagram value/ownership; source/destination metadata; maximum size; queueing/drop policy; control-session ownership; idle expiry |
| Backend | Stable ID; available capabilities/families; health; readiness; TCP/UDP open calls; request context; startup/reconnect/shutdown; per-backend limits |
| DNS transport | Request/response ownership; framing; total request deadline; retry policy; valid negatives; CNAME/HTTPS/SVCB dependencies, hints, and endpoint provenance; truncated-response fallback; selected backend identity |
| Stack adapter | Host-facing accept vs active outbound dial roles; MTU; poll/readiness/timer integration; response injection; supported ICMP/fragmentation behavior |
| Physical egress | Endpoint resolution/refresh; route/socket exemption mechanism; network-change notification; validation before switching endpoints |
| Route manager/driver | Serialized transaction commands; operation IDs; ACK result; snapshots; pending-response/grace/flow references; ownership markers; rollback/recovery reconciliation |
| Supervisor | Task tree; fatal/nonfatal task errors; readiness barriers; cancellation tree; join ownership; bounded drain; terminal restoration and cleanup error reporting |
| Metrics/logs | Snapshot consistency; units; byte-counting boundaries; bounded buffers; loss counters; no backpressure into packet handling |
| Local control API | Shared redacted DTOs; XPC/Unix adapters; real peer identity and owner/admin authorization; version negotiation; bounded queues; operation IDs/configuration generations; snapshot/event resynchronization |
| Desktop native bridge | Narrow Tauri commands/capabilities; bundled local assets and CSP; native credential import without frontend secret persistence; service registration/approval lifecycle |
| Managed configuration | Authorized owner enrollment; normalized import without privileged path reads; protected atomic snapshot/credential storage; disconnected-session installation and fresh-boot startup policy |

## 2. Task and Resource Ownership

Name the owner of each TUN handle, stack runner, backend transport, flow task, timer, queue, journal operation, and DNS mutation. The top-level supervisor owns and joins service tasks; a flow/association owns and cancels its child work. No detached production task may outlive its service unnoticed.

For each queue, document its capacity, producer/consumer, overflow action, cancellation wakeup, and accounting against `docs/configuration.md` budgets. Enumerate hidden library buffers and OS socket memory separately. State lock ordering and prohibit holding global routing/journal locks across backend I/O. Route-manager serialization may await a bounded driver operation, but must not make packet forwarding wait on a global mutex.

Use a monotonic clock for request deadlines, idle expiry, leases, and bounded shutdown. Persistence records enough information to reconcile state after restart without treating a previous process's monotonic timestamps as current.

Define a DNS-state admission owner with atomic reservations against the
global lease/cache counts and retained-byte budget in the configuration
contract. Use the canonical logical lease key, coalesce renewals, and include
names, provenance, container capacity, expiry indexes and stale timer nodes.
Do not infer a metadata bound from kernel route count or active DNS requests.
Separate optional cache eviction from protected routing ownership; demonstrate
NET-12's exhaustion/reclamation/rollback cases before claiming bounded state.

## 3. Route Transaction State Machine

Model each owned prefix mutation with explicit states and operation IDs:

```text
Absent -> Prepared -> MappingPublished -> KernelAcknowledged -> Committed
                    failure/cancellation -> RollingBack -> Absent
                                                failure -> RecoveryRequired
Committed -> Retiring -> Absent
                    failure -> RecoveryRequired
```

`Prepared` includes durable intent. `KernelAcknowledged` requires a verified driver result, not a queued request. `Committed` includes recorded ownership and lease publication; only then may the positive DNS answer be released. A crash or lost ACK may leave the kernel operation outcome uncertain; recovery queries current state and verifies ownership before acting. No rollback may delete resources acquired by another transaction or referenced by another lease/flow.

The finalized contract must address multi-address DNS answers, concurrent duplicate requests, timeout after an operation may have reached the kernel, cancellation during journal writes, and flows arriving after route installation but before commit. If such a flow is admitted, its reference must survive failed DNS rollback; define safe retirement instead of deleting a route it uses. A timed-out request never later emits a positive answer.

Before response output can become visible, the response owns a pending reference to every required route. Define the handoff operation/permit that atomically renews coverage and exchanges those references for timed leases. A queued or partially written DNS response must not lose its routes while still being delivered; cancellation releases only its own reservations. The final handoff timestamp anchors `max(remaining_dependency_ttl_ms, dns_route_grace_ms)`. DNS caching remains governed by wire TTL, with zero-TTL answers never reused. Flow admission acquires a separate reference before retirement may withdraw the route. Tests must control the clock and output readiness to exercise every boundary.

For HTTPS/SVCB, record an endpoint's selected backend, owning query, effective target name, address source (hint, related Additional, or resolved address), alias/service path, and effective TTL. The dependency resolver retains the original backend; every dependency name must match that backend's winning configured domain policy. Reject a mismatch rather than learning implicit split-DNS domains. Include all exposed endpoints in one response gate and state how budgets, negative dependencies, disabled families, static coverage, and truncated UDP/TCP retries are handled. [ADR 0003](adr/0003-dns-endpoint-routing.md) defines the policy that these types must preserve.

For retirement, stop admitting new references under the serialized manager, remove only owned kernel state, and withdraw the unused internal mapping after removal is acknowledged. Define what packet handling sees during retirement and how it avoids direct fallback for packets already captured.

## 4. Error Taxonomy and Readiness

At minimum distinguish `InvalidConfig`, `Authentication`, `HostKey`, `UnsupportedCapability`, `UnsupportedIntegration`, `Timeout`, `Cancelled`, `ResourceLimit`, `RouteConflict`, transport/I/O errors, `ServiceUnavailable`, `ApprovalRequired`, `PermissionDenied`, `VersionMismatch`, `Busy`, and `RecoveryRequired`. Concrete variant names may follow Rust naming conventions; preserve these categories in diagnostics/tests. Include backend/flow/operation IDs and redacted field paths where relevant.

For each category, state whether it fails startup, rejects one request, degrades a backend, retries safely, or requires service shutdown. Trust/authentication errors are terminal until configuration changes. Never retry bytes already possibly delivered to an application peer. Keep the initial error plus cleanup failures, instead of replacing the useful cause.

Define the network-session readiness barrier: backends/handlers ready,
physical egress verified, static routes committed, then system DNS published.
Control API availability is a separate state and can report recovery/idle.
Successful Connect completion or a green Connected state must wait for the
network barrier. Client exit is not network shutdown; explicit Disconnect,
service shutdown, and owned runtime failure have their own cleanup paths.

Follow the [service/client contract](service-and-client.md). Specify operation
serialization/idempotency, observation timeout versus cancellation, same-boot
intent restoration, fresh-boot `service.autoconnect`, version mismatch, lost
events, and stale UI invalidation. Use OS-authenticated identity rather than
peer-supplied UID/PID/path. No generic shell/file-read endpoint is permitted.
The native registration/enrollment/authentication spike gates macOS-dependent
integration without blocking independent Linux feasibility/control work.

For local macOS development, implement the exact-build policy in
[ADR 0005](adr/0005-macos-development-authentication.md): a separate explicit
build/launch mode, administratively installed protected identity manifest,
actual peer identifier/CDHash plus OS UID checks in both directions, and
re-enrollment after code changes. Define how requirements are applied before
activation, how a non-sensitive handshake prevents outgoing credential leaks,
and how old connections/pins are invalidated. No UID-only, self-reported role,
or paid-certificate fallback can satisfy UX-05. Production artifact tests must
prove this mode cannot be enabled through flags, YAML, environment, or IPC.

## 5. Completion Gate

Before declaring this contract gate passed:

1. Link `docs/adr/0002-network-stack.md` and the exact pinned dependency versions/APIs used by both stack-role probes.
2. Replace pending signature decisions above with source links and compile-checked usage. Create only the interfaces needed for the next working slice; update contracts before later dependent features are introduced.
3. Record measurable limits and how cancellation/failure was exercised; include driver ACK delay, uncertain ACK, partial rollback, task termination, pending-response/grace expiry (NET-10), service-binding publication (NET-11), and global retained-state exhaustion/renewal/rollback (NET-12). The platform control contract also needs UX-05's native no-paid-account authentication evidence before macOS-dependent implementation.
4. Verify that `docs/configuration.md`, `docs/implementation-plan.md`, the implementation, and acceptance evidence describe the same behavior. Record unresolved limitations in `docs/implementation-status.md` and leave affected gates open.

## 6. Experimental Boundaries

These are compile-checked experiment APIs, not finalized production
contracts. No production module depends on them. Stack selection, the
initial production contract gate, and the failure-injection requirements
above remain open.

- `experiments/packet_peer.rs`: `Peer::new(IpAddr, u16) -> anyhow::Result<Peer>`
  owns one raw-IP device, interface, socket set, TCP socket, and UDP socket.
  `Peer::poll(i64)` takes elapsed milliseconds only within this experiment;
  production deadlines must use typed durations. `PacketDevice::inject`
  returns `io::ErrorKind::OutOfMemory` for packets over its declared MTU
  (default 1280; controlled MTU fixtures allow 1280–1500) or a full
  64-packet ingress queue. Egress applies backpressure at 64 packets through
  the `Device` transmit/receive tokens. Each TCP direction and UDP byte ring
  is 8192 bytes, with eight UDP metadata slots per direction. Container and
  library bookkeeping and kernel UDP buffers are additional allocations;
  this is not an RSS bound.
- `experiments/host-stack/src/main.rs`: `udp_case(bool, bool)` checks
  source/destination tuples and replies without treating datagrams as byte
  streams. `tcp_case(bool, bool)` owns a wrapper runner future alongside
  the packet driver and handler. Cancellation or error drops all three;
  no application task is detached. The driver must keep pumping packets
  while handler shutdown waits for ACKs. Each scenario has a two-second
  total deadline. TCP input is capped at 1024 bytes and compared with a
  fixed synthetic request; output accumulation has an explicit bound.
  The wrapper's hidden unbounded queues remain unresolved.
- `experiments/host-stack/src/direct.rs`: `DirectHost` is the separate
  direct smoltcp 0.14 candidate. It owns exactly four socket storage slots,
  two handler records, and one bounded packet device. Each handler has one
  TCP socket (8192 bytes per direction) and one UDP socket (8192 bytes and
  eight metadata slots per direction). Total socket payload capacity is
  64 KiB, plus metadata, packet queues, and stack/container bookkeeping.
  A handler's source record is fixed-size; no accepted-flow queue or task
  is allocated on SYN. A second connection to an occupied destination is
  rejected by the stack without replacing the admitted owner.
  UDP replies retain `UdpMetadata::local_address`, including empty payloads.
  Echo reads obey available send-ring space. `cancel()` aborts/closes all
  sockets, drops packet queues, and rejects subsequent `inject` calls with
  `io::ErrorKind::Interrupted`; dropping the owner releases socket storage.
  The experiment handles two preconfigured destinations, not arbitrary
  discovery. `run_probe(bool)`, `verify_admission_and_cancellation(bool)`,
  and `verify_stalled_reader(bool)` exercise both families with a controlled
  clock. Full exchange/admission is capped at ten simulated seconds;
  the stalled-reader case drives five seconds without application reads.
  This fixed-destination comparison has no asynchronous accepted-stream API.
  The separate TCP candidate below extends that boundary; backend transports
  and production scheduling remain open.
- `experiments/wireguard-stack/src/main.rs`: `probe(bool, Duration)` owns
  two peers, two nonblocking loopback UDP sockets, and two BoringTun states.
  No worker is spawned. It polls timers and packet I/O every millisecond,
  caps each receive/drain batch at 64, and verifies outer peer addresses
  and inner source addresses. A drain exceeding its budget fails instead
  of truncating pending output. Normal exchange has a ten-second deadline;
  sustained testing adds ten seconds to its requested duration. Keys are
  fixed public synthetic values. Requests/responses and initial UDP message
  counts are bounded. The executable returns operational errors with context;
  it logs no payloads or keys.
  Fixtures that require a specific next loopback datagram wait for readiness
  within a bounded wall deadline, rather than assuming it is available in the
  same turn as the send. Fragment fixtures observe a saturating count of
  accepted inner packets, including when assembly deadlines coincide. The
  PMTU fixture continues pumping until the final
  ACK is observed or its existing deadline expires. These checks do not establish
  native macOS networking acceptance.
- `experiments/wireguard-stack/src/kernel_peer.rs`: the Linux-only independent
  peer uses `wireguard-uapi` 3.0.1 to configure and read back the disposable
  `wg-feasibility` interface. Both the executable and namespace helper reject
  broad UID mappings before mutation; the harness creates fresh user, network,
  and mount namespaces. The helper owns interface creation and independently
  removes and verifies it on exit, including probe failure. Namespace teardown
  is the final backstop. No host resolver or physical interface is changed.
  Configuration readback verifies the public key, peer, listen port, and exact
  allowed addresses before traffic. Blocking netlink calls rely on the outer
  process deadline; this is not a finalized kernel ACK/ownership contract.
  Each exchange retains two socket worker handles, uses bounded polling and
  read/write waits, and joins both workers on success or failure. TCP replies
  follow request EOF; UDP preserves empty and unequal datagrams. Initial
  handshake loss is deliberate in the short IPv4 case. A 100 ms packet/timer
  drain after completion flushes delayed TCP acknowledgements before fixture
  session replacement. Normal harness runs have a 20-second outer deadline;
  independent-peer rekey runs have 200 seconds. Worker deadlines add ten
  seconds to the requested traffic duration. Errors preserve initial and
  cleanup failures without dumping key-bearing netlink objects.

The harness's external timeout and disposable namespace lifetime bound
failed packet experiments independently of their cleanup. There is no TUN,
route driver, system DNS, journal, resource reservation manager, or service
supervisor here, so these experiments cannot establish those interfaces or
their acceptance invariants. Explicit cancellation, uncertain ACK/rollback,
and crash-recovery tests must still be added for the applicable boundaries.

## 7. Experimental Accepted TCP Boundary

Status: executable Phase 0 candidate, not the finalized production contract.
Sources are `experiments/host-stack/src/adapter.rs`, adjacent
`adapter_tests.rs`, and `accepted_probe.rs`. Third-party stack types are
private. No production package depends on this candidate.

`FlowMetadata` contains `FlowId(u64)`, source/destination `SocketAddr`, and
`BackendId(u8)`. Backend indices are synthetic prototype identities, not
the stable string IDs of YAML. `AcceptedFlow` owns that metadata and an
`AcceptedStream` implementing Tokio `AsyncRead + AsyncWrite + Send + Unpin`.
Both driver and accepted flow are compile-checked as `Send`. The concrete
entry points, exercised by source tests, are:

```text
HostAdapter::new(Limits, fn(SocketAddr) -> Option<BackendId>)
    -> Result<(HostAdapter, mpsc::Receiver<AcceptedFlow>), AdmissionError>
HostAdapter::inject(&mut self, &[u8]) -> Result<FlowId, AdmissionError>
HostAdapter::poll_io(&mut self, &mut Context<'_>, Duration)
    -> Result<(), AdmissionError>
HostAdapter::take_packet(&mut self) -> Option<Vec<u8>>
HostAdapter::active_flows(&self) -> usize
HostAdapter::statistics(&self) -> &Statistics
HostAdapter::cancel(&mut self)
```

### Admission and Publication

Input is limited to the 1280-byte MTU. Library IP/TCP parsers validate
lengths, checksums, ports, and supported headers before admission. The
candidate rejects UDP/IPv6 extension transports with `UnsupportedProtocol`;
fragmented/malformed IPv4 is rejected by the configured library parser.
A non-SYN packet without an owner is `UnknownFlow`. An unmatched
destination is `UnselectedDestination`, with no direct transport. Existing
tuples retain their backend and ID; duplicate SYNs do not allocate a stream
or reset the setup deadline.

A new tuple reserves a socket slot, lifetime buffer permit, and owned
accept-queue permit before mutation. Packet-queue failure aborts the new
listener and releases reservations without disturbing other flows. Only
handshake completion publishes `AcceptedFlow`; the channel is not an
unbounded SYN queue. Setup expiry drops the unpublished stream and queue
permit. IDs increase; exhaustion rejects admission instead of wrapping.
The adapter never retries application bytes after partial admission/reset.

### Ownership, Bounds, and Deadlines

The driver owns an interface, packet device, fixed socket storage, and fixed
slot metadata. Defaults are two flows and two accept-queue permits; both
must be positive, queue capacity cannot exceed flow count, and the prototype
caps flows at sixteen. Each TCP socket has 8192 bytes per direction. Each
flow also owns a Tokio duplex connection with 8192 bytes per direction.
An owned semaphore permit is shared by driver and application lifetime
state and released only after both drop. Thus at most `limits.flows`
duplex lifetimes exist, including retired streams held by consumers.
A consumer retaining a timed-out stream can block new admission; it cannot
cause unbounded retired buffers. Default socket/duplex payload capacity
totals 64 KiB. Packet queues (64 packets per direction), metadata, fixed
channel/container allocation, allocator overhead, and stack bookkeeping
are additional; this is not a process RSS limit.

Storage sizes are fixed at construction. Bridging handles at most 1024
bytes per direction per flow per poll and honors free send-ring space.
Full duplex rings backpressure stack reads and the receive window; reads
reopen that window. Bounded counters replace completion history. No
synchronous mutex is held across asynchronous work.

The caller supplies monotonic elapsed `Duration`; backward/unrepresentable
time is `InvalidTime`. The host TCP/UDP candidates cap elapsed time at
`i64::MAX / 2000` milliseconds, leaving half the signed microsecond range
available for the pinned stack's internal timers. This bound does not prove
that every possible internal timer addition is safe. Default
setup/idle/absolute-age budgets are 10, 300,
and 86400 seconds, respectively. Limits are injectable for timer tests;
invalid/unrepresentable limits fail construction. Expiry at the deadline
aborts the socket and drops driver state, while consumer-held buffers
remain charged. No application task is needed for timer-only tests.
New flow admission rejects an unrepresentable absolute-age deadline before
reserving flow resources. Existing flows retain their original absolute
deadline when activity advances the idle clock.

### EOF, Errors, and Supervision

Half-close works in either order; read EOF preserves the opposite write
direction. Normal completion leaves buffered application output readable.
Transport reset is `io::ErrorKind::ConnectionReset`, deadline expiry is
`TimedOut`, and driver cancellation/drop is `Interrupted`, rather than
clean EOF. The shared reason is published before dropping the duplex
driver, waking blocked readers/writers. Repeated cancellation is safe,
closes acceptance, aborts sockets, discards packets, and rejects input.
Dropping an application before network EOF retires that flow; normal
EOF/shutdown allows buffered response data to drain.

The adapter spawns no task. The probe owns at most two controlled handler
tasks in a `JoinSet`, checks their results, and on failure cancels the
driver then aborts/joins remaining handlers while preserving the initial
error and cleanup diagnostics. The probe has a five-second wall deadline
and bounded controlled packet steps. A production runner must still prove
readiness/waker/timer scheduling, driver-failure propagation, task ownership,
and bounded service shutdown. These manually polled experiments do not
establish runtime supervision, general UDP acceptance, or route, DNS,
physical-transport, and native-platform mutation boundaries.
The combined candidate in section 9 adds wake-driven scheduling without
changing this adapter's ownership or selecting a production stack.

## 8. Experimental UDP Association Boundary

Status: executable Phase 0 candidate in `udp_adapter.rs` and `udp_probe.rs`
under `experiments/host-stack/src/`; no production package depends on it.
The candidate accepts validated unfragmented UDP packets, publishes original
tuple/backend metadata, and returns asynchronous datagram receive plus bounded
nonblocking reply admission. Backend selection occurs once per association.
Empty datagrams remain messages. Replies can target only the admitted source,
with the original destination as their source. Unsupported protocols, malformed
packets, unselected destinations, and resource exhaustion fail explicitly;
there is no direct transport.

Association slots, accepted queue, per-direction message queues, and a global
datagram quota are independently bounded. A lifetime permit remains charged
until driver and application release the association. A datagram permit stays
with its owned payload until the consumer drops it, including after expiry.
No new tuple is published until its first message and all reservations exist.
Rejected admissions do not refresh deadlines, displace another tuple, or
consume an ID. Idle and absolute-age deadlines use a caller-supplied monotonic
clock. Cancellation/drop closes channels, wakes waiting receivers, discards
owned output, and makes retained handles report cancellation. Retirement
removes pending output for that association; stale handles cannot send on a
replacement association. The prototype spawns no task and makes no readiness,
fragmentation/ICMP, TUN, or production backend claim.

### API and Validation

```text
UdpAdapter::new(Limits, fn(SocketAddr) -> Option<BackendId>)
    -> Result<(UdpAdapter, mpsc::Receiver<Association>), Error>
UdpAdapter::inject(&mut self, &[u8]) -> Result<FlowId, Error>
UdpAdapter::poll(&mut self, Duration) -> Result<(), Error>
UdpAdapter::take_packet(&mut self) -> Option<Vec<u8>>
UdpAdapter::active_associations(&self) -> usize
UdpAdapter::statistics(&self) -> &Statistics
UdpAdapter::cancel(&mut self)
Association::metadata(&self) -> FlowMetadata
Association::recv(&mut self) -> impl Future<Output = Result<Datagram, Error>>
Association::try_reply(&self, &[u8]) -> Result<(), Error>
Datagram::payload(&self) -> &[u8]
```

The prototype reuses the TCP experiment's metadata types; identifiers are
monotonic within each driver, not service-global identities. Driver,
association, and datagram are compile-checked as `Send`. Original tuple and
backend are immutable through the public API. Reply admission copies only
after queue and global quota reservation. `QueueFull` backpressures the caller;
`ResourceLimit` includes retained-message and retired-handle charges.

Smoltcp 0.14 IP/UDP parsers verify packet lengths and checksums. Fragmented
IPv4 and non-UDP IPv6 next headers, including extension/fragment headers,
return `UnsupportedProtocol`. The adapter explicitly rejects zero IPv6 UDP
checksums because the library verifier accepts them; omitted IPv4 checksums
remain permitted. Only unicast addresses, nonzero source/destination ports,
and an exact UDP length within the IP payload are admitted. Source port zero
is intentionally rejected because this reply-oriented boundary cannot return
traffic to it. There is no fragment reassembly or ICMP generation. Replies
are serialized with library representations and checksums, hop limit 64,
and at most 1252 IPv4 or 1232 IPv6 payload bytes at MTU 1280.

### Accounting and Retirement

Defaults are two associations, two accepted handles, four datagrams per
direction per association, sixteen globally retained datagrams, a 30-second
idle timeout, and a 300-second maximum age. Constructor bounds are sixteen
associations, 64 messages per direction, and 256 retained datagrams; all
limits must be positive and acceptance cannot exceed association capacity.
Durations cannot be zero or exceed the experiment's signed-millisecond range.

`Datagram` exposes only a borrowed payload, without clone/extraction. Its
owned semaphore permit remains charged even when the application holds it
after dropping an expired association. Reply permits transfer into the
bounded output queue (64 packets maximum) until handoff. Thus default retained
payload/packet storage is at most sixteen allocations of 1280 bytes, plus
one transient serialization allocation of at most 1280 bytes. Channel blocks,
fixed metadata, Arc/semaphore/container/allocator overhead, and caller-owned
output packets are additional; this is not a process RSS bound. Lifetime
permits bound retired associations and their channels independently of active
slots. Retaining handles/messages may prevent new admission; protected owners
are never evicted to make room.

Each poll rotates its starting slot, examines each slot once, and consumes
at most one reply per slot,
only with output capacity available. Successful ingress and reply conversion
refresh idle time; rejected input does not. Absolute age never renews. New
associations whose absolute-age deadlines exceed the supported clock return
`InvalidTime` before reserving resources; existing associations retain their
original absolute deadline. Expiry
at the exact deadline precedes reply processing, removes owned queued output,
and reports `TimedOut` before closing the input sender. Application drop
retires that tuple on the next poll. Cancellation is idempotent and reports
`Cancelled`; later cancellation cannot overwrite an already retired reason.
Both expiry and cancellation wake pending receive futures. No clean EOF is
substituted for a terminal error. Caller polling owns progress, expiry, and
cancellation observation; section 9 exercises one combined caller. Final
production scheduling, fairness under load, and backend task supervision
remain open.

Statistics are saturating counters without completion history. `received`
counts admitted input messages, `replied` counts serialized output admission,
and `rejected` counts failed `inject` calls. Output admission does not prove
wire delivery; retirement can still withdraw it. Application-side reply
errors are returned to the caller without creating a driver history entry.

## 9. Experimental Combined Runner

Status: executable Phase 0 candidate in `runtime.rs`, `runtime_tests.rs`, and
`runtime_probe.rs` under `experiments/host-stack/src/`, not the production
supervisor. A single
owned future drives both host adapters using application wakeups, bounded
packet input/output channels, and the earliest stack or flow deadline. It
does not use a fixed polling interval. Each turn bounds packet output work
and alternates protocol priority. Full output defers transport polling
deadlines while retaining lifecycle expiry and shutdown observation; output
capacity restoration wakes the runner. Application progress may still fill
bounded internal buffers, without polling indefinitely for a blocked sink.

Ingress copies only MTU-sized packets after channel reservation. Protocol
admission failures count as packet rejections without direct fallback.
Ingress/output channel loss is a typed runtime failure; explicit shutdown
cancels both adapters and returns counters after owned queues are discarded.
The caller retains/joins the runner and any backend/peer tasks. This candidate
does not establish service readiness, kernel I/O, graceful backend draining,
or the complete production shutdown/recovery contract.

### API, Scheduling, and Handoff

```text
Runtime::new(adapter::Limits, udp_adapter::Limits,
    fn(SocketAddr) -> Option<BackendId>, usize)
    -> Result<(Runtime, Channels), Error>
Runtime::run(self) -> impl Future<Output = Result<Report, Failure>>
Ingress::try_inject(&self, &[u8]) -> Result<(), Error>
Egress::recv(&mut self) -> impl Future<Output = Option<Vec<u8>>>
```

`Channels` owns cloneable ingress, guarded packet egress, separate accepted
TCP/UDP receivers, and the internal explicit-shutdown oneshot sender. Packet
channel capacity is 1–64 per direction; the probe uses 64. Each queued packet
is at most 1280 bytes. Constructor errors preserve TCP/UDP validation variants.
The adapters retain their independent flow/message quotas: this is not a
combined production resource reservation manager. IDs remain scoped to their
protocol driver, so consumers must distinguish TCP and UDP identity.

TCP `poll_io` registers its application-drop waker and schedules another
bounded turn after successful bridge progress. UDP `poll_io` registers its
driver waker; reply admission and application drop notify it after publishing
the relevant state. Both adapters expose `has_packet` and
`next_deadline(transport_ready: bool)`. TCP combines smoltcp
`Interface::poll_at`, state transitions, and setup/idle/age deadlines; UDP
combines queued work and idle/age deadlines. All times are elapsed monotonic
durations. A single coalescing `Notify` carries application wakes. The runner
waits with Tokio `select!` and `sleep_until`, with no interval or polling sleep.

Each turn admits at most one queued input and emits at most eight packets,
alternating TCP/UDP when both have output. UDP also rotates association
priority to prevent a near-full adapter output queue from continually
favoring its first slot. When the handoff channel is full, output-capacity
reservation remains a wake source and transport work deadlines are deferred;
lifecycle deadlines and application/channel/shutdown events remain armed.
Readiness and bounded work resumption do not establish throughput or latency
guarantees under arbitrary load.

Packet admission failures increment a rejection counter; malformed input,
unknown flows, unsupported protocols, policy misses, and quota errors do not
terminate the runner or switch transport. Channel closure is different:
`IngressClosed`, `EgressClosed`, or `ShutdownOwnerLost` terminates the runtime
with `Failure { cause, report }`. The internal shutdown owner is the experiment
supervisor, not a GUI/control client. Its loss cannot masquerade as successful
Disconnect. Explicit shutdown is checked every bounded turn. Adapter/clock
failures retain their typed cause. Counters saturate and retain no per-run
completion history.

Sending a packet to the egress channel hands it off beyond the adapter;
association retirement can withdraw only adapter-owned output. At runtime
shutdown/drop, an atomic guard prevents egress from returning queued packets
and discards them on the next receive/drop. A packet already returned to the
caller remains caller-owned. Accepted handles/messages retained by consumers
keep their existing bounded charges and report terminal errors. The runtime
closes/drains input, cancels both adapters, and drops its queue/channel owners;
its synchronous local cleanup has no fallible OS mutation. A cancelled runner
future executes the same adapter cancellation through `Drop`.

The combined probe retains its runner `JoinHandle` and at most two handler
tasks. It verifies simultaneous 64 KiB streaming TCP plus a response trailer
after FIN, empty/unequal/MTU-sized UDP, metadata, and explicit shutdown in both
families. The controlled peer acknowledges final UDP receipt solely to keep
its fixture handler alive; this is not UDP delivery acknowledgement exposed
by the adapter. Peer stack polling also follows library deadlines. Its TCP
reader drains both possible contiguous receive-ring slices before waiting.
The fixture has a five-second exchange deadline and a one-second runner join
deadline; failure aborts/joins remaining tasks and preserves the initial
error with additional cleanup diagnostics. Paused-clock tests need Tokio's
existing pinned `test-util` feature only as a development dependency.

No kernel descriptor, backend transport task, journal, DNS mutation, readiness
barrier, or graceful production drain is implemented here. Native-platform
and outage/MTU/ICMP acceptance and finalized production contracts remain open.

## 10. Experimental Active Tunnel Failure Boundary

Status: Phase 0 failure probe, not a production backend API. The probe owns
the active stack, BoringTun state, and outer UDP socket as one optional
resource group. Setup, session lifetime, and an explicitly armed application
response deadline use injected monotonic time. Cryptographic handshake
completion is distinct from application response success. Cancellation,
expiry, and fatal transport/resource errors destroy the resource group;
later operations retain the original terminal category. There is no direct
fallback, automatic application reconnect, or application-payload replay.

Before encapsulation the transport reserves one of 64 plaintext staging
slots, below the pinned library's silent-drop queue limit. Immediate encrypted
data releases that reservation; handshake-staged packets retain it until
drained. Encrypted keepalives do not release application reservations. A full
queue fails explicitly before handing another packet to the library. Each
drain permits 64 packets plus its final Done sentinel, with a typed error if
the bounded drain or its accounting invariant fails.

Controlled loopback peers blackhole outer packets before setup or after
connection. Transient outage checks TCP's own retransmission without another
application write and verifies that a lost UDP datagram is not replayed.
Permanent request loss, queue exhaustion, and cancellation verify immediate
outer socket release. These cases do not establish kernel networking,
physical endpoint changes, service crash recovery, or production deadlines.

`outage.rs` keeps `Session`, `Budget`, `Reason`, and `Failure` private to the
experiment. `Session::new(Endpoint, Budget)`, `step(Duration)`,
`arm_response(Duration)`, `complete_response()`, and `cancel()` are exercised
against real controlled peers, without production dependents. The endpoint
is an owned resource group, not a backend-neutral core interface. The
fixture uses one-second setup and ten-second absolute lifetime budgets,
with explicit response budgets of 100 ms or three seconds. These are
experiment inputs, not YAML defaults. Zero/invalid budgets and backward or
unrepresentable time fail before mutation. Only one response reservation
can be armed; pre-handshake admission is `NotReady`, overlap is `Busy`.

Expiry is checked before polling at the exact deadline. Initial transport
errors retain their source; subsequent calls and cancellation preserve the
terminal reason. Destruction releases the outer socket immediately, verified
by rebinding its exact address. No worker is spawned. Controlled connect and
recovery loops have finite packet steps and wall deadlines; BoringTun's own
timers remain real-time. Each staged IP packet is at most 1280 bytes, so the
additional library plaintext budget is at most 80 KiB, excluding fixed tunnel
state, stack buffers, bounded raw packet queues, metadata/allocator overhead,
and kernel socket memory. Queued output that cannot reach its selected peer
is never redirected to a physical application socket.

The resource policy is deliberately fatal rather than silent library loss.
Malformed traffic from the selected outer peer follows the probe's fatal error
policy, except for the rejected handshake and data packets described below.
Datagrams from other outer addresses are discarded before decapsulation and
count toward the per-pump receive limit. Broader
resilience to hostile datagrams and production congestion
backpressure require separate decisions. Full-queue tests observe 64 actual
encrypted datagrams at the peer socket, not 64 application deliveries through
its smaller UDP ring. Kernel-peer interoperability/rekey and same-library
outage scopes remain separate evidence. A valid initiation sent from another
socket produces no response, and the same initiation from the selected peer
then produces a response in both outer IP families. This does not establish
roaming or sustained-load fairness.
Before handshake, a synthetic encrypted-data-shaped datagram from the selected
peer produces `NoCurrentSession`; the transport discards it and completes the
subsequent valid initiation in both outer families. Another in-process test
creates genuine encrypted data under a retired session, forwards it from the
replacement's configured peer before and after the new handshake, and verifies
that only new-session data reaches the stack. This does not establish actual
process-restart or delayed network delivery behavior.

A controlled loopback test sends the same valid handshake initiation twice
from the selected outer peer. The first produces a handshake response; the
second is discarded on BoringTun's `WrongTai64nTimestamp` result in both
outer IP families. The original handshake then completes and encrypted inner
data enters the peer stack. An unrelated malformed packet still returns an
error, and dropping the endpoint releases its socket. A burst exceeding the
per-call packet limit requires a second pump. This narrow experiment does not
establish production packet rejection policy or resilience to a sustained
hostile sender.

After that handshake, the loopback test corrupts an encrypted data packet,
then delivers the original, replays it, and sends fresh encrypted data. The
transport discards `InvalidAeadTag` and `DuplicateCounter`; the original and
fresh data each enter the stack once in both outer families. It then advances
the sender beyond BoringTun's receive window, discards the original on
`InvalidCounter`, and accepts another fresh packet. Other error categories and
sustained hostile traffic remain outside this evidence.

A separate loopback test corrupts the initiation's MAC, verifies that it
produces no response or inner data, and then receives a response to the
original valid initiation. The pump discards BoringTun's `InvalidMac` result
under the same packet limit. This does not classify other authentication or
protocol errors, and it does not test sustained hostile traffic.

## 11. Experimental MTU and ICMP Boundary

Status: fixed-envelope checks and bounded pre-admission fragment input exist;
dynamic PMTU is unsupported and `host-stack --mtu-check` still fails.
`mtu_probe.rs` drives actual smoltcp TCP sockets with a controlled clock.
The shared `Peer::with_mtu` constructor accepts only 1280–1500 bytes for
these experiments, preserving the default 1280 and bounded packet counts.
This is fixture configuration, not a change to YAML MTU validation.

Both families demonstrate fixed 1280-byte segmentation and valid ICMP
port-unreachable responses from the raw stack. A separate 1500-byte link
emits real TCP data above 1280. A controlled ICMPv4 fragmentation-required
or ICMPv6 Packet Too Big message advertises 1280 and quotes that packet's
exact header and transport bytes. The fixture validates message type/code,
next-hop MTU, quote, and checksum; it preserves original quoted lengths
rather than rewriting a truncated quote to fit a high-level parser. IPv6
errors stay within 1280 bytes. Subsequent timer-driven retries still exceed
the advertised path size. The pinned stack does not adjust TCP sizing from
this feedback and exposes no public established-connection MTU setter.

Fragment probes split a valid UDP datagram into two actual IPv4/IPv6
fragments and inject both orders. No UDP payload is reassembled with the
selected features, while the unfragmented control reaches its UDP socket.
Section 12 supplies a bounded fragment-input adapter without changing those
raw-stack features. A controlled shared-interface probe reserves feedback for
one of two TCP flows with oversized unacknowledged packets. It rejects feedback
quoting the other flow, then applies matched feedback to reduce the shared
interface from 1500 to 1280. Both flows retransmit and complete FIN while a
distinct UDP datagram is delivered once in each IP family. This does not
establish general path attribution or exercise the production runtime. PMTU and the remaining fragmentation strategy must be
resolved before the MTU/ICMP gate or stack ADR can be accepted. ICMP
generation by a raw peer does not prove error propagation through the host
runtime or active backend API. Kernel TUN, route/path changes, and native
platform behavior remain unverified.

`wireguard-stack/src/path_mtu.rs` separately validates a declared outer
budget before transport use and rejects oversized encrypted datagrams before
socket send. The loopback fixture declares 1500 bytes, not a discovered or
verified physical PMTU. Fixed 1280-byte inner packets require at least 1340
bytes for IPv4 outer transport or 1360 for IPv6: IP and UDP headers plus
32-byte WireGuard data overhead. The bound reserves 16-byte alignment,
although pinned BoringTun currently emits unpadded data. Budgets above 65535
are invalid; insufficient paths are typed `PathTooSmall`, and oversized
output is `PacketTooLarge`, without fallback or fragmentation. Supporting
smaller physical paths requires an explicit separate strategy.

WireGuard peers now exchange maximum unfragmented UDP payloads (1252 IPv4,
1232 IPv6) as well as empty/unequal messages. An oversized real encrypted
packet test proves rejection before outer send. These prove fixed packet
size bounds, not general PMTU discovery or fragmentation support.

## 12. Experimental Bounded Fragment Input

Status: host-side Phase 0 candidate. Fragment input is normalized before
TCP/UDP admission; no handler, backend, or flow is published for an incomplete
datagram. The candidate uses released smoltcp header parsers and its public
bounded `storage::Assembler`, with fixed payload storage and overlap policy
owned by the adapter. No upstream fork or global fragmentation feature is
introduced. Larger packets and extension-header chains remain unsupported.

Defaults are two independent assembly slots, 1280 bytes per reassembled IP
packet, and a one-second nonrenewing deadline. Overlap, inconsistent final
length, protocol mismatch, or excessive disjoint ranges discard the whole
datagram and retain its bounded tombstone until expiry. No protected assembly
is evicted to admit another key. IPv6 atomic fragments are processed
independently of queued fragments with the same identification. Cancellation
and timeout clear partial state; runtime scheduling includes assembly expiry.
Completed packets retain source/destination/protocol, have normalized IP
length/fragment headers, and undergo the existing transport checksum and
policy validation. This does not implement PMTU or outgoing fragmentation.

The isolated Linux TUN fixture also forces kernel fragmentation of UDP
datagrams one byte over the 1280-byte reassembly limit. It observes initial
and final fragments for two destinations in both families, receives no reply
within 200 ms for those datagrams, and verifies subsequent supported datagrams
succeed.
This tests rejection and continued operation, not forwarding or reassembly of
datagrams above the limit.

The combined-runtime controlled-clock test fills both slots with overlap
tombstones. It checks that distinct fragment sets publish no handler before
expiry, then that a different datagram is admitted at expiry without replaying
the rejected sets. This covers runtime scheduling and accounting in both IP
families; it is not a real-TUN overload or sustained-traffic test.

A separate Linux TUN scope sets an IPv4 route MTU of 1000 bytes while retaining
the interface's 1280-byte MTU. It observes kernel-generated fragments of a
1252-byte UDP payload for each of two destinations, then verifies the complete
payload, original tuple, backend selection, and 1280-byte unfragmented reply.
The oversized-rejection sequence runs separately because discarded assemblies
retain their two slots until expiry. Native IPv6 fragmentation of an in-limit
datagram and production route handling remain unverified.

The shared implementation is `experiments/reassembly.rs`; host adapter tests
and probes remain under `experiments/host-stack/src/`. Controlled packet
splitting lives in `experiments/fragment_fixture.rs`. Concrete entry points are:

```text
Reassembler::new(Limits) -> Result<Reassembler, Error>
Reassembler::accept(&mut self, &[u8], Duration) -> Result<Outcome, Error>
Reassembler::advance(&mut self, Duration) -> Result<(), Error>
Reassembler::next_deadline(&self) -> Option<Duration>
Reassembler::statistics(&self) -> &Statistics
Reassembler::cancel(&mut self)
Outcome = Pass | Pending | Complete(Vec<u8>)
```

Constructor limits permit 1–4 slots and a positive timeout up to 60 seconds.
Each slot owns 1280 payload bytes, 40 header bytes, fixed library range
metadata (four disjoint ranges with pinned build configuration), key,
deadline, and bounded state. Slots are preallocated; fragments do not grow
payload storage. One completed packet allocates at most 1280 bytes and is
immediately validated/admitted by the owning runtime. Statistics saturate;
no completion history or per-fragment timer node is retained.

Only plain IPv4 headers or a base IPv6 header directly followed by one
Fragment Header are supported, for TCP/UDP unicast traffic. Nonfinal payloads
must be nonempty multiples of eight. First fragments must contain the full
transport header. IPv4 fragment checksums, lengths, flags, and offsets are
validated before reservation; IPv6 reserved fields and lengths are checked.
IPv6 identity excludes next-header protocol, so a mismatch poisons the same
assembly instead of creating another owner. IPv4 identity includes protocol.
Reconstructed packets pass existing transport checksum/policy validation
before publication. No route/backend reference is acquired for partial data.

Overlapping duplicates are rejected as overlaps. Discarded assemblies retain
their slot until the original deadline, preventing later pieces from reviving
the same datagram. IPv6 atomic fragments neither consume nor alter a queued
slot with their identification. The runtime observes assembly timers even
without more input, and cancels this owner on every exit/drop path.
New assemblies are admitted only when their timeout deadline fits the
supported monotonic clock; an unrepresentable deadline returns a typed time
error without allocating a slot. Fragments for existing assemblies retain their
original deadline and do not require a new representable deadline.

Packet receive stages at most one additional MTU-sized input until the next
bounded turn advances every adapter's monotonic clock. This prevents
first-after-idle packets inheriting stale creation times. Queued shutdown
still precedes admission, and cleanup counts/discards staged input. Separate
protocol quotas, backend ownership, and guarded egress remain unchanged.

## 13. Experimental Decrypted Fragment Input

Status: active WireGuard-side Phase 0 candidate. The same bounded
`experiments/reassembly.rs` boundary is applied after peer authentication and
inner source/destination validation, before plaintext enters the active IP
stack. Each transport owns independent assembly slots and a monotonic clock;
partial packets are never injected into TCP/UDP sockets. Pump calls advance
expiry even without incoming ciphertext. Transport destruction cancels partial
state together with its tunnel and socket; fatal fragment errors retain their
typed source through the existing active owner. This does not change PMTU,
outgoing fragmentation, roaming, or production error policy.

`Transport::pump(&mut Peer, Duration)` advances the injected monotonic clock
before handling decrypted packets. Source validation uses the authenticated
peer's configured inner address; destination must match a local stack address
before any fragment slot is reserved. Unfragmented packets follow the same
checks. Fragment errors are fatal in this experiment; production peer-error
isolation remains unspecified and must be finalized before reuse.

The default WireGuard probe exercises both fragment orders and both directions
for maximum-size UDP datagrams, preserving tuple and payload boundaries. It
also expires partial input without traffic, rejects an authenticated duplicate
inner fragment, and releases outer sockets with partial/tombstone state still
retained. These fixtures encrypt every fragment separately; they do not test
fragmentation of outer UDP packets or kernel-peer fragment handling.

## 14. Experimental Independent-Peer Outage Workload

The active exchange helper supports a controlled outage after the four initial
UDP request/reply datagrams and TCP establishment. It admits the TCP request
once, half-closes once, and queues one distinct UDP datagram while outbound
ciphertexts are suppressed. It observes the distinct UDP datagram and initial
TCP segment entering the blackout, then requires a TCP segment with the same
sequence number while the blackout remains active for at least 1200 ms. After
at least three encrypted packets are dropped, it restores transport and sends a
separate recovery heartbeat. TCP retransmits through the stack; the application
never resubmits request bytes or lost UDP.
For the independent peer, the client then suppresses inbound ciphertext for
at least 1200 ms while the kernel worker writes its response. The worker's
atomic notification establishes that the write occurred; the client requires
at least one subsequent WireGuard data datagram to be discarded, sees no
application response during suppression, and then receives the exact response
and EOF. The encrypted datagram is not inspected to identify its inner payload.
Completion also requires the recovery heartbeat.

The default Linux kernel-peer run applies this workload in both inner families.
Its retained workers validate the exact TCP request and reject the lost UDP
payload if it appears. Exactly five UDP messages are expected: the four original
messages and one recovery heartbeat. Automatic sustained heartbeats are disabled
for this bounded case. A 25-second workload deadline and matching worker
bound include handshake loss, the observed retransmission, and later TCP
recovery; workers are stopped and joined on every result. The separate
sustained rekey workload retains its periodic heartbeats.
This establishes controlled outbound and inbound ciphertext suppression and
recovery against an independent peer, not full network outage detection,
service crash recovery, or roaming.

## 15. Experimental WireGuard Outer Address Families

Pair fixtures select the outer address family independently of the inner
family. IPv4 endpoints bind loopback IPv4; IPv6 endpoints bind loopback IPv6,
without dual-stack or cross-family fallback. The client derives its local
socket family and declared path-header budget from the remote socket address.
The server applies the same selection. Both outer families use actual UDP
sockets and preserve exact peer-address checks.

Default packet probes cover all four inner/outer combinations for TCP, UDP,
FIN and encrypted inner fragment input. Linux kernel-peer probes pair IPv4
inner/outer and IPv6 inner/outer with the controlled outbound-loss workload;
the kernel-peer's additional sustained rekey workload uses IPv6 outer
transport. These
loopback probes establish family interoperability, not physical-path bypass,
outer fragmentation, dynamic PMTU discovery, or production endpoint roaming.

## 16. Experimental Reserved UDP Error Feedback

Status: a single-operation feasibility boundary, not a production backend API.
A transport may reserve one emitted unfragmented UDP packet for error matching.
Reservation retains only addresses, IPv4 identification when applicable, and
its eight-byte UDP header, never payload. A second reservation returns typed
Busy without replacing the first. The operation owner supplies its deadline
and destroys the transport on cancellation/expiry; no unbounded error queue or
packet history is retained. Default exchanges do not reserve operations.

After authenticated source/local-destination validation, plaintext ICMPv4
port-unreachable or ICMPv6 destination-unreachable/code 4 is matched against
that reservation. Validate full outer IP/ICMP lengths/checksums and the quoted
IP header, protocol, addresses, UDP header/declared length, and IPv4 identity.
Quotes may be truncated after the complete UDP header without rewriting the
original IP length. Ignore unrelated/malformed ICMP bodies inside valid IP
envelopes without consuming the reservation; malformed IP envelopes retain
the experiment's existing packet-failure policy. A match consumes it once and returns typed PortUnreachable through
the existing fatal experimental owner; application payload is never replayed.

Only plain unfragmented IPv4/IPv6 headers are accepted by this candidate.
Router-originated errors, other ICMP categories, PMTU adjustment, concurrent
UDP operations, host-side error synthesis and production peer-error isolation
remain unresolved. Peer authentication authenticates the tunnel sender, not
any quoted packet's ultimate origin. Matching minimum quotes cannot distinguish
identical datagrams; deadlines/ownership limit stale-operation exposure and do
not establish cryptographic anti-spoofing.

## 17. Experimental Interface MTU Reduction

Status: a sizing-control feasibility probe, not complete PMTU discovery.
The pinned stack stores device capabilities in `Interface`; updating a device
alone does not refresh the cached TCP sizing context. A raw-IP experiment
therefore replaces only `Interface` after reducing an empty device's MTU,
retaining the original `SocketSet`, socket handles, endpoints, TCP buffers,
sequence/acknowledgement state, and timers. It copies interface addresses,
routes and any-IP policy and uses the current controlled monotonic time.
Selected features have no neighbor, SLAAC, multicast or fragmentation state
to transfer. The fixture re-seeds interface randomness; production entropy and
state-transfer policy remain unproven. Reduction is interface-wide and also
lowers the device receive limit; multiple flows and asymmetric paths are not
established. This is not a generic interface migration API.

Device reconfiguration accepts only the existing 1280–1500-byte fixture range
and rejects nonempty input/output queues before mutation. It does not evict
queued packets. The controlled path deliberately drops oversized TCP output
before reconfiguration; TCP owns retransmission of unacknowledged data. No
application write is repeated and no UDP queue is discarded by this operation.

The probe starts an established 1500-byte TCP connection, delivers and
acknowledges part of one application write, drops later oversized output,
then reduces the interface to 1280. It must deliver the complete original
byte sequence exactly once, preserve endpoints and FIN/half-close, and keep
all subsequent packets within 1280. Existing raw ICMP behavior remains a
negative control. Production feedback validation/attribution, per-path state and expiry,
UDP errors for queued output, smaller physical paths, and production WireGuard
integration remain separate work; the MTU gate still returns unsupported and ADR 0002
remains proposed.

## 18. Experimental Matched TCP PMTU Feedback

Status: one outstanding TCP segment, one interface-wide reduction candidate.
Reserve a validated emitted TCP data packet after its owner has established
that its sequence remains outstanding. Store only addresses, original IP
length/IPv4 identity and the first eight TCP bytes (ports and sequence), with
one nonrenewing deadline and one explicitly selected unicast reporter of the
same IP family. The owner supplies only ACKs already accepted by the stack,
along with the local and remote socket addresses of that flow. An ACK for a
different tuple returns a typed error without retiring the reservation; a full
ACK for the reserved flow retires the segment (including FIN sequence
space), while partial ACKs preserve it. A second reservation is Busy;
cancellation and exact deadline expiry retire the reservation. The candidate owns no payload, cache,
unbounded history or background task.

ICMPv4 fragmentation-required and ICMPv6 Packet Too Big must have valid IP and
ICMP lengths/checksums, a local recipient, the selected reporting source and an
exact quoted IP/transport identity. Quotes may stop after eight TCP bytes while
retaining original IP lengths. A selected router source is allowed; matching is
not cryptographic authentication or proof of path ownership. Reporter selection
and changes remain a production path-policy decision. Malformed/unrelated
feedback cannot mutate sizing or consume the reservation. Only supported
1280–1500-byte reductions smaller than the quoted packet are usable; matched
sub-minimum/zero advertisements return typed UnsupportedMtu without pretending
that fragmentation or legacy plateau discovery is available.

Validation, interface replacement and reservation consumption run synchronously
under the same experimental owner. Empty-queue refusal retains the reservation
and its original deadline for retry; commit consumes it only after successful
replacement. The live retained-TCP probe now derives its 1280 sizing action
from matched feedback, rather than passing a literal MTU to the rebuild helper.
Both 1280 and 1400 advertisements are exercised in each family; an advertisement
cannot increase a device already configured at a smaller MTU.
Per-path caches/expiry, changing routes, concurrent flows, asymmetric/outer
paths, below-minimum handling, production entropy/state transfer and feedback from WireGuard's outer path
are still open. The full MTU gate remains unsupported.

Sources: shared `experiments/pmtu_feedback.rs`, with validation tests under
`experiments/host-stack/src/pmtu_feedback_tests.rs`. Shared
`experiments/mtu_reduction.rs` owns synchronous classification, interface
replacement and commit; `experiments/pmtu_fixture.rs` builds controlled feedback.
The concrete tracker API is:

```text
Tracker::default()
Tracker::reserve(&mut self, packet: &[u8], reporter: IpAddr, now: Duration, lifetime: Duration)
    -> Result<(), Error>
Tracker::acknowledge(&mut self, source: SocketAddr, destination: SocketAddr, accepted_ack: u32, now: Duration)
    -> Result<(), Error>
Tracker::reduction(&mut self, feedback: &[u8], now: Duration)
    -> Result<Option<usize>, Error>
Tracker::next_deadline(&self) -> Option<Duration>
Tracker::commit(&mut self)
Tracker::cancel(&mut self)
```

Lifetimes are positive and at most ten seconds; the flow probe uses one second.
Time-bearing operations check the injected monotonic clock. Full ACK, expiry, commit
and cancellation clear pending metadata. Classification alone never consumes
a reservation; the owning synchronous apply operation commits only after its
mutation succeeds. No await or other flow progress intervenes between those
steps in this candidate. The owner must provide the tuple belonging to the
accepted ACK and must not reuse a reservation for a different flow or operation.

## 19. Experimental Encrypted Inner PMTU Feedback

Status: same-library WireGuard integration of the bounded TCP sizing candidate.
Default transports retain the 1280-byte inner limit and 1500-byte declared outer
budget. A controlled TCP-only fixture uses 1500-byte peers and a 1600-byte
outer budget; it validates decrypted plain TCP before either delivering it or
dropping oversized packets and returning one encrypted too-big message. Its
larger TCP admission is scoped to this fixture and does not expand ordinary
fragment/UDP support. The reporting address is the configured inner peer. IPv4 oversized fixture
packets must have DF set before fragmentation-required feedback is generated.

The client reserves one emitted outstanding TCP data segment. Authenticated
source/local-recipient checks precede quote matching and synchronous interface
replacement. A successful replacement commits the reservation once; malformed
or unrelated feedback cannot resize. The owner supplies accepted ACK retirement
and the pump checks reservation expiry even without further packets. Busy or
unsupported mutations follow the experiment's typed fatal-error policy; no
new hidden retry queue is introduced. All state remains owned by the endpoint
and is cancelled/dropped with its socket and tunnel.

Probes cover both inner/outer families and 1280/1400 advertisements, preserving
one application write, exact bytes, lost-sequence retry and FIN/response across
the same established TCP connection. The peer must process the final ACK before
fixture retirement. They establish encrypted inner feedback,
not physical outer-UDP PMTU discovery, independent-kernel PMTU, path attribution,
concurrent/asymmetric routing, sub-minimum paths or a production migration API.
Remote router-address admission remains unproven under the experiment's exact
inner-source policy.

## 20. Experimental Local Outer UDP MTU Feedback

Linux-only candidate using safe nix error-queue decoding and rustix socket
options. A dedicated connected UDP socket explicitly enables reliable error
reporting and no-fragment path discovery, with option readback. The owner
serializes I/O, keeps its local/remote tuple fixed, and confirms an empty error
queue before one application datagram can fail. A local MTU report is usable
only alongside that synchronous EMSGSIZE and matching error-queue destination,
family, LOCAL origin, EMSGSIZE errno, zero type/code and nonzero bounded MTU.
Remote ICMP errors do not satisfy this local attribution contract. The reader
owns one duplicate socket descriptor, so it cannot outlive the underlying
socket or consume errors from a replacement descriptor. The owner drops this
reader before socket rebinding/retirement; a peer change is rejected.

One nonblocking recvmsg reads at most 2048 payload bytes and 256 ancillary
bytes; truncation, missing/duplicate/unknown controls or endpoint changes fail
without changing the path budget. No packet payload is logged, retained or
replayed. A validated report can reduce the declared outer budget only; an
unsupported small path is typed failure and a larger report cannot grow it.
Section 21 adds sizing for one retained TCP connection from local feedback.

The isolated 1400-byte loopback fixture carries real BoringTun traffic. After
handshake/warmup, one oversized encrypted UDP datagram must fail locally and
never reach the peer. Its kernel error reduces the budget; the same size is
then rejected before send. A distinct safe datagram must arrive intact over
the same tunnel. Both inner/outer families are tested. Endpoint destruction
and address rebinding prove cleanup. This is local enforcement, not remote
router/path-change discovery, physical-path validation or full PMTU acceptance.

Implementation: `wireguard-stack/src/outer_errors.rs` reads one bounded
nonblocking error record; `outer_mtu_probe.rs` owns the serialized operation,
expected failed-send diagnosis, budget reduction and cleanup. Safe APIs are
pinned nix 0.31.3 (net/uio) and rustix 1.1.5 (net/time), Linux-only. Dedicated
socket ownership means these option changes need no host-state rollback.
No generic transport path enables the option automatically in this increment.

## 21. Experimental Outer-Driven TCP Sizing

Status: local-kernel outer feedback applied to one retained TCP connection.
A validated outer MTU yields an inner limit of
`floor((outer_mtu - outer_IP_UDP_headers - 32) / 16) * 16`, reserving WireGuard
padding. Unsupported paths fail before mutation. At outer MTU 1400 the limit
is 1328 for IPv4 outer transport or 1312 for IPv6, independently of inner family.

The controlled owner handles one synchronous failed encrypted send with an
initially empty error queue. It validates all pending output as checksum-valid,
unfragmented TCP for the same socket tuple and refuses queued input, UDP,
foreign flows or invalid clocks before mutation. Pending TCP packet attempts
may then be retired explicitly; their unacknowledged bytes remain in the
original TCP send buffer. Interface replacement preserves the SocketSet and
commits the reduced outer budget only after sizing succeeds. No ciphertext or
application write is replayed; TCP generates retries with fresh encryption.

The isolated outer scope adds 1500-byte TCP fixtures under a declared 1600-byte
outer budget. Kernel EMSGSIZE/report 1400 must drive the reduction, exact 8 KiB
transfer, original tuple, lost-sequence retry, FIN/response and final peer ACK.
The receiver's scoped larger-TCP admission must generate no inner feedback.
All four inner/outer combinations run. This remains one serialized local-path
operation, with the prior interface-wide/state/entropy restrictions; remote
router discovery, concurrent flows and general physical-path policy stay open.

## 22. Experimental Independent-Kernel Outer MTU Recovery

The Linux-only `wireguard-stack --kernel-mtu-check` scope requires a disposable
single-UID user/network namespace. Its harness creates only a private WireGuard
interface (MTU 1500), addresses and loopback path (MTU 1400); it verifies interface
removal after either success or failure. It does not touch resolver or bus state.

The configured kernel peer owns a real TCP listener. In each inner/outer family
combination, one client connection writes 8192 synthetic bytes once and closes
sending. The existing validated local EMSGSIZE/error-queue operation reduces
outer/inner budgets while retaining its TCP socket. TCP must retry the rejected
sequence, preserve its tuple, deliver exact bytes and FIN, and receive the exact
response and EOF. The kernel reader rejects changed source tuples and excess or
incorrect bytes. Both sides have bounded deadlines; the owner cancels and joins
the worker, preserving the primary failure if cleanup also fails. Endpoint
rebinding and kernel handshake/counter readback supply independent cleanup and
traffic evidence. No same-library receiver or generated inner feedback is used.

This scope accepts no rekey option. It establishes independent-kernel local-path
recovery only, without closing remote-router discovery, general concurrent or
asymmetric path policy, physical-path validation or full PMTU acceptance.

## 23. Experimental Remote-Router Outer MTU Feedback

The Linux-only router MTU scope uses three disposable network namespaces in
one mapped user namespace: client, forwarding router and independent kernel
WireGuard peer. The ingress link is 1600 bytes and router egress is 1400.
The explicit fixture socket uses no-fragment PROBE mode (with readback) so
earlier PMTU cache entries do not turn later remote cases into local errors;
the declared transport budget continues to guard every send. All four inner/outer family
combinations first complete a real encrypted UDP exchange.

Two oversized encrypted UDP sends on distinct connected sockets must be accepted
locally and rejected by the forwarding router. Each bounded reservation retains
its error-reader lifetime token, local socket tuple, 16-byte public WireGuard
data header, encrypted length, explicit fixture router address and monotonic
deadline. Error-queue decoding retains at most the first 16 quoted
bytes plus quoted length in the returned metadata; its 2048-byte receive
buffer is transient. No application/ciphertext payload enters the reservation
or logs. The error reader attaches its checked local tuple to every decoded
report, along with an opaque token unique to that reader's lifetime. Reservation
accepts the reader itself and obtains its token, local tuple and connected
destination together. Feedback matching does not accept a separate destination.
Reduction requires the same reader token and local tuple, connected destination
and family, ICMP
origin (IPv4 type 3/code 4 or IPv6 type 2/code 0), EMSGSIZE, the expected router,
nontruncated controls, matching data header and a quote length within the sent
datagram. Quotes shorter than the data header are unsupported. This is bounded
correlation with a controlled router, not cryptographic authentication of ICMP.
A Linux synthetic loopback experiment shows that a quote ending at the UDP
header returns no UDP payload through the error queue, for either IP family.
Such a report lacks the WireGuard data header and cannot satisfy this
reservation's correlation rule. See `scripts/probe-short-icmp.py`; this does not
establish behavior on other kernels or safe correlation using other metadata.

The owner confirms an empty error queue before reservation, serializes I/O,
and waits no longer than its reservation deadline. Synthetic decoded-record
checks cover delayed reports after commit, cancellation and expiry: a different
16-byte header leaves the new reservation and budget unchanged. An identical
header is indistinguishable from a current report, even after cancellation;
uniqueness across sessions and attribution on real paths remain unproven. A
synthetic loopback error queue retains the quoted old header after a later send;
this does not establish header uniqueness. The routed kernel-peer fixture
rejects feedback from a distinct socket against the experimental owner. It
then holds a genuine report from the owner, changes and restores its peer,
and rejects the retired report both before and after a new reservation. A
modified copy with the new packet's header isolates reader generation from
header matching. A new genuine router report commits the new path budget.
Separately, the router delays ICMP feedback in transit while the owner retires
one reservation and sends a distinct later datagram. The old report reaches
the socket only after that send, cannot change the later reservation or budget,
and the subsequent report commits the reduction. This controlled delay does not
establish header uniqueness across sessions or general path attribution.
A real loopback rebinding test verifies that a new reader at the same local
tuple cannot match an old reservation. The token identifies an error-reader
instance, not a physical path: two independent readers for one socket have
separate tokens, and owners must select the reader used for the operation.
Reservation and feedback application recheck the reader's socket tuple; a
currently changed peer is rejected before mutation. The caller must still
serialize socket reconfiguration with these operations: a peer changed and
restored between checks, or concurrently after a check, is not detected. Reader
replacement, peer transitions and physical-path attribution still need a
production contract. A controlled loopback test demonstrates the blind spot:
traffic reaches a second peer, the original peer is restored, and otherwise
matching cached feedback is accepted. This is a limitation, not an acceptance
of such reconfiguration. A production adapter must exclusively own socket
reconfiguration and serialize it with send, reservation and feedback handling;
it must retire the old reader generation and invalidate its pending feedback
before publishing a changed peer, even when a previous tuple is later restored.
A separate Linux experimental owner constructs and privately owns a nonblocking
socket and its error reader. Peer replacement validates first, cancels pending
feedback and drops the old reader before constructing a replacement socket on
the same local IP and a fresh ephemeral port. The old socket stays bound until
the new reader is ready; a failure leaves feedback and sends unavailable until
explicit recovery. The socket, reader and validated path budget are published
together on success. Loopback tests cover change and return, queued old-peer
datagrams, stale feedback even with a matching header, validation refusal,
and an injected failure after the replacement socket connects. The original
error is preserved and recovery creates a new socket and reader. This experiment
retains at most eight retired sockets, bound until owner destruction, so those
local ports cannot be reused while this owner is active. An additional
transition fails with a typed capacity error before invalidating the current
reader or reservation. Failed replacement does not consume a retired slot.
For each active socket the owner also retains the highest observed WireGuard
data counter for at most eight receiver indices. A repeated or lower counter
for an observed index is rejected before sending, and a ninth index fails with
a typed capacity error. The counter is retained even when a send fails or is
partial, because delivery may be uncertain; cancellation, expiry, and feedback
commit do not free it. A successful socket replacement resets this history
only after the old socket and reader generation have been retired. This bounds
history without treating an identical quoted header as a new operation.
Reused receiver indices, out-of-order sends, and more than eight indices on
one socket therefore fail closed. The bounded experiment does not establish a
production session-retirement policy, persistence across owner destruction,
or authentication of router feedback.
The routed kernel-peer fixture now also retains a genuine router report,
rejects a repeated data header before send on the same socket, rejects that
report against a later distinct header, and commits a later genuine report.
This exercises delayed report delivery in all inner/outer IP-family
combinations; it does not establish general physical-path attribution.
Each retained kernel socket has its own bounded receive buffer. This deliberately
bounded experiment has no retirement timer and is not a production policy;
traffic delayed beyond owner destruction and ports used before this owner remain
outside the protection.
The routed probe encrypts real inner traffic with BoringTun and sends it through
the owner and completes a distinct UDP application exchange through it after
recovery, verifying the returned payload and source tuple. The owner does not
replace the existing WireGuard transport.
Concurrency, cancellation during transition, and production path selection
remain unverified. Production ownership and path policy remain open.
Larger reports never grow the budget; unsupported small paths fail before mutation. Matching alone does
not consume the reservation: budget validation/mutation precedes commit.
Expiry, cancellation and commit release retained metadata. No failed datagram
or ciphertext is replayed. The reduced budget must reject a distinct oversized
operation before send and deliver a distinct safe UDP message on the same tunnel.
The joined peer verifies exact datagram counts; the independent harness joins
namespace/peer processes and verifies veth and WireGuard interface retirement
on success or failure. Forwarding sysctls are changed only in the private
router namespace. No resolver, bus or host configuration is changed.

Section 24 adds retained TCP sizing from the same remote classification.
This does not establish general router trust, concurrent/asymmetric physical paths, roaming, short
IPv4 quote support, sub-minimum MTU policy or full PMTU acceptance.

## 24. Experimental Remote-Router Retained TCP Sizing

The routed MTU scope adds one TCP connection per inner/outer family combination
against the independent kernel peer. The peer's private WireGuard link uses
MTU 1500; routed ingress/egress remain 1600/1400. Each connection writes 8192
synthetic bytes once and closes sending. The owner encrypts and sends only its
first oversized TCP segment, reserves the public WireGuard header and waits for
a genuine matching remote report before processing any remaining output.
The initial send must succeed locally; local EMSGSIZE is not substitute evidence.

Remote classification is shared with UDP. The synchronous TCP operation
validates the report, checks all queued packet attempts and resizes the original
SocketSet/interface through the existing sizing action. Only after sizing and
outer-budget commit succeed may the reservation be released. Queue-busy,
foreign/mixed output, invalid quotes, unsupported MTU and invalid clocks leave
budgets, queued attempts and the reservation intact (except explicit expiry).
There is no await or application progress between validation and commit.

After reduction, TCP generates fresh encrypted retries from its retained send
buffer. The probe checks the rejected sequence, original tuple, exact request,
FIN and response/EOF, no inner feedback, a final ACK pumping interval and joined
peer workers. All outgoing retries must fit the new inner limit, including
WireGuard overhead/padding in the outer budget. No application write or
ciphertext is replayed by the owner. The peer verifies four TCP connections
alongside twelve UDP messages, then releases listeners; the harness
independently retires its interfaces, links and namespace processes.

The single-operation, known-router, minimum-16-byte quote, explicit PROBE mode
and interface-state/entropy restrictions remain. This is controlled routed TCP
recovery, not general concurrent/asymmetric path or production trust policy.


## Physical Path and PMTU Ownership Proposal

Status: proposed production obligations, not a completed interface or evidence
of OS route verification. A physical transport exemption and a physical path
are distinct: an exemption is useful only while the actual route and socket
egress satisfy the verified path. A service-owned path generation must bind the
endpoint, address family, source address, egress interface identity and route
selection evidence. A socket and its error reader belong to exactly one such
generation; neither a socket tuple nor an ICMP reporter alone proves the path.
The platform driver must establish and revalidate that evidence without routing
the endpoint through the capture interface. Interface removal, route changes,
source-address changes, notification loss, ambiguous lookup, and uncertain
reconfiguration invalidate
the generation. Until verification succeeds, new sends and feedback mutations
on that path fail closed; no direct or alternate-backend fallback is allowed.

An owner serializes sends, reservations, feedback, and path transitions for
each generation. Validate prospective endpoint, source, family and MTU before
retiring the current generation. On invalidation, stop new sends, revoke
pending feedback, retain active-flow ownership, and publish a replacement only
after its socket and exemption are verified. Failure after retirement leaves
the path unavailable until recovery; it must not restore an unverified path or
replay an application payload. Keep retired resources bounded and fail closed
when safe retirement cannot be established. Handle shutdown and cancellation
as explicit transitions, with the supervisor joining owners and reporting
cleanup errors alongside the initial failure.

Each simultaneous path has independently bounded reservation, error-reader,
counter and MTU state. Reports must match the live generation and outstanding
operation before any mutation. A short, truncated, ambiguous, untrusted or
otherwise uncorrelated report does not reduce an MTU or retire an operation.
ICMP reporter selection is a path policy input, not cryptographic proof of a
router. Limit each reservation's lifetime and avoid retaining ciphertext or
application payload. Unknown delivery is never retried at the application
layer; TCP retransmission remains the TCP stack's responsibility.

Outer MTU reductions must account for the actual outer family, UDP, WireGuard
overhead and padding. Before committing an interface-wide inner reduction,
the owner must prove that every retained flow and queued packet sharing that
interface can be preserved or safely retired; an unresolved shared-interface
conflict leaves the budgets and reservation unchanged and returns a typed
failure. UDP datagrams must retain boundaries; unsupported sizes fail without
fragmenting or silently falling back. A report cannot increase an MTU. A new
path generation must not inherit the old generation's discovered PMTU without
independent verification.

The present `outer_owner` fixture provides exclusive socket ownership and
bounded single-operation correlation, not the platform driver or this complete
state machine. Interleaved loopback owner tests demonstrate independent
reservation and failure isolation. An isolated routed test sends distinct
encrypted datagrams with two outstanding reservations over separate source-bound
veth links to the same router. Each owner rejects the other's genuine ICMP
report and commits only its own reduction, in all four inner/outer family
combinations. The links share a router and egress; this does not prove physical
path verification or concurrent stack resizing. A harness-owned interruption of
the second veth with both reservations outstanding is acknowledged before the
probe receives a Linux link notification and invalidates its owner, revoking
its reservation and preventing further sends. The first owner commits its report
while the link is down; after restoration the second replaces its socket and
commits feedback for a distinct send. The fixture covers all family combinations
and independently cleans up. It does not establish automatic invalidation or
safe behavior before notification processing. The experimental invalidation is
idempotent and rejects sends, feedback, and reads until socket replacement;
failed replacement remains unavailable. The bounded Linux link listener uses
a nonblocking netlink socket, validates the kernel sender and message bounds,
and invalidates on change or uncertainty, including overrun and truncation.
Each poll drains unrelated notifications before reporting an empty queue, with a
64-datagram work bound that fails closed on saturation.
It watches one interface index and is explicitly polled only in this fixture;
it does not prove a verified physical path or provide a continuous production
event loop. A second bounded subscription watches IPv4/IPv6 route and policy
rule notifications and conservatively invalidates both fixture owners on any
such event or uncertainty. The harness removes one source-specific default route while both
reservations are pending, then restores it; both owners reject sends until
socket replacement and each subsequently commits feedback for a distinct
operation. A separate exchange removes and restores the source-specific policy
rule with the same invalidation and recovery in both outer IP families. Another
exchange uses a separate address-only subscription to observe removal of the source
address and conservatively invalidates both owners before recovery. This does
not attribute an event to one path or establish a race-free production route
snapshot and notification protocol.
The isolated harness checks source-bound kernel route lookups for both fixture
paths before traffic and before acknowledging each restoration. Failure prevents
the experimental replacement socket from proceeding. A subscription established
before the lookups rejects queued changes or notification errors after the
queries. A controlled private-namespace route change between queries produces
a real notification and rejects the snapshot. This does not establish general
notification ordering or cover the interval after the check. The lookup verifies destination, source,
gateway, interface, and an unambiguous unicast result, but does not include
socket marks, verify exemptions, or close the snapshot/notification race.
During link, route, rule, and address recovery, the experimental owner verifies
the candidate socket's actual addresses and UDP ports before publication.
Verification failure leaves the owner unavailable and releases the candidate.
Initial owners in the two-path and recovery scenarios also require this check;
other fixture sockets, real socket routing and production integration remain
unverified. In route/rule and address scenarios, each experimental owner retains
link, route/rule, and address subscriptions opened before candidate verification. The
link interruption scenario guards its affected owner; the comparison owner is
unmonitored. Each guarded owner checks its subscriptions before sends, reads
and feedback, invalidating on a queued change or receive error; replacement of
an attached monitor is rejected. For the second owner in route/rule and address scenarios, a retained worker
also observes changes while idle and wakes a supervisor, which refreshes the
owner; the worker is joined on success and failure. Other fixture owners are
not idle-supervised. Observation and invalidation remain separate, and this
does not close the race between a poll and the subsequent operation. Required further evidence includes
actual route/exemption verification and change detection, concurrent and
asymmetric paths, shared-interface TCP/UDP behavior, delayed feedback across
generation retirement, cancellation and recovery, and native platform cases.
The production API, limits and OS mechanisms remain pending that evidence;
this proposal does not close the Phase 0 or MTU gates.

## 25. Experimental Kernel Peer Link Transition

A separate Linux-only probe starts an established userspace WireGuard session
against the independently configured kernel WireGuard peer. The disposable
namespace helper creates and owns that peer interface and independently deletes
it, even if the probe fails. The probe uses bounded commands and reads back the
interface flags before treating each down/up transition as complete.

While the kernel peer interface is down for at least 1200 ms, the client admits
one TCP write and FIN plus one distinct UDP datagram and verifies that both
are emitted. After the interface is brought up, the fixture explicitly restores
its IPv6 address if the kernel removed it and checks the peer port. Recovery
requires a new handshake completed after link-down, the exact TCP response and
EOF, and a distinct heartbeat sent once after TCP recovery. Joined peer workers
verify one TCP and two UDP messages; the down-time UDP payload is not replayed.
The original error is retained if worker or socket cleanup also fails.

The kernel peer interface, not the client's physical path or host TUN, is the
link under test. Restoring its fixture-owned IPv6 address is explicit setup,
not evidence of automatic platform recovery. This does not establish service
outage detection, production route or address repair, inbound link loss on a
separate physical path, or native macOS behavior.


## 26. Experimental Private Outer Path Interruption

A separate Linux fixture uses distinct client, router, and kernel WireGuard
peer network namespaces. A private tmpfs control directory coordinates the
probe and its independent supervisor. Once the TCP connection and a warmup
UDP exchange are established, the supervisor lowers its own router egress veth
and reads back its administrative state. The client admits one TCP write with
FIN and one distinct UDP datagram, observes both emitted while the path is down,
and waits at least 1200 ms before requesting restoration. The supervisor raises
the veth, restores its fixture-owned IPv6 address and verifies both states.

Only explicitly classified OS network errors can be tolerated during the
bounded recovery period; their count is bounded and reported. The client never
replays the lost UDP datagram or application TCP bytes. After exact TCP response
and EOF, it sends a distinct heartbeat. The independent kernel peer checks the
exact TCP and UDP workload, joins workers, and releases listeners. The helper
separately removes and verifies both veth links, reaps namespace processes, and
unmounts its private control state, preserving primary failure status. The
control directory is validated for naming, ownership, mode, canonical path and
a tmpfs mount; markers are created exclusively.

This covers all inner/outer IPv4 and IPv6 family combinations on private virtual
links. It does not establish behavior for a physical NIC,
production route repair, host TUN interception, macOS, or concurrent network
changes. An actual OS network error was not observed in the passing runs.
