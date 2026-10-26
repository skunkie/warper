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
  independent-peer rekey runs have 180 seconds. Worker deadlines add ten
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
time is `InvalidTime`. Default setup/idle/absolute-age budgets are 10, 300,
and 86400 seconds, respectively. Limits are injectable for timer tests;
invalid/unrepresentable limits fail construction. Expiry at the deadline
aborts the socket and drops driver state, while consumer-held buffers
remain charged. No application task is needed for timer-only tests.

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
refresh idle time; rejected input does not. Absolute age never renews. Expiry
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
Malformed/unexpected outer traffic also follows the existing probe's fatal
error policy; resilience to hostile datagrams and production congestion
backpressure require separate decisions. Full-queue tests observe 64 actual
encrypted datagrams at the peer socket, not 64 application deliveries through
its smaller UDP ring. Kernel-peer interoperability/rekey and same-library
outage scopes remain separate evidence.

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
raw-stack features. PMTU and the remaining fragmentation strategy must be
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
ciphertexts are suppressed. After at least two encrypted packets are dropped,
it restores transport and sends a separate recovery heartbeat. TCP retransmits
through the stack; the application never resubmits request bytes or lost UDP.
Completion requires the exact response after FIN and the recovery heartbeat.

The default Linux kernel-peer run applies this workload in both inner families.
Its retained workers validate the exact TCP request and reject the lost UDP
payload if it appears. Exactly five UDP messages are expected: the four original
messages and one recovery heartbeat. Automatic sustained heartbeats are disabled
for this bounded case. The existing 10-second workload deadline includes
handshake retries and TCP recovery; workers are stopped and joined on every
result. The separate sustained rekey workload retains its periodic heartbeats.
This establishes controlled outbound loss recovery against an independent peer,
not full network outage detection, service crash recovery, or roaming.
