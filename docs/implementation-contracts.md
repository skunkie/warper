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
  returns `io::ErrorKind::OutOfMemory` for packets over 1280 bytes or a full
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
