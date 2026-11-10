<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Post-Feasibility Implementation Contracts

Status: initial Linux slice contract selected after Phase 0. Section 6 locks
its backend-neutral TCP, route-driver and task ownership boundaries against
compile-checked usage. Sections 7 onward retain detailed experimental evidence;
features outside the initial fixed-CIDR slice remain proposals until their
own production contract and acceptance gates pass. No macOS or production
DNS gate is claimed here.

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

## 6. Initial Slice Contract

[ADR 0002](adr/0002-network-stack.md) selects direct smoltcp 0.14.0 and
BoringTun 0.7.1 with the root manifest's exact features. The next production
slice uses a fixed 1280-byte host MTU, static CIDRs, SOCKS5 TCP and no system
DNS mutation. The concrete interfaces below are compiled in
[`initial-contract`](../experiments/initial-contract/src/lib.rs), with real
accepted-stream usage in the host experiment. Promote the applicable types
into core/service modules when the slice needs them; production packages must
never import an experiment or expose smoltcp/BoringTun types.

| Boundary | Concrete source and usage |
| --- | --- |
| Static policy | [`routing.rs`](../crates/warper-core/src/routing.rs): `Policy::new(&[Entry], limit) -> Result<Policy, Error>` validates canonical IPv4/IPv6 prefixes, rejects duplicate/conflicting assignments and bounds construction. `select(IpAddr) -> Option<BackendId>` performs deterministic longest-prefix selection without allocation or transport fallback. The caller retains the result for each flow. |
| Offline source paths | [`paths.rs`](../crates/warper-core/src/configuration/paths.rs): `IdentityProvider` supplies effective UID and trusted OS account records; `invoking_account` validates sudo UID/name consistency only for root callers. `Paths::new` and native-byte-preserving `with_config_path` own the invoking home/source path; `resolve_value` resolves YAML paths against its lexical directory. Transformations have typed redacted errors and no environment mutation, file reads, network I/O or service authority. Both parser and offline CLI use them. |
| Unix account lookup | [`identity.rs`](../crates/warper-config/src/identity.rs): `UnixIdentity` implements `IdentityProvider` using the existing pinned nix dependency's effective UID and reentrant account lookup. It copies only UID/name/home, discards other account fields, and maps missing accounts and OS lookup errors to redacted `IdentityLookup`. It reads OS account records without reading credential/trust files or using environment paths. This synchronous call may block in NSS/directory services and has no cancellation/deadline guarantee; future ordinary-user clients must isolate it on a blocking worker with bounded admission and track unfinished calls after timeout. Native Linux lookup has an executable probe; native macOS remains unverified. |
| YAML decoding | [`yaml.rs`](../crates/warper-config/src/yaml.rs): `decode(&[u8]) -> Result<Value, Error>` admits at most 1 MiB before UTF-8/parser allocation, with 65,536 key/value nodes and depth 16. The owned tree preserves scalar types/spelling and sequence order; duplicate keys, nulls, anchors/aliases, unsupported/mismatched tags and multiple documents fail with typed redacted category/reason/path. Scanner types/errors remain private; Value Debug is redacted. Synchronous decoding releases partial state on error and creates no tasks/I/O; source bounds are not an RSS cap or execution deadline. Schema/semantic checks remain required before any import/network operation. See ADR 0006. |
| Source and CLI | [`source.rs`](../crates/warper-config/src/source.rs) opens with `O_NONBLOCK`, checks the descriptor is regular and bounds metadata/read size. It returns typed redacted errors and follows source symlinks; it is not a credential-file reader. [`warper-cli`](../crates/warper-cli/src/lib.rs) separates arguments, injected `Environment`/`SourceReader`, execution and stream writes. Only check-config resolves identity/paths and reads a source; help/version and unsupported service commands perform no environment/file/IPC access. Success reports offline validity, never engine startup. stdout failures return typed I/O kinds; `Failure` retains primary and stderr failures. Account/file I/O is synchronous without a hard deadline; no background task or host mutation is introduced. |
| Linux control peer | [`warper-control`](../crates/warper-control/src/lib.rs): `OwnerPolicy::new(Option<u32>)` validates policy data but does not load/store/enroll it. Its internal evaluator permits owner observation/operation and UID-0 administration; external consumers must use native authentication. Credential fields have no public constructor/deserializer; Debug is redacted. [`unix.rs`](../crates/warper-control/src/unix.rs) admits the initial user namespace before socket type/family/connection and SO_PEERCRED checks. Both authentication directions borrow caller-owned streams, perform no payload I/O/retries/tasks, retain socket error kinds and do not close on denial. [`namespace.rs`](../crates/warper-control/src/namespace.rs) uses fixed verified procfs and openat2 traversal guards, a pinned symlink and a 64-byte readlink buffer; missing/malformed/submounted/noninitial evidence fails closed (ADR 0008). No caller anchors, environment override or cache is accepted. Native integration must prohibit user-namespace transitions between authorization and operation. Snapshots prove neither liveness/code identity nor a protected endpoint. Recheck current owner policy per request; revocation is a later gate. macOS returns UnsupportedIntegration; endpoint/enrollment/framing adapters are separate boundaries, while authenticated sessions and service operations remain open. |
| Linux runtime ownership | [`runtime.rs`](../crates/warper-control/src/runtime.rs): `RuntimeLease::acquire() -> Result<Self, Error>` admits initial-user-namespace effective UID 0 and fixed `/run/warper/service.lock`. It pins and verifies root-owned directories, rejects symlinks/submounts beneath `/run`, and creates exclusively or inspects/reopens an empty regular root-owned mode-0600 single-link lock without truncation. Exclusive nonblocking flock precedes final identity validation. `revalidate()` checks namespace, effective UID, metadata and named identities before later mutations. Four owned descriptors, no public constructor/path override/raw FD, redacted Debug/typed errors, no tasks/retries/payload I/O. Drop releases descriptors without unlinking persistent state. Synchronous filesystem operations have no hard deadline; root and a stable launch namespace remain trusted. Private UID fixtures establish contention, changed-state rejection and child SIGKILL recovery; actual public root acquisition has privileged CI evidence; runtime submount rejection remains unverified. Endpoint/enrollment adapters use this lease separately; journal and integrated network-instance ownership remain open (ADR 0009). |
| Linux control endpoint | [`runtime/endpoint.rs`](../crates/warper-control/src/runtime/endpoint.rs): `ControlEndpoint::bind(RuntimeLease) -> Result<Self, Failure>` consumes the lease, syncs exclusive fixed intent before binding, pins the socket pathname inode and sets mode 0666 before listening. `accept(&OwnerPolicy) -> Result<Option<Accepted>, Error>` is nonblocking and returns only authenticated Observe peers; per-request authorization and current enrollment remain required. Backlog is 32, caller owns returned streams, no tasks/readers/queues are created. `close(self)` closes admission and retires only unchanged pinned objects under the lease; Drop leaves uncertain state. `Failure` preserves primary and cleanup errors. Four lease FDs plus intent, socket pathname and listener FDs are retained; directory sync uses a temporary FD. No cwd/umask mutation, stale deletion, listener path override or network mutation. Root/launch mount namespace and procfs FD lookup are trusted, filesystem waits have no hard deadline. Controlled current-UID fixtures prove normal retirement, foreign denial, crash-stale conflicts and changed-state preservation; actual root publication/retirement has privileged CI evidence; syscall-fault injection remains unverified. |
| Linux client endpoint | [`runtime/client.rs`](../crates/warper-control/src/runtime/client.rs): `connect(Instant, watch::Receiver<bool>)` admits the initial user namespace, verifies fixed root-owned `/`, `/run`, mode-0755 `/run/warper` and a mode-0666, single-link socket, and pins four descriptors. It connects through the socket's procfs descriptor path, authenticates a connected real root peer, then rechecks metadata/name identities before exposing the Tokio stream. No payload, arbitrary path/UID, repair, retries or task spawn. One absolute async deadline and cancellation on owner loss; synchronous metadata/procfs inspection has no hard wall bound. Caller negotiates the wire version before configuration transfer. Private current-UID fixtures test real pinned-inode connection, root-peer rejection and changed-state preservation; public root-service success is a privileged CI gate. |
| Linux owner enrollment | [`runtime/enrollment.rs`](../crates/warper-control/src/runtime/enrollment.rs): `OwnerStore::open(&RuntimeLease)` admits effective UID 0 and pins fixed root-owned `/var/lib/warper`. `read` revalidates the lease/state, refuses pending intent and reads at most 25 bytes from a verified regular file into the exact versioned 24-byte snapshot. `enroll(&mut self, &RuntimeLease, &UnixStream, expected_revision, owner)` authenticates a live administrative peer before reading records, then exclusively stages/syncs a revision and its directory, rechecks the prior snapshot identity/revision, renames atomically and syncs again. Pre-publication cleanup touches only unchanged owned pending state; `Failure` retains primary/cleanup causes. Post-rename sync failure is CommitUncertain, never rollback/replay. Four state directory FDs plus bounded temporary record/pending handles, no tasks/retries or generic paths; synchronous filesystem waits have no hard deadline. Debug/errors are redacted. Current-UID private fixtures prove real storage transitions and injected post-rename uncertainty; positive public root enrollment has privileged CI evidence. Administrative `inspect_pending` pins a bounded partial/complete pending file and committed snapshot; consuming `discard_pending` freshly authenticates root and compares store/owner/pending identities, timestamps and bytes before unlink/sync. It never promotes a pending owner or changes the committed revision; mismatches preserve state, final sync failure is CommitUncertain. Each inspection retains at most two file pins and 25 payload bytes; the service must bound retained inspections and serialize mutations. Current-UID tests cover partial writes, changed snapshots, unsafe metadata, denial, lease loss and uncertain sync; positive root recovery CI now passes; live connection revocation and service integration remain open. |
| Linux connection intent | [`runtime/connection.rs`](../crates/warper-control/src/runtime/connection.rs): `ConnectionStore::open(&RuntimeLease)` requires actual root and fixed protected `/var/lib/warper`, reusing the private directory pins with enrollment. Native bounded verified-procfs BootId and nonblocking 16-byte instance entropy have no overrides/fallback. `Request::from_frame` decodes validated v2 lifecycle fields. `accept(lease, current_approved_generation, request)` verifies independent generation/instance/revision fences, binds the operation ID's revision prefix and nonzero nonce to its original expected revision, returns AlreadyAccepted for the unchanged last operation, then exclusively stages/syncs an exact 80-byte snapshot and directory, rechecks prior identity/content, renames and syncs before Accepted. No network action or RPC authorization is implied. Changed/deleted observed snapshots fail closed; CommitUncertain blocks acceptance until explicit unchanged inspect/resync. Opaque bounded pending inspection/discard never promotes staged intent and preserves changed state; unlink uncertainty requires resync. Four directory FDs, bounded transient file pins/buffers, one fixed observed snapshot and no tasks/retries; synchronous kernel waits have no hard deadline. The service must serialize operations, authorize each command, bound inspection retention and apply boot/recovery/readiness barriers. Public root persistence passes owner-dispatched CI at `ed834b5`; authenticated daemon integration remains open. |
| Control framing | [`wire.rs`](../crates/warper-control/src/wire.rs): private-field `Frame::new(Kind, nonzero_request_id, Vec<u8>)` validates version-2 kind-specific length/body rules; redacted Debug. Connect/Disconnect carry 48-byte operation/configuration/desired-revision/instance fences, StatusReply carries 26 bytes, and legacy layouts/versions fail before body reads. Expected instance IDs and operation IDs must be nonzero; durable comparison/acceptance belongs to service handlers. Async `Frame::read/write` borrow I/O and an injected watch cancellation receiver plus one absolute Tokio deadline covering header/body/flush. Magic/version/kind/length/ID validation precedes body allocation; maximum is 1 MiB plus eight generation bytes, fixed commands are exact-sized. Limited read/write variants enforce the configured encoded-message budget before body allocation/any output, counting header and generation metadata. No generic paths/shell commands exist. A framing error poisons the stream; partial output is never replayed. No tasks/queues/retries are spawned. Callers own connection admission/global buffer accounting, peer authentication, Hello session order, reply correlation, current per-request authorization and operation idempotency. Controlled duplex probes cover all kinds, maximum-size/partial I/O, rejection before body reads, cancellation/closed channel/EOF and total deadlines. Service handlers remain open. |
| Offline schema | [`schema/mod.rs`](../crates/warper-config/src/schema/mod.rs): `Config::parse(&[u8], &Paths, Platform) -> Result<Config, Error>` constructs owned typed tunnel/backend/timeout/limit settings, resolves credential paths without opening files, rejects unknown/mistyped/conflicting values, normalizes IDNA and enforces global ID/domain/CIDR uniqueness. Secret-bearing Debug is redacted, including usernames/source paths. `static_policy` checks route-count admission before cloning entries into the existing core policy. `BackendSettings::requirements` describes required protocol behavior, never current adapter availability. Parsing is synchronous with no tasks, external mutation or host discovery; allocation/CPU remain bounded by admitted source plus normalized-model/library overhead, not a hard deadline/RSS guarantee. Returned editable records are not authorization tokens; validation and runtime preflight remain required before installation or networking. |
| Production TCP and physical connector | [`warper-core::transport`](../crates/warper-core/src/transport.rs) promotes the proven Metadata/CapturedTcp/boxed TcpIo, Capabilities, Backend and deadline/cancellation Request boundaries. EndpointConnector is service-constructed; implementations must protect the selected physical endpoint and cannot detach I/O or fall back. Request cancels on owner loss, has one total setup deadline and drops owned futures on failure. Errors are typed/redacted, retaining I/O kind and generic rejection category. No backend/stack implementation is imported by core. Service path protection and platform adapters remain open. |
| SOCKS5 TCP | [`socks5.rs`](../crates/warper-backends/src/socks5.rs): `Socks5::new(BackendId, SocketAddr, Option<Credentials>, max_streams, Arc<dyn EndpointConnector>)` validates credentials/endpoint/semaphore range. Backend open_tcp reserves one permit without queueing, connects only through the supplied connector, performs exact configured authentication and numeric CONNECT under the original Request deadline, and consumes the complete bound address. Permit survives half-close until boxed stream drop. No UDP, destination DNS, retries, direct connector or detached tasks. Setup buffers are bounded (auth 513, request 22, reply 257 bytes plus credentials/allocator/OS overhead); data relay/idle/age budgets are service-owned. Real controlled peers and loopback workload evidence are described in ADR 0011; physical/TUN integration remains open. |
| Captured TCP | [`transport.rs`](../experiments/initial-contract/src/transport.rs): `Metadata { id: u64, source: SocketAddr, destination: SocketAddr, backend: BackendId }`; `CapturedTcp { metadata, stream: Box<dyn TcpIo> }`; `TcpIo: AsyncRead + AsyncWrite + Unpin + Send`. `AcceptedFlow::into_contract` is used by the controlled packet and Linux TUN relays. |
| Backend TCP | `Backend: Send + Sync`, `id`, `capabilities`, `open_tcp(&self, SocketAddr, Request) -> OpenTcp<'_>`; the boxed future and stream are `Send`. `Capabilities` advertises IPv4/IPv6/TCP/UDP independently. The TUN fixture's `ControlledBackend` opens distinct real loopback peers through this interface; it is not a production protocol backend. |
| Setup ownership | `Request { deadline: tokio::time::Instant, cancellation: watch::Receiver<bool> }`; `Request::run` bounds the complete setup operation. Cancellation or loss of its owner drops the owned future/I/O. `Error` distinguishes unsupported capability, cancellation, timeout, resource limit and I/O, retaining the I/O cause with redacted Display. |
| Route driver | [`routes.rs`](../experiments/initial-contract/src/routes.rs): `Transaction::new(OperationId, Route) -> Result<Self, Error>` validates a canonical IPv4/IPv6 prefix. `Driver::execute(operation, route, command) -> impl Future<Output = Ack> + Send`; `inspect` returns `Observed::{Absent, Owned, Foreign}`. The operation owner retains the transaction through timeout/cancellation. |
| Route progress | `advance_driver(&mut self, &mut impl Driver, Instant)` executes one serial command under a deadline. Install/remove timeout produces uncertainty and inspection, never a positive answer. `complete` rejects wrong operation/command acknowledgements. `can_release_answer` requires committed ownership and a live caller. |
| Flow retention | `acquire_flow` admits references after mapping publication and before retirement; cancellation closes admission. `release_flow` enables removal only after the last reference. Kernel removal is acknowledged before mapping withdrawal. A driver must compare full ownership/interface identity at removal, even following inspection. |
| Supervision | [`supervisor.rs`](../experiments/initial-contract/src/supervisor.rs): `Supervisor::new(1..=64)`, `spawn`, `next_failure`, `shutdown(Instant, Option<Error>)`. Tasks are retained, cancellation is broadcast, stalled cooperative tasks are aborted and joined, and `Failure { primary, cleanup }` preserves both causes. Packet/service tasks must never block the executor. |

`BackendId` now lives in [`warper-core`](../crates/warper-core/src/lib.rs);
the experiments reuse that backend-independent identity. Static policy is the
first Phase 1 increment. A policy snapshot does not mutate routes or implement
configuration parsing, DNS discovery or backend health selection.

Backend IDs are registry identities within a configuration generation;
persistence/control must carry that generation and the stable configured ID.
Flow and operation IDs must not be reused within their owner's lifetime.
Limits for the production parser, registry, control messages, journal and
platform driver must be concrete before those modules depend on them.
These are Phase 1 implementation gates, not permission to introduce implicit
fallbacks, unbounded adapters, or arbitrary privileged file/shell APIs.

The accepted stream owns its lifetime permit until both application and driver
release it. TCP shutdown closes sending while reads continue; the relay uses
`copy_bidirectional` and never resubmits possibly delivered application data.
The supervisor owns the TUN runner, backend workers and control worker; flow
tasks own their setup/relay cancellation. The route manager serializes journal
and driver commands without holding application locks over network I/O.
The Linux driver must make journaling durable before installation and verify
actual kernel acknowledgements; `Driver` is not itself that implementation.
A lost caller wait is distinct from cancelling a service operation.

### Contract failure evidence and later-phase boundaries

`cargo test --locked -p initial-contract` exercises a working in-memory,
fault-injecting driver: its install mutates state and then withholds the ACK.
Controlled time expires, inspection observes the owned route, and rollback
removes it before withdrawing the handler. Additional cases cover rejected
operations, delayed commit, wrong acknowledgements, cancellation at every
ACK boundary, partial rollback, foreign state and admitted flow references.
Task tests verify cancellation, deadline abort, joined resource destruction,
worker failure propagation and preservation of the initial error.

[`dns.rs`](../experiments/initial-contract/src/dns.rs) supplies **contract
models**, not finalized production DNS interfaces. `Ledger<N>` reserves an
entire endpoint set, coalesces same-key renewals, and separates pending output,
grace, flow ownership and optional positive/negative caches. Its fixed-size
names/provenance, bounded request/index arrays and full per-record allocation
charges make entry and logical-byte exhaustion independently testable. There
is no growing expiry heap. Allocator bookkeeping and externally held tokens
are additional costs, explicitly outside this model's logical retained-byte
budget. Production accounting must add and document them.

NET-10 model cases keep queued/partial output pending across expiry, preserve
zero cache TTL, anchor grace at handoff, retain active flows, reject foreign
handles and cancel without renewing. NET-11's endpoint publication model waits
for every required route's commit and rejects a target whose winning domain
policy selects another backend. NET-12 model cases exhaust entry/byte budgets
for distinct names sharing one IP, roll back partial/concurrent reservations,
coalesce repeated renewals without timer growth, reclaim expired state, and
separate cache eviction from protected ownership.

The eventual DNS manager must serialize `validate_endpoints` and handoff with
route retirement; these separate model operations are not an atomic production
API. The model consumes a prevalidated complete endpoint set and does not
parse DNS, resolve CNAME/SVCB dependencies, perform transport retries, or prove
physical captures. Production NET-10–NET-12 acceptance and complete retained
allocation accounting remain Phase 2 requirements. UX-05 remains a native
macOS gate. This contract evidence does not substitute for any of them.

### Experimental API detail

The following historical prototype details explain the evidence and rejected
alternatives. Only the role selection and initial slice boundaries above are
accepted for dependent work. Physical egress/PMTU proposals below require
extension before production use; fixed seeds and synthetic inputs are fixtures.

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
HostAdapter::with_mtu(Limits, fn(SocketAddr) -> Option<BackendId>, usize)
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

The default MTU remains 1280 bytes. The experimental `with_mtu` constructor
accepts 1280–1500 and returns `InvalidMtu` outside that range; ingress is bounded
by the current device MTU. Oversized ingress returns `PacketTooLarge { mtu }`,
separate from resource exhaustion; it does not itself emit ICMP or retry data.
A test-only response candidate may construct one bounded too-big response only
for an exact-length, checksum-valid data packet owned by an already accepted
flow. It rejects multicast, unspecified and limited-broadcast addresses,
fragmented IPv4, IPv4 without DF, unsupported headers, and unmatched flows
before construction. A test-only candidate uses a separate 64-entry feedback
queue and a 64-entry lease index with a one-second per-flow cooldown; a full
queue, retained-handle limit, or cooldown rejection does not change the queue or
cooldown. Each response is at most 1280 bytes; allocation and index bookkeeping
are additional. The candidate does not verify that the TCP stack would accept
the segment sequence. The lease index retains flow ownership for queued or
handed-off responses, suppresses queued responses
after retirement, and blocks tuple reuse until handed-off handles are released.
A test-only bounded channel candidate reserves output capacity before removing
feedback from the queue. Busy or closed output leaves the queued handle intact;
a received handle retains its flow lease until released. A controlled local
Unix datagram handoff verifies exact packet boundaries while the handle remains
live. This does not establish a TUN write or network-stack acknowledgement. Directed-broadcast classification, kernel
delivery acknowledgement, cross-instance lifetime, runtime integration,
production rate policy, and sender adaptation remain unresolved.
This is a TCP-only probe interface, not YAML or CLI configuration or a dynamic
PMTU implementation. The UDP candidate and production
runtime remain separately constrained. Library IP/TCP parsers validate lengths,
checksums, ports, and supported headers before admission. The
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
channel capacity is 1–64 per direction; the probe uses 64. The default queued packet
limit is 1280 bytes; `with_pmtu` can declare a TCP link limit through 1500,
independently of reduced egress sizing and UDP/reassembly limits. Constructor errors preserve TCP/UDP validation variants.
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
with `Failure { cause, report: Box<Report>, pmtu }`. PMTU seed/rebuild failures
retain their typed underlying I/O source in `pmtu`. The internal shutdown owner is the experiment
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

Status: raw fixed-envelope checks and bounded pre-admission fragment input.
`host-stack --raw-mtu-check` still fails for the unadapted stack. Section 27
adds actual runtime downward PMTU handling and genuine routed TUN evidence;
`--mtu-check` and `--tun-pmtu-check` are required passing adapter gates.
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
distinct UDP datagram is delivered once in each IP family. When queued packets
make replacement busy, the fixture verifies that the packet queue, both TCP
send queues, original MTU, and reservation survive for a controlled retry. This
does not establish general path attribution or exercise the production runtime.
A separate controlled accepted-stream adapter test directly rebuilds the
interface while two flows on distinct backends retain pending application data.
It checks their identities, exact delivery, FIN and permit release in both IP
families. With output queued for both flows, a busy rebuild preserves the queue,
TCP send state, MTU and flow ownership before delivery and retry. Feedback
correlation and UDP are outside that test. The test uses the experimental TCP
adapter MTU constructor; it does not establish a production MTU configuration.
PMTU and the remaining fragmentation strategy must be resolved before the
MTU/ICMP gate or stack ADR can be accepted. ICMP
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

## Controlled TUN Backend Dispatch

The Linux TUN fixture creates two separate loopback TCP listeners in its
disposable network namespace. Accepted flows retain their selected backend ID
and are relayed to the corresponding listener; each peer checks a distinct
synthetic payload, echoes it, and responds after FIN. Listener and relay tasks
are owned and joined by the fixture. The listeners are controlled feasibility
peers, not SSH or SOCKS implementations, and UDP remains a separate synthetic
association handler. A successful fixture does not complete NET-01 or the
production backend contract.

## Experimental Encrypted Outer Fragmentation

A Linux-only private-loopback fixture uses two BoringTun peers with a declared
1500-byte experimental envelope over a verified 1280-byte loopback path.
Socket PMTU discovery is explicitly disabled only for this fixture. The peers
exchange TCP and UDP traffic, including maximum supported and empty UDP
payloads, across all inner/outer IP-family combinations. A bounded raw packet
capture observes fragmented WireGuard data for both outer families. With
fragmentation disabled, the corresponding negative controls require a kernel
size error. Fixture sockets are released and loopback state is restored.

The same capture now observes fragmented WireGuard data in both directions
for each outer family while an independent Linux kernel peer completes all
inner/outer family combinations. Its workers are joined, fixture sockets are
released, and the parent independently removes the kernel interface.

A separate private-loopback loss fixture drops the final outer fragment with
owned traffic-control filters, then removes the filters. Its independent kernel
peer verifies one application TCP write completes via stack retransmission,
while one lost UDP datagram is not replayed and a later heartbeat succeeds.
Filter drop counters, worker joins, socket release and independent network
cleanup are required observations. This controlled fixture does not establish
loss recovery across a router or production flow ownership.

Both fixtures deliberately mismatch the declared envelope and path MTU to test
kernel fragmentation; they do not relax the existing path-budget guard. Private
loopback does not establish routed or physical behavior, fragment-loss recovery,
resource limits under hostile traffic, native macOS behavior, or a production
fragmentation policy.

## 17. Experimental Interface MTU Reduction

Status: a sizing-control feasibility probe, not complete PMTU discovery.
The pinned stack stores device capabilities in `Interface`; updating a device
alone does not refresh the cached TCP sizing context. A raw-IP experiment
therefore replaces only `Interface` after reducing an empty device's MTU,
retaining the original `SocketSet`, socket handles, endpoints, TCP buffers,
sequence/acknowledgement state, and timers. It copies interface addresses,
routes and any-IP policy and uses the current controlled monotonic time.
Selected features have no neighbor, SLAAC, multicast or fragmentation state
to transfer. A fixed-seed fixture demonstrates the sequence-reset risk. A negative
control shows that two replacement interfaces emit the same initial TCP
sequence for the same new connection in both families. The sequence is
observable on the wire; no production uniqueness or security claim follows.
The experimental replacement and matched-feedback operations require a
caller-prepared `u64` seed, allowing the owner to obtain it before entering
the synchronous rebuild. Some fixture callers explicitly provide a fixed seed
and cannot supply production entropy. A Linux-only experiment obtains one
seed using `getrandom` with `GRND_NONBLOCK`: errors or a short read fail before
interface mutation or reservation consumption, with no retry or fallback.
Seed-source errors use a distinct typed `SeedError` that retains the underlying
I/O cause; a busy device queue continues to return its own I/O error.
Feedback validation may advance the tracker clock before the seed request.
The controlled host and WireGuard feedback probes use this source on Linux.
The experimental WireGuard owner retains at most one matched response, bounded
to 1280 bytes, if seed acquisition or device queue readiness returns
`WouldBlock`. It retries no more often than every 10 ms while the original
reservation remains valid; duplicate matching feedback does not replace the
retained response. A pending response blocks replacement of its reservation
even if that reservation has already retired. Retry occurs only when the
experimental pump is called;
there is no independent timer wakeup. Expiry and other errors remain visible
to the owner, and shutdown drops the retained response. The reservation is admitted only for a packet present in the experimental
`Peer` output queue and binds a weak identity for that peer; attempts to pump,
apply or retry against a different peer are rejected before state mutation. This does reject a missing, closed, listening, or unestablished TCP socket before
reservation or feedback work. The emitted packet's TCP endpoints must match
the socket at reservation, and later operations verify the same endpoints.
The experimental peer rotates a TCP connection identity when its poller
observes a new established lifecycle, so a later polled connection reusing the
same slot and tuple cannot consume the earlier feedback. Direct socket-set
replacement or state changes outside that poller are not covered. Each peer
owns one current identity allocation; its single reservation holds a weak
reference to the earlier identity until replacement or owner destruction.
This is a controlled driver policy,
not production supervision. The experimental transport owns an injectable,
nonblocking seed source; a controlled encrypted-peer test forces one transient
source failure and verifies that the same TCP transfer completes after retry.
Other fixtures retain fixed seeds; macOS acquisition, integration and the
production failure and state-transfer policy remain unproven. Reduction is
interface-wide and also lowers the device receive limit; multiple flows and asymmetric paths are not
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
integration remain separate work. The raw-stack MTU negative control still
returns unsupported. ADR 0002 accepts the demonstrated stack roles, with the
host runtime's bounded downward PMTU path in section 27; general production
physical-egress integration remains separate.

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
remain production requirements. These one-operation experiments cannot alone
close PMTU acceptance; section 27 supplies the required host-runtime gate.

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
this proposal does not establish production physical-egress or PMTU acceptance.

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

## 27. Host Runtime PMTU Feedback

The host runtime must consume validated IPv4 fragmentation-needed and IPv6
Packet Too Big feedback, rather than relying on a fixed link MTU. The initial
executable scope supports downward TCP egress adjustments from 1500 to 1280.
The link ingress MTU remains unchanged; UDP and fragment admission retain their
separate documented limits. Lower MTUs must fail the selected flow explicitly.
No ICMP report can increase a budget or select a different backend.

`runtime::Runtime::with_pmtu` takes an explicit link MTU, a reporter-selection
function over admitted `FlowMetadata`, and a fallible nonblocking seed source.
The owner selects the reporter before tracking output; it is not learned from
an untrusted report. The local TUN fixture selects the original kernel client's
address. This is scoped reporter policy, not general Internet router trust.

Each live flow retains at most sixteen emitted-segment identities, for three
seconds each, without retaining application payload. A full history refuses
new sizing hints until an accepted ACK or expiry frees capacity; it never
releases flow/routing ownership. ACK retirement observes each input separately
and requires the matching socket's send queue to advance. Admission
records a unique flow ID and fixed tuple/backend; retirement destroys its
feedback history and pending reduction. Reports must match the pinned reporter,
IP identity/length, TCP ports/sequence and checksums. Unsupported sizes terminate
only the selected flow with an unsupported-operation error. Malformed, stale,
wrong-reporter and unrelated reports cannot mutate sizing or renew ownership.

Validated reductions retain the original reservation expiry. The runner retries
transient entropy unavailability and busy output at a minimum 10 ms interval,
including without new input. Expired/cancelled/retired work is discarded. A
permanent seed/rebuild failure remains typed and retains its underlying cause.
Fresh entropy is prepared before synchronous replacement. A separate temporary
device supplies the new egress capabilities; addresses, routes and any-IP policy
are copied while socket sets, input queues and flow permits remain owned.
Replacement waits for the adapter output queue to drain and never discards
queued application bytes or asks an application to replay a write.

The initial shared TCP interface conservatively uses the minimum validated
budget across its live paths. This may reduce unrelated TCP throughput but
cannot increase another path's packet size. UDP has its own adapter/budget.
Per-path optimization, upward probing and sub-1280 support remain explicit
capability extensions; they are not inferred from this downward discovery.
The kernel fixture places Unix sockets in a private tmpfs state directory under
the ignored evidence run; a real directory in that tree is required before TUN
creation. The fixture independently unmounts it on success/failure, and namespace
destruction removes the private mount if the harness is killed.

The MTU gate requires actual runtime and kernel-TUN exchanges with multiple
flows, exact bytes/FIN, pending output, failed seed retry, cancellation/expiry,
and independent cleanup. The raw stack failure stays a separate negative
control and cannot substitute for this gate.

## 28. Production host TCP boundary

`warper-stack::{host, runtime}` promotes the initial TCP boundary from sections
7 and 10; it does not promote the experimental combined TCP/UDP or expanded
PMTU interfaces. ADR 0012 records the scope. No third-party stack types cross
this boundary. `AcceptedFlow::into_core` preserves `transport::Metadata` and
returns the core boxed stream; backend selection is immutable per flow.

`HostAdapter::new(Limits, Arc<Policy>, Seed)` validates limits before allocation.
MTU is 1280, each flow has two 8192-byte stack buffers and a duplex stream with
two 8192-byte directions, and each adapter packet queue holds at most 64 MTU
packets. Flow/accepted limits are nonzero, accepted is at most flows, and flows
is at most sixteen. Setup, idle and absolute lifetimes are positive bounded
`Duration`s. A retired stream retains its permit until all handles drop; a
reusable socket slot does not release that charge. Adapter-owned delayed input
for the old tuple is discarded before slot reuse. Packet rejection is typed,
with no backend retry or direct fallback. The caller advances the adapter clock
with `poll_io` before admitting new input; the runtime enforces this ordering.

`Runtime::new` adds bounded ingress/egress channels, each with capacity 1..64.
`required_buffer_capacity` validates first and reserves adapter payload buffers
plus `(2 * capacity + 1) * MTU` for channel and pending input. Allocator, policy,
stack metadata, kernel I/O and relay buffers require separate service accounting.
Ingress reserves capacity before copying. Egress returns no queued packets
after runtime termination. Cancellation cannot retract packets already handed
to the consumer, which must stop/join its own I/O worker.

`run` is the only owner future and spawns no task. The caller retains and joins
it. It handles application wakeups, monotonic transport and lifecycle timers,
eight output packets per turn, and bounded input admission. Output pressure
suppresses transport retries while retaining lifecycle expiry. Explicit stop
wins before another turn; loss of input, output, acceptance or shutdown owners
returns a typed failure with counters. Normal stop and failure cancel flows,
drain pending input and close outputs. Dropping/aborting the future also cancels
flows; retained streams expose terminal errors rather than silently surviving.

`Seed::generate` uses native nonblocking Linux randomness, returns typed OS or
short-read failure, and has no configured value or fallback. Non-Linux native
entropy is unsupported. UDP, fragmented IP, IPv4 options, IPv6 extension headers
and MTUs other than 1280 are outside this initial production boundary. Service
preflight must reject unsupported configuration before external changes. This
boundary alone establishes neither TUN interception nor physical egress safety.

## 29. Service-owned TCP relay supervision

The service owns a bounded `relay::Relays` set, with 1..1024 task slots and at
most 64 immutable backend registrations. Duplicate backend/active flow IDs,
unknown selected IDs and unsupported destination families fail admission. A
slot covers setup, transfer and the completion record until joined; completed
records cannot accumulate outside the task bound. Constructor/admission checks
precede task creation. There is no task admission queue or backend reselection.

Each flow opens only its selected backend with the original numeric destination
and a shared cancellation owner. One absolute setup deadline is capped by the
flow's absolute lifetime, and the service independently enforces it around the
backend future. Established copying uses two 8192-byte buffers and preserves
half-close in each direction. Positive writes count transferred bytes even on
later failure; progress resets the idle deadline. Millisecond progress timestamps
permit up to one millisecond of expiry grace, never early expiry. Payload is
never replayed after errors. The caller adds stack, backend and kernel buffers
to the service relay reservation of `flow_limit * 16384` bytes.

A returned completion contains flow/backend IDs, transferred byte counts and a
typed/redacted outcome without addresses, credentials or payload. Backend and
individual flow failures terminate that flow. A worker panic/lost worker closes
admission, cancels remaining relays and is surfaced to the supervisor. Explicit
shutdown closes admission, signals cancellation and joins all workers within
the configured shutdown budget; at expiry it aborts remaining async workers and
joins their cancellation. This relies on backend futures respecting nonblocking
polling. Dropping the task set aborts workers as a safety net; required service
shutdown uses the explicit joined path. Client connection lifetime is unrelated
to relay ownership. This boundary alone does not publish a connected service,
create a TUN or verify a physical transport path.

Shutdown reports retain the first typed flow failure and worker failure alongside
aggregate counters and any shutdown deadline/clock error. Expected cancellation
is counted separately. Thus explicit teardown preserves an initial operational
failure even when workers finish while shutdown is joining them; bounded reports
do not silently replace errors with successful cleanup.

## 30. Pure service preparation and adapter allocation

`warper-service::preflight::Plan::prepare(&Config, Platform)` validates the
initial Linux static IPv4 SOCKS5/TCP capability before external changes. No
filesystem reads, name resolution, socket opens, entropy initialization, task
spawns or connected-state publication occur. Unsupported protocol, DNS,
routing, family, MTU and hostname requirements return typed redacted errors.
File-valued credentials require prior protected import; no privileged YAML path
is opened. The canonical initial capability and diagnostics are specified in
configuration.md. Malformed relevant mutable snapshot values fail preparation.

At most 64 unique nonzero backend registry IDs are retained, with consistent
static route ownership. Effective flow slots are the lesser of the configured
admission ceiling and the host adapter's sixteen slots. This is exposed in the
plan; defaults remain unchanged. Preserve deterministic core longest-prefix
selection. Validate host and relay durations/limits before buffer reservation.

Reserve host/runtime payloads with channel capacity 64, two relay copy buffers
per effective flow, TUN reader/output buffers, conservative per-flow protocol
setup buffers and copied credential bytes against the aggregate data-plane
buffer budget. Compute with checked arithmetic and reject one-byte shortages;
copy credentials only after the budget fits. Policy/registry/task/allocator
metadata, protected source material and kernel socket buffers have separate
owners. Native physical socket budget enforcement remains an open gate.

`Plan::instantiate(Seed, Arc<dyn EndpointConnector>)` consumes the admitted
snapshot and allocates real SOCKS5 backends, host runtime/channels and retained
relay owners. No worker is spawned or backend opened during allocation. The
service supplies verified physical protection and retains/joins the resulting
owners. There is no default connector, direct fallback or claim of network
readiness. Ordinary client lifetime does not own these values. Native privilege,
route/conflict verification, managed storage and journaled platform application
must pass before a service publishes a usable capture route or connected state.

### Shared runtime ownership during shutdown

`ControlEndpoint::bind` accepts `Into<Arc<RuntimeLease>>`, retaining the same
verified lease rather than reopening or duplicating the lock. Existing owned
callers remain supported. A service worker can retain another reference while
native work completes; endpoint retirement does not release its instance lock.
Explicit service shutdown must join workers before dropping the final reference.
A real flock/thread test closes the listener, observes acquisition contention,
then joins/releases the worker and reacquires the unchanged persistent lock.
All lease mutation checks and native namespace/credential admission still apply.

### Native read-only IPv4 transport route lookup

`warper_service::linux::route_lookup::lookup(Query, Request)` observes one route
in the current network namespace. Query contains the numeric IPv4 destination
and port, explicit `Protocol::{Tcp, Udp}`, optional actual source/port and
nonzero interface constraint. The adapter supplies the process effective UID,
encodes the selected IP protocol and lookup-table flag, and rejects an
inconsistent protocol echo;
it never accepts caller-provided privilege or starts a network connection.
It returns an opaque-Debug `Observation` with the reported interface index,
source, optional gateway, table and local/unicast kind. These values confer no
physical-path protection or mutation authority.

Each retained future owns a nonblocking close-on-exec socket, a unique
process-local sequence, at most 128 request bytes and 32769 receive bytes.
The receive buffer uses fallibly allocated heap storage with exactly the
reserved capacity, prepared before socket creation or send. Receive still
borrows a fixed slice, so `BufMut` cannot grow it. Route/link query futures
retain at most 16 KiB inline, independently of the datagram reservation, to
bound stack use when composed into protected connections.
Strict kernel input checking is mandatory; the verified kernel receive queue is
at most 64 KiB including Linux bookkeeping doubling. The
extra receive byte rejects oversized/truncated datagrams. Parsing allocations
are bounded by that datagram; callers must reserve transient parse memory and
bound concurrent queries before using this boundary in a service. No worker,
subscription, hidden queue, retries after successful send or persistent cache is
created. Cancellation, owner loss and one total deadline drop the socket.
Both query and protected transport setup wrappers check that original deadline
before every operation poll, including ready I/O resumed while the Tokio timer
driver is idle. Cancellation retains priority when both conditions are ready;
an expired operation cannot start or resume I/O through a stale timer poll.
Exactly one complete kernel unicast reply with matching port and sequence is
required. An ACK is not a route, and a negative kernel errno remains typed.
Unknown, ambiguous, missing, duplicate or unsupported routing metadata fails
closed. IPv6, multipath, encapsulation and nexthop indirection are unsupported.
See ADR 0016 for dependency ownership and executable limits. A monitored path
generation, interface identity, socket binding, native mutation ACKs and journal
recovery remain separate obligations before capture or physical sends.
Existing protected TCP callers explicitly select TCP. ADR 0025's isolated
UDP-binding experiment gates the future direct-DNS datagram connector; adding
UDP observations alone does not authorize production UDP traffic.

### Native change subscription

`linux::change_monitor::Monitor::subscribe` owns one nonblocking close-on-exec
netlink socket subscribed to link, IPv4/IPv6 address, route and policy-rule
changes. Subscribe before route observations. `check_pending` returns only a
momentary empty-queue observation, while `wait(Request)` is a retained future
for the next change or failure. Neither confers send authority or makes a route
snapshot atomic. No worker, internal event queue, per-interface history or
automatic restart exists. An owner must await/poll it and prevent sends after
invalidation; merely creating a monitor is insufficient.

Any subscribed event, malformed/foreign message, socket failure, overrun,
truncation, cancellation, owner loss or deadline permanently invalidates the
monitor and closes its socket. Subsequent operations preserve the first reason
and never silently clear it. Replacement requires fresh subscription and
inspection. A dropped pending wait consumes no message across suspension and
leaves the still-owned subscription intact. Any relevant event invalidates the
whole generation conservatively, including changes unrelated to its endpoint.

The kernel receive queue is capped/verified at 64 KiB with ENOBUFS suppression
disabled. Each receive uses a fixed 32769-byte slice and accepts at most 64
messages totaling 32 KiB; oversize, malformed tails, unknown messages and excess
work fail closed. Packet libraries parse one bounded message at a time; payloads
and addresses are never retained or returned. Callers reserve receive/parse
storage and retain the monitor until retirement. This is a notification sensor,
not interface identity, a race-free route snapshot, socket binding, a routing
exemption or a complete physical-path generation. Those integration gates stay
open, alongside native mutation ACKs and persistent journal recovery.

### Native link inspection

`linux::link_lookup::lookup(Query, Request)` accepts a validated Linux interface
name or a nonzero signed-range index and returns one correlated native link
observation. It shares route lookup's private read-only transport, 128-byte
request bound, fixed receive slice, strict kernel checking, sequence ownership,
queue budget and total cancellation/deadline. The transport admits only
GetRoute/GetLink requests; native mutation messages cannot pass this boundary.
`linux::QueryError` is shared; `route_lookup::Error` remains its public alias.

Retain the index, at most 15 ASCII name bytes, at most 255 alias bytes, nonzero
MTU, layer type, flags and classified loopback/TUN/other kind. Reject missing,
duplicate, zero, mismatched or oversized comparison fields. A TUN-kind link with
Ethernet framing is unsupported, so a TAP is never admitted as a TUN. Other
link kinds do not establish physical egress. Ignore unrelated metadata only
within the shared datagram/parse bounds; Debug and errors omit native values.
This is an observation for conflict/recovery comparisons, not owned generation
identity or cleanup authority. A protected journal, boot/network-namespace
identity and service ownership mark must establish ownership before mutation or
recovery; a reused name or index is insufficient. Monitoring, physical binding
and mutation acknowledgement requirements remain separate.

### Protected network journal storage

The fixed Linux `runtime::journal::NetworkJournal` is protected storage for the
native platform, separate from connection intent and RPC authorization. Open
and every operation require native root and the retained `RuntimeLease`, reuse
protected state-directory pins and expose no path/UID/descriptor override.
An exact versioned envelope bounds payloads to 64 KiB; the platform validates its
own secret-free payload schema before depending on it. `read` returns a bounded
revisioned snapshot. `replace(expected_revision, payload)` checks the observed
snapshot, exclusively stages/syncs bytes and directory, rechecks prior/pending
identity/content, renames atomically and syncs before success. It never mutates
the network or treats storage success as kernel acknowledgement.

An observed snapshot cannot disappear or change into revision zero. Failed
staging preserves pending state and blocks writes. Uncertain durability blocks
normal operations until unchanged inspection/resync. Recovery inspection pins
bounded current/pending state; consuming discard revalidates directory/store,
identity/timestamps/bytes and prior content before unlink/sync. Never promote
pending state or remove changed objects. Abandoning a token preserves evidence;
service handlers separately authorize/bound inspections. Each store retains four
directory descriptors and at most one 64-KiB observed payload. A call/token can
retain at most two bounded records/file pins; serialization/readback add bounded
64-KiB transients, which the service must account before worker admission.
Synchronous filesystem waits need retained blocking workers and may outlive a
caller deadline; the final runtime reference cannot be released before joining.
The platform journal schema, boot/namespace/instance ownership and actual native
mutation/recovery integration remain open until independently implemented.

### Native journal owner context

`linux::context::Context` retains the runtime lease and native network/PID
namespace descriptors. Capture requires the real root runtime lease and native
connection store; no path, namespace, process, boot or instance override is
accepted. A verified procfs anchor supplies guarded namespace links and bounded
current-process stat data. Follow only the already checked fixed namespace name,
require nsfs/type/inode agreement and retain namespace handles. Check procfs PID
against the current kernel PID and preserve the exact field-22 start ticks.
Revalidation checks the current thread's scopes, process and boot before a
future driver operation; a decoded record never becomes native authority.

A fixed version-one 88-byte owner component records boot ID, network/PID
namespace device/inode, service instance, PID and process start ticks. Decode
rejects wrong length/version, noncanonical zero identities and reserved bytes;
zero process start ticks remain valid. Serialization exposes native boot bytes
without adding a public constructor for trusted `BootId`. Compare records as
current owner, previous instance, conflicting owner, foreign boot or foreign
namespace. Previous-instance classification permits inspection only; process
liveness, object ownership marks, full journal schema and mutation/recovery
policy remain required before cleanup or continuation. Debug/errors omit native
record values. Capture/revalidation uses bounded synchronous procfs reads in
retained native workers; no task, namespace mutation or network change is made.

### Journaled initial TUN lifecycle

`linux::tun::Owner` is a synchronous native-worker boundary for the initial
1280-byte Linux TUN. `prepare(Arc<Context>, optional_name, mtu)` validates native
scope, the fixed protected real TUN device and name availability before writing
a durable Prepared intent. `allocate` always creates an unnamed, down,
nonpersistent device; never pass a configured name to the upstream constructor.
Validate descriptor-derived name/index/MTU and persist Allocated ownership before
success. `apply_name` writes Renaming intent before the atomic kernel rename,
then verifies/persists Named ownership. An unchanged/OS-selected name is explicit;
no interface becomes usable or Connected through this boundary.

The version-one fixed 160-byte `WTUN` platform payload contains the 88-byte owner
component, lifecycle stage, MTU, optional requested/actual names and kernel index.
Only absent or validated Retired journal state permits a fresh preparation.
Unknown, active, pending or uncertain state requires recovery. Each native step
revalidates context and committed journal; any failed native/storage mutation
blocks further application. Keep the live device in the owner for explicit
rollback. Cleanup closes only the freshly created owned descriptor, never an
interface selected by stored name/index. Kernel index absence must be verified
before durably recording Retired. Record retirement intent before close when
storage is available; the original Prepared intent also covers compensating
closure of an owned temporary descriptor after storage failure. Preserve the
initial failure alongside rollback/storage/absence-check errors.

Repeated close verifies unchanged Retired storage. Drop closes the owned device
before releasing context/instance ownership but does not advance the journal or
claim asynchronous cleanup. The supervisor must run/join native workers and
call explicit close. A crash leaves a conservative recovery record; this version
never deletes an interface based on stored identity alone. External persistence
or unexpected surviving indices fail cleanup rather than touching foreign state.
Validate the protected device node before invoking the upstream builder so its
missing-node repair path is not selected. No network address, UP flag, route,
DNS setting, packet task or application flow is published here. Those native
transactions and full platform recovery remain subsequent implementation gates.

### Blocking native job ownership

`warper_service::native::Workers::new(1..=4)` bounds running jobs and unjoined
results. `try_reserve` requires an active Tokio runtime and returns Busy without
queuing; reserve before moving an existing native resource into a job.
`Reservation::start` moves trusted synchronous native work into a blocking task.
A reservation is shared by task and worker/result so a panic, early owner drop
or completed-but-unjoined result cannot release capacity while work remains.
Discarded results drop native resources before their reservation.

`Task::wait(Request)` borrows its retained handle. Deadline, cancellation and
owner loss end only the wait; they do not abort accepted native work or consume
its result. Subsequent waits can join the same job. Successful completion or a
panicked/cancelled worker is joined once and releases admission; another wait
returns AlreadyJoined. Panic payloads are not returned/logged by the adapter.
There is no hidden application queue, work replay, namespace change or native
mutation in the worker primitive. Reusable blocking threads must preserve
credentials/namespaces; concrete native operations revalidate their context.
The supervisor retains every Task across caller detach, surfaces failures and
joins/drains before dropping runtime ownership. Drop cannot asynchronously stop
or join a blocking syscall and is not a clean-shutdown operation. Kernel waits
may outlive a caller deadline; service worker admission and driver/application
integration remain separate gates.

### Initial owned IPv4 address transaction

The TUN owner may assign one unicast non-loopback IPv4 address with /32 and
IFA_F_NOPREFIXROUTE while remaining down. Validate the owned descriptor/context
and take a bounded IPv4 address snapshot before journaling Addressing intent.
Reject an address already assigned anywhere in the namespace. Send one exclusive
RTM_NEWADDR request only after durable intent and renewed ownership validation.
Require a correlated kernel ACK containing the original request header, then
verify the exact /32/local/no-prefix-route address in a fresh bounded snapshot
before committing Addressed. Same-address repetition verifies ownership without
sending another mutation; other address changes are unsupported by this slice.

A native-worker netlink socket bounds request/datagram/kernel queues, total wait
and cancellation checks. Dump inspection retains no address history and caps
messages/datagrams; interrupted/lost/truncated/ambiguous replies fail closed.
Only a kernel unicast sender, matching port/sequence and exact original header
can acknowledge mutation. Missing ACK after successful send is uncertain, never
permission to resend. Report not-sent, rejected or potentially-applied delivery
separately from timeout/cancellation/protocol/kernel errors. No address is
removed by number: rollback closes the originally owned TUN descriptor and
verifies retirement, preserving initial and cleanup failures.

WTUN version two uses the same 160-byte envelope and records the address and
Addressing/Addressed stages. Version-one Retired records remain admissible for
fresh preparation; active version-one state still requires recovery. Unknown
versions and malformed state/address combinations are preserved. Kernel dumps
are observations under the service's serialized native owner; changes by other
privileged network managers can invalidate them. Global live path monitoring,
interface UP, capture routes, exemptions and full recovery remain open gates.

### Initial owned TUN activation transaction

After committed address ownership, `Owner::enable(Request)` may set only IFF_UP
on the newly owned descriptor's verified index. It must validate context,
storage, identity/MTU and the exact owned address before journaling Enabling.
Send one RTM_NEWLINK with a change mask of IFF_UP only; no creation/replacement,
name, MTU or other flags may be requested. Require the shared correlated native
ACK, fresh link UP inspection and address verification before committing
Enabled. Repetition verifies current ownership/UP without sending another
mutation. Missing ACK or subsequent failure remains sticky and requires cleanup;
never infer rejection from a timeout or replay an uncertain request.

Activation publishes no capture route or connected-service status. Internal
packet handlers and verified physical endpoint protection still must precede
capture route publication. Rollback closes only the original descriptor and
verifies retirement. WTUN version three adds Enabling/Enabled, retaining the
160-byte layout and decoding version-one/two records conservatively; only
Retired records authorize fresh preparation. Native operations share the bounded
worker netlink transport and one total operation deadline. Privileged external
changes can invalidate observations; full monitoring/recovery stays open.

### Owned native packet port

The initial TUN owner registers its fresh down descriptor with an I/O-enabled
Tokio runtime during allocation in a retained native worker. No named device,
raw descriptor, cloned TUN queue or upstream device escapes. After committed
Enabled, `packet_port` may issue one non-cloneable port. The port shares only
the original descriptor and retains the native context/runtime lease, dropping
the descriptor reference before that lease. It cannot reconfigure the device.
Issuance validates context, storage and descriptor identity/MTU. Once issued,
a second port is rejected even if the first was dropped.

One receive and one send may be pending per port; concurrent same-direction
operations return Busy without queueing. Receive uses exactly 1281 bytes to
reject packets exceeding the 1280-byte MTU. Zero-length reads, oversized
packets, short writes and native failures remain typed/redacted. Send accepts
only nonempty packets up to MTU and never retries a partial write. One total
Request deadline and cancellation/owner loss bound each asynchronous wait;
the actual monotonic deadline is checked before every device I/O poll, including
resumed readiness before a rounded runtime timer wakes. Expired I/O is not polled.
Dropping the future releases its direction reservation and retains no task.
Failure/cancellation never authorizes replay of a potentially delivered packet.
The caller owns framing/family validation and bounded packet queues.

Explicit owner close returns PacketPortActive while a port reference survives;
it does not advance the journal or pretend the interface was retired. Shutdown
must cancel and join packet work and drop the port before descriptor retirement.
Dropping the journal owner with a live port preserves context/runtime ownership
until the last port drops and leaves conservative active journal state. There
is no asynchronous cleanup hook or capture-route authority in this boundary.
Verified physical protection, journaled route ownership and a supervising daemon
remain separate gates.

### Bound TCP egress feasibility experiment

Before a production physical connector depends on a binding mechanism, the
private Linux fixture must create two isolated veth namespaces, observe the
original unicast path and bind a TCP socket to that interface and source.
Read back SO_BINDTODEVICE and the actual ephemeral local tuple; query routing
with that same TCP tuple/UID/interface. Add a competing /32 capture TUN route
and prove the unconstrained lookup selects the TUN while the constrained tuple
still selects the original egress. Actual TCP must reach only the isolated
peer, preserve source/port and FIN, and leave no IPv4 packet in the capture TUN.
A failed proof remains failure; it does not authorize an unbound connection.

The root experiment uses only synthetic bytes, a fixed 1281-byte observation
buffer, at most 32 capture observations, six readiness bytes and bounded peer
request/response reads. Socket/pipe operations have two-second waits; the peer
has a five-second lifetime. Retain and join the child, preserve initial/cleanup
errors, and remove only fixture-created links/namespaces. The outer private
mount/network/PID harness independently reaps processes and verifies host state.
This is proposed API evidence, not a production physical-path lease: monitored
path generations, continuous invalidation, reservations, endpoint refresh,
exemption ownership and daemon integration remain open.

### Initial Linux protected TCP connector

Construct preparation in a retained native worker from verified native context,
1..=64 numeric IPv4 endpoints, the currently owned capture index and 1..=16
stream slots. Revalidate context before collecting read-only route/link
observations. Preparation subscribes before inspection and rejects any pending
change, but its stored observations alone confer no send authority. Supported
paths are unicast over unstacked Ethernet/veth, or explicit loopback endpoints
using a local loopback route. Other virtual/stacked links, TUN, nonlocal loopback,
IPv6 and ambiguous routes remain unsupported; no alternate path is selected.

Each admitted connection owns a fresh change subscription and one stream permit.
Reinspect the selected link, bind SO_BINDTODEVICE and the observed source before
connect, verify option/local-port readback, and query the exact TCP/UID/source/
interface tuple against the prepared route. Check notifications before SYN;
race connect against invalidation and inspect the tuple/route again before
returning. Bindings remain the capture-loop backstop across observation races.
Any mismatch or notification/loss fails closed without unbound retry. Kernel
TCP send and receive queues are each capped/read back at 64 KiB; the monitor
queue is capped at 64 KiB. Query/monitor parse capacity and at most two stored
I/O wakers per stream are separately bounded; the service must account these
native resources alongside its payload budget before admission.

Returned streams own their descriptor, monitor, permit and native context in
that retirement order. Before each read/write/flush/half-close, poll the monitor
with a waker that notifies both I/O directions. Any event/error permanently
closes the socket and returns a typed/redacted network-unreachable I/O failure.
An idle pending read wakes on changes; no worker or hidden monitoring task is
spawned. Half-close retains the permit and read side. Caller timeout/drop closes
setup resources; stream drop releases capacity only after socket/monitor close.
Fresh dials must repeat all current-path checks against the prepared selection;
network changes never select another interface/backend implicitly. Full daemon
readiness, capture publication/recovery and hardware deployment evidence remain
independent gates.

Link inspection now distinguishes unstacked Ethernet (Ether layer with no link
kind) and veth (Ether plus Veth kind). Bridges and other stacked/unknown links
remain Other, and neither classification alone proves physical egress. The
change subscription also exposes `poll_invalidation(Context)` for retained I/O
owners: Pending consumes no datagram; ready errors/events are sticky and close
the monitor. Callers provide deadline/cancellation and combine wakers when more
than one I/O direction waits on the same monitor.

Portable transport errors distinguish UnsupportedIntegration (an unavailable
verified OS transport path) from UnsupportedCapability (an unsupported backend
operation). Neither category permits selecting a different backend or direct
connection. Native route/monitor details remain behind the Linux adapter.

### Host TCP admission quiescence

Before retiring capture routes, the service can request quiescence through a
runtime-owned admission control. At the acknowledged linearization point, no
new flow or pending handshake may become an accepted stream. Already accepted
flows retain their tuple/backend, data, FIN behavior and lifetime references.
Selected new SYNs are processed without a listener so the live stack returns
RST; they allocate no stream, ID or backend task. Unknown/unselected traffic
retains its typed rejection. Pending handshakes abort without discarding queued
output or allowing a socket slot to be reused for a different tuple.

One command/result reservation bounds queued work and unread acknowledgements.
A successful queue admission owns the command even if its observer disappears;
timeout, cancellation and owner loss end only that wait. The retained receipt
can be waited again and is joined once. The runtime processes queued commands
before new ingress, and acknowledges active/retained flow counts after applying
quiescence. Repetition is idempotent, with no resume operation in this slice.
Dropping all admission senders disables that command branch without a hot loop;
it does not close the networking service. Explicit shutdown ownership remains
separate and retains its existing owner-loss behavior.

Quiescence is not shutdown, drain completion, route retirement or OS authority.
The supervisor still must drain/cancel accepted streams and pending output,
retain route/response grace references, remove acknowledged owned capture state,
then stop/join packet and stack tasks. Counts in one acknowledgement alone do
not prove those barriers. One fixed command and completion plus their retained
reservation/waker metadata are bounded separately from packet payload capacity.

### Published capture policy and lifetime observation

A host runtime publishes a read-only reference to its allocated immutable
prefix/backend mapping, ingress channel, quiescence state and shared flow
lifetime accounting. Only runtime construction creates it; native drivers may
inspect canonical entries and compare runtime identity, but cannot construct
it from serialized records or modify its counters. It proves allocated handler
publication, not that a task has been scheduled or that networking is ready;
the supervisor must retain/start packet and runtime owners before capture.

The reference holds only a weak ingress sender, so metadata cannot keep the
packet-input owner alive. Publication ends when the runtime stops, the last
ingress producer disappears or its receiver closes.
Quiescence is observed with acquire/release ordering after admission stops.
Retained flow count includes driver, pending/queued and application stream
ownership, and remains observable after runtime cancellation. Native retirement
requires quiescence and zero retained references; zero alone is not a barrier
while new admission is possible. The reference cannot remove OS state or bypass
response grace, packet drain or verified native ownership. Its private runtime
identity distinguishes two runtimes using the same policy. Payload queues stay
unchanged;
its fixed references/counters are separately bounded metadata.

### Bounded native IPv4 route inventory

The read-only route inventory runs synchronously in a retained native worker
under the caller's cancellation and absolute deadline (at most 30 seconds).
It requests all IPv4 tables, retains at most 8192 compact entries, and accepts
at most 64 datagrams / 16384 messages. Each datagram is bounded to 32768 bytes,
with a one-byte oversize sentinel and a verified kernel receive queue of at
most 65536 bytes. Parsing retains one bounded upstream message at a time.
There are no tasks, subprocesses, name lookups, mutations or retries.

A successful result requires a correlated kernel unicast multipart dump and
terminal zero-code Done. Truncation, interruption, overrun, malformed
correlation or capacity exhaustion returns an error without a partial result.
Entries retain canonical destination, table, output interface, metric, source
preference, gateway, protocol, scope and kind as adapter-owned values. Extra
selectors, flags or attributes make an entry ineligible for exact ownership
comparison; they never disappear from conflict inspection. Ambiguous or
unrepresentable destination/table metadata rejects the whole inventory.
Debug output omits route metadata.

This is a bounded observation, not a consistent snapshot, policy-rule proof,
route ownership token or authority to publish/delete routes. A future driver
must subscribe before inspection, validate rules and conflicts, journal intent,
apply exclusive changes, await ACKs, compare fresh exact metadata and commit
ownership before reporting capture readiness. Retirement must also honor
quiescence and retained flows.

### Initial IPv4 policy-rule admission observation

The initial capture driver supports only the ordinary three unconditional IPv4
lookup rules: priority 0/table 255, priority 32766/table 254, and priority
32767/table 253. A complete bounded rule dump reports whether exactly this
layout was observed. Additional/duplicate rules, selectors, suppression, flags
or actions make the layout unsupported; no rule is changed or ignored to make
a host fit. Missing priority on the local rule represents its kernel default
of zero. A matching Table attribute must agree with a nonzero header table.
Protocol is origin metadata only. SuppressPrefixLen equal to u32::MAX means
no prefix suppression; any other value is unsupported. Duplicate comparison
attributes and malformed family/length/table metadata reject inspection.

Inspection shares the retained-worker multipart transport, 30-second maximum
caller deadline, cancellation/owner loss, 32 KiB datagram, 64 KiB kernel queue
and 64-datagram bounds. At most 64 rules plus terminal Done are admitted, with
constant retained counters/bitset and one bounded parsed message. There are no
background tasks, retries or host mutations. Debug contains only counts and
layout classification. Concurrent changes invalidate observations; subscribe
before inspection and freshly recheck around journaled capture publication.
This classifier is not snapshot consistency, authorization to mutate rules,
capture readiness or support for custom policy routing.

### Initial journaled static IPv4 capture batch

After creating the packet port, the retained TUN owner can publish the complete
immutable IPv4 policy of one allocated host runtime (at most 4096 prefixes).
The caller must start and retain the real runtime/packet owners first; the
publication observation alone proves allocation, not task scheduling. No
backend dispatch or connected readiness is inferred from capture publication.
The owner retains the same runtime identity through failures and retirement.

Admission requires the ordinary IPv4 rules and no overlapping local-table
route or foreign main/default route at equal or greater specificity. Unknown
rules fail as unsupported; conflicts preserve existing state before mutation.
A bounded change subscription precedes inspection. Journal the full batch as
Routing before adding any route; add each main-table static unicast link-scope
route exclusively with destination, original TUN index and an instance-derived
high-bit metric. Each mutation requires its correlated ACK, without replay.
After all additions, subscribe afresh, recheck the complete batch/rules/link/
address and a quiet queue, commit Captured, then check the queue again. Expected
own-change notifications never stand in for fresh post-mutation verification.
The retained monitor must be supervised; any later change or uncertainty
invalidates capture readiness. No race-free kernel transaction is claimed.

Native delivery categories describe the last request, not the entire batch.
Partial or uncertain mutation leaves sticky failure, the full durable intent,
the original device and runtime observation retained. No automatic retry,
direct fallback or deletion follows. Withdrawal requires runtime quiescence
and zero retained flows, with caller-owned packet/grace draining. Journal
RoutesRetiring, inspect each exact recorded route key before deletion, preserve
changed/foreign keys, await each deletion ACK, and verify absence before clearing
the batch. Missing keys allow idempotent cleanup; different metadata at the same
prefix/metric is a conflict. Explicit TUN close refuses an attached capture
batch, even after an error, until withdrawal succeeds. Drop/crash still closes
the original nonpersistent descriptor; restart reconciliation remains required.

WTUN version four retains the 160-byte header and adds up to 4096 eight-byte
canonical IPv4 prefix entries. Header bytes 140..142 hold count, 144..148 the
metric, with remaining reserved bytes zero. Entries contain address, prefix
length and three zero bytes in policy selection order. The maximum payload is
32928 bytes. Legacy versions remain conservatively readable; only Retired
permits fresh allocation. Routing/Captured/RoutesRetiring require a nonempty
batch, address and device identity. Retiring/Retired may retain batch history;
recorded data alone never authorizes touching a named/reused device or route.

### Controlled traffic through journaled static capture

The native application fixture now publishes its actual selected /32 through
the retained production capture owner, rather than an `ip route add` command.
The real runtime task is retained before publication, and native publication
is joined outside the cancellable packet loop. Capture changes are supervised
while kernel TCP traverses the production host, protected connector, SOCKS5 and
relay adapters. The original numeric destination and exact request/response
bytes remain asserted.

The fixture quiesces after accepting its one stream, verifies that withdrawal
rejects its still-live flow reference, then completes duplex data and FIN.
After the controlled rejected SYN, joined relay and zero retained flows, it
continues packet handling until a bounded two-millisecond output quiet interval.
It joins native withdrawal before stopping the still-published runtime mapping.
This controlled quiet interval is not a general kernel drain guarantee or DNS
response grace policy. Error-driven forced flow draining, uncertain mutation
recovery and the production service supervisor remain separate gates.

### Explicit flow cancellation with retained capture mapping

The admission controller also accepts an explicit `cancel_flows` command for
error/deadline shutdown. It shares the one-command/unread-result reservation,
retained receipt, wait cancellation and observer-loss semantics of quiescence.
It first stops new admission, then cancels all driver flows and pending
handshakes, drops driver-owned packet queues and retains the live interface,
policy, input/output owners and reset handling. Existing accepted I/O wakes
with Interrupted. No application payload is replayed or handed to another
backend. Repeating the command does not restore admission or double-count
canceled flows.

Completion reports zero active driver flows but may report retained queued or
application stream handles. The supervisor must cancel/join relays and release
unread accepted streams; those references remain charged until their last drop.
Already handed-off packets and in-flight native I/O remain supervisor-owned.
`Egress::discard_pending` discards at most one configured queue capacity without
closing the receiver or stopping the runtime. It is a bounded cleanup tool, not
a kernel delivery/drain acknowledgment or DNS response-grace barrier. Only after
flow references and packet/grace work retire may the supervisor withdraw native
capture and stop the handler. No CLI state or authenticated command is added.

### Native recorded-owner process observation

A context can inspect the process identity in a recorded owner only after fresh
runtime/boot/namespace/process revalidation. A different boot is reported as
PreviousBoot; foreign namespaces or conflicting current-instance ownership fail
without interpreting foreign PID numbers. Current identity is Alive. For a
previous instance in the same scope, open a native close-on-exec PIDFD and poll
without waiting. ESRCH or a terminated process descriptor reports Exited;
otherwise read the bounded verified-procfs stat and compare start ticks. A
changed start identifies PID reuse. Missing/unreadable evidence while the PIDFD
remains live is uncertainty, never process death. No signals are sent.

The operation has no mutation, retries, tasks, subprocesses or caller paths. It
retains one transient PIDFD plus fixed procfs/stat handles and at most 4097 stat
bytes; existing native-context revalidation costs also apply. Run it in a
retained native worker: synchronous filesystem/syscall waits have no hard
cancellation guarantee. PID numbers are interpreted only in the verified PID
namespace. This is an observation, not authority to delete or adopt a recorded
TUN/route. Recovery still needs protected journal comparison, proven object
absence, fresh request checks and committed retirement.

### Abandoned initial TUN journal retirement

Recovery runs under a fresh native context/runtime lease in a retained worker.
It reads only the fixed protected network journal, decodes the bounded WTUN
record and compares native owner scope/process evidence. No record and an
already Retired record are explicit idempotent observations. A live owner,
foreign same-boot namespace, conflicting instance or uncertain evidence blocks
retirement without changing the journal or host state.

For a departed/reused same-boot owner, a recorded interface index must be absent
and all recorded main-table prefix/metric keys must be absent on every current
interface. Reused/foreign objects and changed surviving route keys are preserved
as conflicts. Prepared intent with no recorded index relies on the private,
nonpersistent descriptor/retained-lease invariant after verified process death.
A different native boot ends old kernel ownership; current objects with reused
identifiers are foreign and are never inspected for deletion or adopted.

After fresh context/request checks, commit only the Retired journal stage under
its observed revision. Preserve the old bounded identity/prefix history. Never
send a link/route deletion or open a named TUN during this recovery. Pending or
uncertain storage remains blocked until explicit protected journal inspection/
resync/discard; staged data is never promoted. Caller cancellation/expiry before
commit changes nothing, and commit uncertainty is surfaced. Filesystem waits
still have no hard cancellation guarantee, so native jobs must be retained and
joined. This operation does not implement desired-state restart, control-socket
recovery, resolver recovery or connected readiness.

## Ordinary-client credential file reader

`warper_config::credential::read_secret(&Path) -> Result<Secret<String>, Error>`
performs synchronous Unix file I/O with the client's current effective UID.
It never consults sudo environment fields, changes credentials, expands paths,
connects to a backend or approves service installation. Schema path resolution
precedes this call. Privileged handlers must never call it on RPC paths.

Open nonblocking, then inspect the descriptor: require a regular file owned by
that UID or root with no group/other permissions. A symlink is allowed because
validation and reads refer to the opened file. Bound input to 16 KiB including
an optional final newline, with one overflow sentinel; metadata alone is not
size authority. Compare descriptor identity, UID/GID, mode, length and mtime/
ctime including nanoseconds after reading. Observed changes reject the import;
this is not an exclusive lock or a guarantee against concurrent writers.

Remove exactly one final LF or CRLF, require nonempty UTF-8, and retain every
other character. Return only redacted secret Debug output and typed errors
without file paths, contents or underlying OS error text. Backend-specific
validation follows import. The reader allocates at most a bounded input buffer
and its UTF-8 result; callers account for retained copies separately. Filesystem
waits have no hard wall deadline: asynchronous clients retain/join a blocking
worker rather than canceling and losing its task. Protected serialization,
credential references, storage and the import CLI remain separate work.

## Initial managed SOCKS5 snapshot

`warper_config::managed::Snapshot::import(source, paths, platform)` runs in the
ordinary native client. Validate schema and at most 64 SOCKS5 backends before
opening selected password files; other backend imports return typed unsupported
capability. Resolve password files with the credential reader, then enforce
SOCKS5's nonempty 255-byte UTF-8 user/password limits. No service or network
mutation occurs. Import is synchronous and retains the reader's worker rules.

`Snapshot::encode() -> Result<Secret<Vec<u8>>, Error>` emits a bounded `WMCF`
version-one envelope; `Snapshot::decode(bytes, platform)` performs only bounded
in-memory validation and opens no files. The 16-byte big-endian header contains
magic[4], version u32=1, normalized YAML length u32, credential count u16 and
reserved u16=0. Follow with that YAML, then ascending unique credential entries:
protocol index u16 (zero-based), user byte length u16, password byte length u16,
reserved u16=0, then UTF-8 user and password bytes. Each length is 1..255; every
index must name an existing SOCKS5 backend. The whole envelope is at most 1 MiB.
Reject unknown versions, reserved fields, duplicate/out-of-order entries,
truncation, trailing data and over-limit input before using it.

The configuration section materializes every root default, backend ID and
normalized routing/endpoint value in deterministic key order, without user,
password or any file path. Decode requires exact canonical representation under
version-one semantics before applying the separately bounded credential table.
Never promote decoded values into networking readiness; service preflight still
checks the currently supported static IPv4 slice and native resource budget.
`Snapshot::config()` exposes the reconstructed typed configuration only to native
code. Debug and errors redact both sections; neither encoded snapshots nor this
in-memory accessor is an observable configuration RPC. Protected atomic storage,
administrative installation, generation fencing and redacted views remain
separate boundaries. Version-one defaults must remain stable; incompatible
normalization/default changes require a new version or explicit migration.

## Offline owner-intent recovery

Offline owner-intent recovery uses a uniquely borrowed runtime lease rather
than a manufactured control peer. The lease must be freshly acquired and must
never have attempted endpoint publication. Its existing initial-user-namespace,
actual UID and protected-lock validation supplies administrative authority.
Inspection pins exactly the same bounded pending/committed objects as online
recovery; discard repeats every unchanged-object and committed-policy check.
Neither path promotes staged enrollment or removes committed owner policy.
Publication permanently invalidates offline recovery through that lease even
after its endpoint is dropped. A stopped-service command must reacquire the
persistent flock before inspecting or discarding pending owner intent.

`tun::inspect_abandoned` reads the protected committed network journal and
checks the same recorded process, boot, interface absence and capture-route
absence conditions as retirement. It reports NoRecord, Retired or Retirable
without journal writes or kernel mutation. Pending/unknown state, live owners,
foreign route keys, cancellation and unavailable evidence remain errors.
Retirement independently rereads and revalidates before its revision-fenced
journal write; an inspection result is never a mutation capability. The offline
coordinator may apply the same read-only validation to the committed snapshot
pinned by a pending token before discarding any unpublished state.

The stopped-service `linux::recovery::inspect` coordinator acquires the actual
exclusive native runtime lease before reading fixed owner, connection,
configuration and network stores. It retains at most one bounded pending token
per store, validates the corresponding committed snapshots, and reports only
pending booleans plus endpoint/network retirement classifications. It performs
no snapshot replacement, discard, sync or kernel mutation. Instance-lock
creation during acquisition is permitted; the persistent inode is retained.
Native queries share five seconds; synchronous filesystem reads retain their
documented kernel-wait limitation. The synchronous command starts no executor
or service tasks, has no user-selected path and releases all pins on return.

Stopped-service repair performs that complete preflight before external changes.
It retains the four pending tokens and exclusive runtime lease, retires only
verified stale endpoint publication, discards unchanged unpublished intent,
resyncs unchanged committed records, and reruns native ownership/absence checks
before revision-fenced journal retirement. It never promotes pending bytes,
changes committed owner/configuration/connection intent, starts a backend or
deletes an inferred kernel object. Owner resync requires the same exclusive
never-published lease and checks the pinned committed file before and after
fsync, followed by directory sync. Partial failure is reported with its typed
primary error and inspection guidance; completed safe steps are not rolled back
or replayed automatically. All pins and the runtime lease survive until the
repair operation returns.

Online administrative recovery uses the authenticated serialized controller.
WCTL v2 InspectRecovery (6, empty body) returns RecoveryReply (0x8006, u16):
bit 0 means pending intent, bit 1 means recovery required, and bit 2 means live
or retained service work prevents repair. No other bits are valid. Recover (9,
empty body) returns Recovered (0x8009, empty body) only after completed repair.
Older peers reject unknown operations; clients never retry automatically or
fall back to an offline privileged path. Hello precedes recovery, but Status
is not required because uncertain stores can prevent ordinary status reads.

Repair refuses active/pending/retained network ownership. Before mutation it
pins pending records, validates committed configuration and native ownership,
and prepares operation-history/control admission changes. It then discards
unchanged unpublished intent, resyncs committed records, refreshes approved
in-memory configuration and retires proven-ended network ownership. It preserves
accepted connection intent and never starts a backend. Admission changes are
applied before acknowledgement. Root peer authorization is renewed at handlers
and persistence boundaries. Policy corruption/unavailability can stop the daemon;
unavailable service or retained ownership requires explicit stopped-service
recovery, never a client-side bypass. Partial errors preserve typed causes and
require fresh inspection, without replaying accepted payload or operations.

Foreground diagnostics import normalized configuration with the same validated
invoking-account materializer as the client. Only the daemon binary's
presentation layer reuses that client helper; core service modules consume
normalized bytes and accept no user paths. Before creating an async runtime,
diagnostic preparation validates the candidate and all fixed protected stores,
requires the exclusive instance lock and rejects pending state. It can retire
proven stale publication/journal ownership but never discards pending state or
changes managed configuration, enrollment or accepted connection intent.

The diagnostic lease is explicit in-memory approval with generation zero,
meaning no managed generation; it is never exposed through a control endpoint
or accepted as a durable managed approval. It retains the same context and
exclusive configuration ownership guard as managed leases. Diagnostics use the
production Network supervisor, physical protection, TUN journal, queues, flow
handling and cancellation/drain deadlines. No local control endpoint is
published. SIGTERM/SIGINT/SIGHUP stop the foreground engine; loss of signal
observation preserves its primary error alongside cleanup failure. Presentation
output occurs before networking starts or after it stops, so output backpressure
cannot stall forwarding. Verbose/debug summaries contain aggregate counts only.
Synchronous import/bootstrap filesystem waits retain their documented absence
of a hard kernel deadline. Service/diagnostic exclusion uses the same persistent
flock inode; diagnostic operation never clears a saved connection intent.

## Linux native import process

The explicitly elevated CLI materializes configuration before starting its async
executor. It validates the invoking sudo identity against the OS account
database, then executes its own binary through the fixed `/usr/bin/setpriv`
helper with that UID, primary GID, initialized account groups and
`--no-new-privs`. The environment is cleared. No shell or user-selected executable
is involved. The materializer verifies real/effective credentials and the exact
account group set before path resolution or source reads. Root without a sudo
identity imports as root. Required util-linux helper failure is an error.

The private stdout pipe uses a 12-byte big-endian header: magic `WMIM`, version
u16=1, status u16 and payload length u32. Status zero carries one canonical WMCF
snapshot of at most 1 MiB. Error statuses 1 through 7 respectively mean source,
schema, credential, size, identity, unsafe child and unsupported capability;
they carry no payload.
Reject unknown statuses, versions, truncation, trailing bytes and excess length.
The child rejects stdout that is not a pipe. The parent bounds reads, validates
the snapshot without opening paths, and always reaps the child; failed reads
trigger termination before reaping. Cleanup errors retain the primary failure.
Source/account I/O is synchronous without a hard filesystem deadline.

After native service authentication, administrative CLI commands obtain a fresh
status and compare the corresponding configuration generation or owner revision.
Installation sends normalized bytes, never source paths. Enrollment sends an
optional UID; UID 0 remains the administrative principal after owner removal.
Administrative mutations are submitted once. A lost or invalid acknowledgement
requires inspection before retrying; it never triggers automatic resubmission.

## Protected managed configuration storage

The Linux `warper_control::runtime::managed::ManagedStore` is synchronous fixed
storage under the retained runtime lease, not an installation handler. It opens
only root-owned `/etc/warper` mode 0700 beneath verified root-owned nonwritable
parents, without symlink or mount traversal into the final directory. Creation
belongs to installation. It never searches home directories or accepts a path.

Reuse the network journal's bounded atomic storage mechanics with distinct
fixed slots, magic and limits; do not change its on-disk format or capacity.
The managed slot uses `configuration` and `configuration.pending`, and a `WCFG`
version-one 24-byte envelope: magic[4], version u32=1, generation u64>0, payload
length u32, reserved u32=0, followed by 1..=1 MiB of managed data. Files are
root-owned regular mode 0600, single-link, without symlink or mount traversal.
Payload semantics/`WMCF` decoding belong to service preparation before mutation.

`read/inspect/replace/resync/inspect_pending/discard_pending` retain the network
journal's revision comparison, inode/metadata/byte observation, exclusive staging,
fsync/rename/fsync, uncertain-commit and explicit recovery rules. Tokens belong
to one opened slot; a network token cannot discard managed state or vice versa.
Pending bytes are never promoted. A stale observation or foreign replacement is
preserved as conflict, including changed parent directories. Debug/errors redact
all data. Each slot's input/pending/readback allocations are bounded by its own
capacity and must be included in the eventual supervisor's native budget.

Service handlers must freshly authorize administrators, validate managed data,
serialize installation while disconnected, and fence the expected generation
before calling replacement. The low-level runtime lease is not peer enrollment
or administrative installation authority. No handler or CLI becomes reachable
merely because this storage primitive exists. Blocking calls retain their worker
and runtime references after observer cancellation; filesystem waits have no hard
wall deadline. Native privileged evidence is required separately from local
fixed-root filesystem tests.

## Linux approved configuration ownership

`warper_service::linux::configuration::Configurations` owns the fixed managed
store and an immutable approved snapshot under `Arc<Context>`. A single-owner
claim belongs to the exclusive runtime lease and is retained by the manager and
all approved configuration leases. Dropping/reopening a manager cannot bypass
outstanding leases, even through another native context sharing that runtime.
The claim releases only after its final guard drops and keeps the runtime lock
held throughout. All operations
are synchronous retained-worker operations; no background task or network is
started here. Open decodes WMCF and runs pure service preflight before exposing
stored material. Missing data is generation zero with no default configuration.

Each `lease()` first revalidates protected storage, then returns a cloneable
`ConfigurationLease` retaining its approved generation, typed data and native
context/runtime ownership. The
supervisor must retain this lease from preparation through complete network
retirement/cleanup, including failed startup and observer cancellation. Any
outstanding lease makes installation Busy. Mutable manager access serializes
admission; when only its own Arc remains, no external holder can begin a new
clone. Dropping a client does not release a supervisor's lease.

`install(peer, expected_generation, encoded)` revalidates native context and
freshly authenticates the actual Unix peer as administrator before data handling.
It refuses active leases, rechecks the observed protected generation and expected
revision, decodes canonical managed data and runs pure service preflight before
replacement. Only confirmed durable replacement publishes a new cached snapshot
and generation. No raw paths are accepted. Uncertain storage stays blocked for
explicit recovery, without claiming the proposal was applied or replaying it.
`status()` and new leases recheck native/storage identity; external changed data
is never silently adopted. This is a native installation boundary, not a control
session handler, native-budget approval or connected/readiness declaration.

## Linux authenticated control sessions

`warper_control::session::Session` owns one nonblocking Tokio Unix stream, a
nonzero service instance ID and an encoded-message ceiling. Construction does
not publish a listener or prove a protected endpoint; the service retains its
runtime lease and authenticates endpoint admission before creating sessions.
UID-only sessions remain Linux-only; macOS requires its native identity gate.

`receive(policy, deadline, cancellation)` freshly authenticates Observe access before reading
one bounded frame, then retains it without dispatch. After reading, the service
loads current protected policy again and calls synchronous `authorize(policy)`;
that checks actual kernel identity and command access before exposing the frame.
Hello must be first and occur once. Request IDs strictly increase within one
connection; retries use a new frame ID with the original operation identity.
Unsolicited replies, missing/repeated Hello or duplicate/decreasing IDs poison
the session. Only one frame/request is pending per session.

Hello, Status and OperationStatus require Observe; Connect/Disconnect require
Operate; Enroll, InstallConfig, InspectRecovery and Recover require Administer. An
`AuthorizedRequest` records the verified role and owns the redacted frame; it is
not durable authority. A handler that queues/waits before mutation must reload
protected policy and authorize again at its commit boundary. Global client,
request, native-worker and retained-frame budgets belong to service admission.

`respond(frame, deadline, cancellation)` requires the active request ID and appropriate reply
kind (or ErrorReply). HelloReply must echo the session's actual instance ID.
Successful HelloReply opens the session for commands; a failed Hello closes it.
No next request may be read until its response is finished. Every frame read/
write has an injected total deadline/cancellation receiver and encoded bound.
The stream is moved out before asynchronous I/O: dropping an in-flight future,
partial failure, expiry or cancellation closes it rather than permitting resume
or payload replay. Authorization/protocol failures also close the session.
Closing a control stream does not cancel service work or release networking.

This boundary supplies framing, handshake, correlation and fresh-policy dispatch,
not concrete command handlers, a daemon executable or client availability proof.

### Linux control admission

The service constructs one `admission::Admission` from a pure validated `Plan`
and uses `Session::admitted` for every accepted client. The primitive
`Session::new` remains available for callers that provide their own admission.
Client and request ceilings are independently capped at 64. The encoded message
ceiling is between 68 bytes and the wire maximum. Checked arithmetic reserves
46 encoded reply bytes per client, then divides the remaining configured
control buffer budget into whole maximum-message request reservations. At
least one request must fit; effective request concurrency may be below the
configured ceiling (seven with the current defaults).

A non-cloneable client permit retains its admission owner. `receive` verifies
Observe access, then acquires a request reservation before reading a header or
allocating its body. Waiting shares the frame's absolute deadline and
cancellation; cancellation/expiry/abandonment closes the session. Admission
closure wakes waiters and rejects new permits without canceling admitted work.
The reservation moves with `AuthorizedRequest`, so dropping the client session
cannot release capacity while a retained worker still holds its frame. Failed
framing/authorization releases the reservation. Handlers move the whole request
into retained work and avoid unaccounted copies of its borrowed body.

The buffer calculation covers logical encoded request buffers and one bounded
reply per client. It does not claim a process RSS limit: allocator overhead,
Unix socket kernel queues, protected storage copies, operation records, native
workers and service metadata need separate reservations in the supervisor.
Handlers must construct only one bounded reply at a time. This boundary does
not supply event subscriptions or operation-history admission.

Reconfiguration updates that same admission owner; it never creates a second
quota pool. Each outstanding frame retains its original encoded-byte charge and
its client lease through queued/native work, even if the session disconnects.
A smaller plan admits nothing beyond its client, request and byte limits until
old charges drain. Previously admitted buffers remain bounded by the previous
plan and their original deadlines; a smaller limit does not claim to free or
cancel them. An expansion accounts for old and new charges together. Session
readers obtain their next frame size from the actual request reservation rather
than caching the size from connection admission. Reply capacity remains reserved
for the entire client lease. Closing or poisoned accounting cannot reopen through
reconfiguration or a late release.

## Linux retained packet pump

`linux::packet::Pump` owns the original `Arc<PacketPort>`, host ingress and host
packet egress. Its owner runs the pump in one retained task and joins it before
retiring the native TUN owner. The pump polls an independent reader and writer
inside that task; neither direction spawns detached work. `run` borrows the
pump, so stopping packet I/O retains the host output receiver until explicit
runtime shutdown is joined. Only then may the supervisor drop the pump. Each
yields after at most eight ready packets so sustained I/O cannot starve its sibling or
supervisor cancellation. A failure in either
direction cancels and joins the other, preserving a secondary failure alongside
the initial cause and bounded counters. Dropping the external cancellation
sender is an ownership failure; explicit cancellation is an orderly stop.
Dropping the run future is not a substitute for joining its task.

The reader retains one 1281-byte sentinel buffer, passes at most 1280 bytes to
bounded host ingress, and counts queue-full drops without retry or direct
forwarding. Read waits renew after a 30-second idle deadline; idle is not a
network failure. All other native read failures stop the pump. The writer owns
at most one output packet, performs one original-device send with a positive
write deadline no greater than 30 seconds, and never retries an uncertain or
failed send. Cancellation may discard that pending packet, which is counted.
Closed host ingress/egress and native errors surface to the supervisor.

The existing `Plan::buffers().tun_io` reservation covers the sentinel buffer and
one pending output packet; fixed counters and task metadata need supervisor
accounting. The pump reports captured/sent bytes and packets, queue-full drops,
discarded output and a fixed logarithmic write-wait histogram. It retains no
payload in diagnostics or unbounded per-packet timing samples.

The supervisor keeps this pump and the runtime mapping alive during flow
quiescence and route withdrawal. After the native withdrawal acknowledgment it
can cancel/join packet work, then stop/join the runtime and retire the TUN. A
pump stop does not withdraw routes, prove flow drain, declare connected
readiness or provide a general shutdown barrier on its own.

## Linux network supervisor

`linux::network::Network` is constructed from an approved configuration lease.
It derives its context from that same lease, validates the pure networking plan
and reserves one native worker before mutation. Phase 1 startup and shutdown
budgets must be positive and no greater than 30 seconds. The supervisor retains
the configuration through all native work, packet/runtime tasks and cleanup.
Its cancellation channel belongs to the service, never a client connection.

Startup journals and activates a fresh TUN, prepares protected physical backend
paths, instantiates the admitted stack/relays, and polls both retained packet
and runtime tasks before publishing capture. A task that finishes during its
first poll cannot acknowledge startup. Connected is published only after the
native capture acknowledgment and a final live-task check. The service must
continue supervising runtime, packet and capture-monitor failures afterward.
Individual relay failures remain per-flow outcomes; worker failure stops the
network owner. Relay-capacity exhaustion drops only the newly accepted stream
and increments bounded rejection counters; it does not stop established flows.
Selected-backend failure never retries traffic directly.

All blocking transitions use one retained native task slot. Its result returns
the original owner even on operation failure. Observer cancellation/expiry
leaves the accepted native task in the supervisor; cleanup first joins it with
an independent service deadline. Panic/lost native ownership requires recovery.
An unresolved native task prevents releasing its runtime, packet or mapping
owners. `Network` itself stays retained when cleanup cannot establish retirement;
`cleanup` retries owned work without replaying application payload.

Stop first quiesces admission. An explicit stop permits existing accepted flows
to drain for at most one quarter of the shutdown budget; failure stops skip
this grace.
It then cancels remaining driver/relay flows, drops queued accepted streams and
joins relay work within that first-half deadline. Capture withdrawal requires
zero retained flow references and keeps the packet pump and mapping alive.
Only after acknowledged withdrawal does cleanup stop/join packet work, stop/
join the runtime, release the original packet port and explicitly retire the
TUN. A failed withdrawal leaves those owners retained and admission quiescent.
Reports preserve the initial failure and separate cleanup-stage failures.

Each native result and asynchronous task completion retains its own approved
configuration lease until joined. Backend connector ownership pins the same
lease through every relay task. Emergency owner drop aborts async tasks but
does not claim journaled cleanup or retirement.

The supervisor owns at most two asynchronous owner tasks, one native job and
the preflight flow ceiling of relay tasks. Payload buffers retain the existing
plan reservation; physical TCP queues remain bounded by the connector's stream
ceiling and verified per-stream queue limits. This component does not admit
control clients, install configuration or persist Connect/Disconnect intent;
the daemon controller composes those independent ownership budgets.

## Linux control endpoint restart recovery

New endpoint publication writes a fixed 160-byte WCTL version 1 intent. It pins
the persistent lock's device/inode identity, a Prepared or Bound stage, and
(for Bound) the socket pathname inode's full recorded metadata. Prepared is
synced before bind; Bound is synced after final socket mode and before listen.
Each owned verification also compares the expected intent bytes. Legacy empty,
torn, unsupported or changed intent is not automatically adopted.

`endpoint::recover(&mut RuntimeLease)` requires uniquely owned runtime access
and a lease that has never attempted endpoint publication. Publication marks
that lease permanently; extracting its Arc after listener drop does not replace
fresh flock acquisition. Retained service/context work therefore prevents a
fresh eligible owner. Recovery verifies protected paths, lock identity and the
recorded socket metadata before removing only the proven stale objects. It
never removes the persistent lock. A Bound record with an absent socket can
finish interrupted retirement; repeated recovery without either object is a
no-op. Prepared plus an existing unidentified socket, a socket without intent,
legacy intent and any foreign metadata remain explicit recovery conflicts.

`endpoint::inspect(&RuntimeLease)` applies the same protected-path, fresh-lease,
intent and socket verification without unlinking or syncing objects. Its only
successful observations are Absent and Retirable. Neither is a capability for
later mutation: `recover` repeats all checks. Inspection rejects a lease that
attempted publication and preserves unknown or changed state. The caller retains
the instance lock throughout inspection; only its owner may attempt recovery.

## Linux daemon composition contract

The daemon composes the verified native controller, shared admission owner and
network supervisor. One retained native-worker reservation owns the synchronous
control actor for its lifetime. Bounded command/event channels have 64 slots;
queued commands retain their authorized frame and client reservation. The actor
blocks on its inbox rather than polling. The network supervisor owns its own
single native worker. No client owns either worker or the network cancellation
sender.

Bootstrap acquires fresh runtime ownership, reconciles endpoint publication and
network intent, then publishes the protected listener. Readiness of that actual
listener drives acceptance through a cloned owned Unix listener. Its async
adapter owns readiness bookkeeping without a raw-descriptor registration.
Native work verifies protected endpoint metadata and authenticates each accepted
peer before framing. The cloned listener closes before endpoint retirement.
Each accepted stream retains
one native peer descriptor for fresh authorization. Peer descriptors are dropped
before their final client quota can release. Each session has one request/reply
at a time and five-second absolute I/O deadlines. Session tasks are retained in
a bounded join set; closing a session never sends Disconnect.

Native dispatch executes durable actions before delivering their replies.
Controller callbacks consume actual network readiness and joined outcomes;
unknown cleanup keeps the original Network owner for an explicit cleanup retry.
Historical operation success cannot be repurposed as current network readiness.
Changed admission limits update the existing owner and preserve outstanding
charges. The encoded-buffer limit does not claim to cap allocator overhead,
protected configuration copies, kernel peer-owned queues or total RSS.

Stopping closes admission, cancels and joins session tasks, signals the network
owner, and wakes the native actor. Queued mutations are discarded after stop is
observed; already executing work remains owned and joined. The daemon keeps
receiving native completions while stopping so a bounded event channel cannot
prevent shutdown. Listener references are released and endpoint retirement runs
in retained native work only after task ownership is settled. A 35-second daemon
stop budget covers the initial network deadline (at most 30 seconds) and control
drain. Kernel filesystem stalls are not claimed interruptible. A deadline leaves
pending ownership retained and returns a typed cleanup failure; it never reports
successful cleanup or removes foreign state. Runtime/process termination is a
separate final boundary and leaves durable recovery obligations explicit.

### Linux lifecycle tracing

The service's `telemetry::LifecycleLog` is a scoped `tracing` subscriber for
fixed lifecycle event names only. It retains at most 64 static names in a ring;
all event fields, unknown names, other targets and spans are discarded. Event
recording uses `try_lock`, performs no I/O and counts contention/overflow with
a saturating atomic loss counter. Its memory bound is independent of traffic
volume and control admission. It does not retain payloads or configuration.

`warperd service` and `warperd run` share network-supervisor transition events.
The current-thread runtime installs the scoped dispatcher; native blocking
workers do not emit lifecycle events. The executable writes the ordered tail
and loss count only after the command returns and its asynchronous forwarding runtime stops.
Uncertain native cleanup may still retain ownership and recovery obligations;
writing diagnostics does not establish successful retirement.
It preserves the primary error/exit classification if the diagnostic writer also
fails; a writer failure after operational success produces a failure exit.
Presentation may wait after shutdown, never during forwarding. This is shutdown
tracing, not a live log stream. Bounded nonblocking desktop delivery remains
Phase 5 and must preserve these data exclusions and loss semantics.

## Phase 2 DNS names and domain selection

`warper_core::dns::{Name, Rule, Policy}` implements the normalized selection
boundary. `Name::from_labels` consumes decoded DNS labels and stores at most
255 wire bytes inline, including length octets and the root terminator. Labels
are nonempty and at most 63 octets; an empty iterator represents root. ASCII
case folds without transforming other octets. Embedded dots and underscores
remain label content. `Name::from_ascii` accepts unescaped ASCII presentation
names with one optional terminal dot; Unicode configuration names must first
pass the existing IDNA validation. Debug and error output exclude names.

`Rule::new` accepts canonical lowercase ASCII configuration domains, rejecting
root, terminal dots, IP literals and non-hostname labels. It does not repeat
IDNA conversion. `Policy::new(&[Rule], limit)` validates a positive count limit,
rejects excess entries before allocation, and rejects duplicate or conflicting
domain assignments. The immutable boxed rule slice has fixed-size inline names
and no secondary indexes. Storage is proportional to the admitted rule count,
plus allocator overhead; lookup allocates nothing. The caller retains this
snapshot for the request's configuration generation. The longest whole-label
suffix selects one backend; misses return `None`. Backend errors cannot cause
selection to be retried with a broader rule.

Core tests exercise maximum wire lengths, binary labels, case, terminal dots,
service record names, IDNA ASCII output, label boundaries, longest selection,
input-order independence, duplicates and admission failure. This boundary has
no I/O, tasks, deadlines or cancellation work. It does not decode compressed
wire packets, execute DNS transports, resolve endpoints or mutate routes.
Those production interfaces and native Phase 2 acceptance remain open.

### DNS packet adapter

`warper_service::dns::{Limits, Packet, Question, Error}` wraps pinned
`hickory-proto` 0.26.3 (`std` only). Third-party values/errors remain private.
`Limits::new(wire_bytes, records)` accepts 12–65535 bytes and 1–4096 records.
`Packet::request` and `Packet::response` check byte size, one question and the
sum of all record-section counts before library allocation. Packet vectors,
expanded names and variable record data are bounded by these independent
count/wire limits; allocator metadata and packet/request concurrency are
additional service obligations. No global cache or lease admission is implied.

`Packet::response(bytes, request, limits)` requires the original request's ID,
case-folded whole-label name, record type and class, and response direction.
Both methods require standard-query opcode. `Truncated` is returned only after
complete envelope correlation, even if a trailing record is incomplete. A
transport may then retry TCP through the same selected path and deadline.
Full decoding rejects malformed records and trailing bytes. Valid negatives
remain successful packets with their original response codes. Encoding preserves
DNS fields/TTLs through the library. `encode_limited` enforces a smaller output
limit during serialization and rejects implicit record truncation; arranging a
safe UDP TC response belongs to the output owner. Neither encoding method grants
no positive-answer publication permission. No library Debug/error text escapes.

This synchronous adapter owns no tasks, sockets or asynchronous cleanup.
DNS transport framing, endpoint validation, cache/lease admission, route commit,
response handoff and native resolver integration remain required Phase 2 work.

### Selected-backend TCP DNS exchange

`warper_service::dns::{Admission, TcpTransport, ExchangeError}` implements one
TCP DNS request per owned backend stream. `Admission::new(1..=4096)` creates
a service-wide count pool; all transports must receive clones of that same pool.
Acquisition is immediate and never queues. The permit spans encoding, setup,
partial frame I/O and validation, and releases on every return, cancellation,
timeout or dropped exchange future. The caller owns/polls the future; this
adapter starts no task and retains no worker after it returns.

`TcpTransport::new(Arc<dyn Backend>, SocketAddr, Limits, Admission)` validates a
literal upstream and its selected backend's TCP/family capabilities. It owns
no direct connector, resolver or alternate backend.
`exchange(&Packet, Request, &QueryBudget)`
uses the original total deadline and cancellation context through the entire
operation, including backend setup. It writes one two-byte big-endian length
and complete query, bounds the response length before allocation, reads exactly
one frame, then applies packet correlation/validation. A TCP TC response fails;
it is not retried or redirected. Valid negative packets pass unchanged in
meaning. No query is retried following an I/O or selected-backend failure.

One exchange retains a query frame of at most 65537 bytes (including its TCP
prefix) and a received wire vector of at most 65535 bytes, plus bounded decoded
packets, backend setup/stream buffers and
allocator overhead. Request-count admission is not byte admission: service
preflight must charge these capacities and decoded record/name storage before
enabling DNS. The daemon still rejects DNS configurations until the complete
session, route and resolver integration exists. There is no connection pool or
unbounded pending queue. Local listener framing for multiple requests on a
connection, UDP/direct transport, endpoint discovery and publication remain open.
The query's prefix and body share one write operation to avoid artificial
small-prefix/Nagle delays; partial writes still complete under the same deadline.

Unit tests use bounded duplex peers and a controlled clock for partial framing,
negatives, failures, admission, cancellation, timeout and dropped-future cleanup.
`tests/dns_tcp.rs` checks actual loopback TCP against a controlled SOCKS5 peer,
the original DNS destination, production backend negotiation, DNS frames and
stream closure. This is protocol/transport evidence, not DNS-discovered TUN
routing or system resolver acceptance.

`DirectTcpTransport::new(Arc<dyn EndpointConnector>, SocketAddr, Limits,
Admission)` supplies a separate explicit direct role over the same framing and
ownership engine. It accepts only numeric upstreams; the service must supply
the already verified physical connector and reject loop-producing resolver
choices before installing DNS policy. It does not discover or trust a host stub.
The selected-backend transport retains no direct connector. Direct setup and
deadline failures are typed `ExchangeError::Direct`, distinct from selected
backend errors, and neither role retries or invokes the other. Both share the
same service-wide admission pool. Controlled direct and SOCKS5 peer tests verify
the distinct wire protocols, negative results and joined stream cleanup.

### Protected connected datagrams

`warper_core::transport::datagram::{DatagramIo, Received, Socket,
OpenDatagram, DatagramConnector}` defines a connected, fixed-peer datagram
boundary. Poll-send succeeds only for a complete datagram; no byte-stream
partial-write retry is permitted. Poll-receive returns the initialized copied
length and explicit truncation flag. Callers must discard truncated packets,
including prefixes fitting their buffer. Zero-length datagrams are valid.
The caller owns buffers, deadlines and the socket; the boundary adds no queue
or detached task. This currently serves physical DNS transport, not application
UDP support in the SOCKS5 or other backend implementations.

`linux::egress::udp::Preparation::new` runs in a retained native worker and uses
the same authenticated context, 64-endpoint limit, excluded capture identity and
supported underlays as TCP. It selects UDP tuples explicitly. `prepare(Request)`
records immutable monitored paths. `Connector::connect` reserves one of at most
16 lifetime association slots, subscribes afresh and verifies the saved link.
It creates a nonblocking close-on-exec UDP socket, limits/readbacks receive and
send queues before binding a local port, binds/readbacks the verified device,
binds the saved source, and validates its actual UDP tuple route before connect.
Post-connect tuple, route, link and pending-change checks precede publication.
No alternate address, device or unbound socket is selected on failure.

The returned `Datagram` owns its socket, monitor, two-direction waker table,
admission permit and native context in that destruction order. Every poll checks
path invalidation before I/O; a change/loss closes the socket and wakes pending
I/O with typed `PathInvalidated`. The object retains admission/context until
full drop. Sending rejects IPv4 payloads above 65507 bytes before the syscall.
Receiving uses bounded `recvmsg`, rejects unexpected peers (including queued
pre-connect data) or truncated ancillary metadata, and reports payload
truncation without treating its prefix as a complete packet. No raw descriptor
or reconfiguration API escapes.

Kernel queue admission is 3 × 65536 bytes per association: UDP receive/send and
monitor receive queues, including Linux's socket-buffer doubling. Native setup
query buffers, path metadata, descriptors, packet buffers and allocator/kernel
bookkeeping are additional costs. Service-wide data-plane and DNS admission
must charge these before enabling DNS. IPv6/unsupported paths return typed
unsupported integration; resolver discovery and loop-proof selection remain
separate preflight obligations even for an accepted physical socket path.

Local socket tests exercise zero/truncated datagrams, consumption boundaries,
connected-peer filtering and rejection of an unexpected queued source. The
isolated physical fixture adds actual production-connector roundtrips, retained
admission, oversized sends, an independently parked receive, MTU invalidation
and failed replacement. It also records a controlled 200-datagram workload's
latency distribution, bytes, process CPU/cumulative peak RSS and private egress
drop deltas. Native execution passes in
[CI 41618257779](https://github.com/skunkie/warper/actions/runs/41618257779)
at `edadf71`, with inspected production UDP assertions, a measured controlled
workload and all four zero-exit, no-timeout, host-preserving probe manifests.
The installed-unit gate also passes. This establishes the Linux x86-64
connector boundary; DNS integration and service-wide byte admission remain open.

### Request-scoped query budgets and direct UDP DNS

`dns::QueryBudget::new(limit)` requires a positive attempt count and owns fixed
atomic metadata. A parent request supplies the same budget to every selected
TCP, direct TCP and direct UDP exchange and all dependency lookups. Each actual
upstream transport opening charges one attempt before dialing. Failed setup
does not refund it; admission/validation refusal before a dial does not consume
an attempt. Concurrent children charge atomically and cannot underflow or reset
the parent count. The resolver must still bound upstream concurrency/buffers
independently; an attempt count alone is not byte admission.

`DirectUdpTransport::new(Arc<dyn DatagramConnector>, Arc<dyn EndpointConnector>,
SocketAddr, Limits, Admission)` accepts two prepared physical connectors for one
literal upstream. It owns no selected backend or alternate resolver. One global
request permit spans the entire UDP/TCP exchange. It bounds the encoded query,
charges/opens one connected UDP socket, sends one complete query and receives
one bounded datagram with an extra size-detection byte. Socket truncation,
oversized or malformed data, mismatched ID/question/class/type, I/O failure and
timeout fail without TCP retry. Valid negatives are final packets.

Only correlated DNS TC triggers TCP retry to the same upstream. UDP resources
drop before TCP opens; the TCP helper borrows the existing permit, verifies its
admission-pool identity and never reserves another client slot. The original
deadline/cancellation and query budget cover both attempts. Queries above the
conservative 65507-byte UDP ceiling use TCP first with one charged attempt.
The helper rejects a permit from another pool. No transport failure selects
another role or DNS server; ordered same-role server retry belongs to the parent
resolver and must use the same budget/deadline.

Controlled tests cover single-slot TC retry, exhausted budgets, concurrent
charges, valid negatives, malformed/truncated datagrams, foreign permits,
oversized-query TCP selection and a delayed UDP reply followed by stalled TCP
without deadline renewal. The native physical fixture adds 100 actual protected
UDP/TCP DNS exchanges under competing capture, with source/query validation,
one-slot admission, two charged attempts and a controlled workload. The native
composition passes in [CI 41671110746](https://github.com/skunkie/warper/actions/runs/41671110746)
at `b8e8c52`, including inspected workload and isolated cleanup evidence.
This is transport evidence; endpoint/lease publication and daemon DNS readiness remain open.

### Address-answer dependency traversal

`warper_service::dns::AddressLookup` consumes correlated IN A/AAAA responses
through the packet adapter. Each step either finishes with `AddressAnswer` or
returns the same owned lookup with a new `question()` for a CNAME dependency.
The parent resolver retains its selected backend, request permit, query budget
and original deadline; a continuation grants no new admission or retry budget.
Ordinary CNAME traversal does not introduce a new domain-policy selection.
Service-binding discovery must additionally validate every dependency against
ADR 0003 before issuing queries or accepting endpoints.

Only Answer records of the requested class at the current canonical owner
contribute. Unrelated Answer, Authority and Additional records create no
routes. Traverse aliases independently of wire record order; reject loops,
conflicting CNAME targets and CNAME/address coexistence. Count aliases across
responses, not per packet. Bound retained path names and unique addresses by
explicit limits with fallible allocation; there are no tasks, timers or I/O.
A continuation is needed only for a successful CNAME-only response. A valid
NODATA or negative response finishes without retrying another backend.

Every address retains its canonical owner, original question, full CNAME path
and monotonic expiry. Expiry is the minimum observed alias/address expiry;
follow-up time never renews an earlier TTL. Unequal RRset TTLs use their minimum,
TTL zero remains zero, and a TTL with the high bit set has zero freshness per
RFC 2181. Duplicate addresses do not consume extra address capacity. Packet
bytes and response codes remain unchanged. The result authorizes neither
positive output nor route publication: endpoint/family/conflict validation,
acknowledged route commits, grace and response handoff remain separate gates.

`TcpTransport::discover_addresses` drives that traversal through its one fixed
selected backend and literal upstream. `AddressDiscoveryLimits` supplies the
alias/address bounds. One root permit remains held through every dependency;
each new TCP query charges the same supplied `QueryBudget` and uses the
original `Request`. Exhaustion, failure, timeout and cancellation discard the
entire discovery. No direct connector, fallback selection or child task exists.
The result retains the original upstream response, complete address analysis
and backend identity for the later route gate. It grants no output permission.

Dependency queries retain the original ID, RD/CD settings and EDNS parameters;
fresh TCP streams correlate each reply independently. Their canonical question
changes to the dependency name/type/class. Refuse synthesis from a response or
a request carrying transaction signatures or non-EDNS Additional records rather
than invalidating authentication or copying unrelated data into a new query.
Responses remain unchanged; synthesis never asserts AA or AD. Address freshness
is stamped immediately after each complete validated exchange.

### Service-binding packet semantics

`Packet::service_bindings(owner, received_at)` provides a bounded, borrowed
view of the reachable owner's IN HTTPS or SVCB Answer RRset. The question's
record type chooses the RRset; the two types never alias one another. Negative
response codes and empty sets remain distinct from CNAME, AliasMode and
ServiceMode. A CNAME cannot coexist with service or address data at its owner.
Conflicting CNAME targets fail. RRset TTLs use the minimum observed TTL, with
zero/high-bit TTL freshness handled as in address traversal.

AliasMode suppresses ServiceMode records in the same RRset and ignores its
parameters. Preserve every AliasMode alternative; a root target is an explicit
unavailable-service indication, never an address lookup of the DNS root.
ServiceMode root targets use the effective owner verbatim, including Attrleaf
and port-prefix labels. Do not strip prefixes or reapply them to alias targets.
Every ServiceMode alternative is retained independent of priority, ALPN or
unknown mandatory keys: this intermediary cannot infer all clients' support.
Validate recognized parameter self-consistency, mandatory-key ordering and
presence, and nonempty address hints. Preserve unknown parameters and original
packet bytes; never rewrite records to conceal an endpoint.

`Packet::related_addresses(owner, received_at, address_limit)` inspects only
that reachable owner's IN Answer/Additional A/AAAA and CNAME data, excluding
Authority and unrelated owners/classes. It retains section provenance, both
families and per-family RRset expiry, rejects ambiguous aliases, and bounds
unique IPs independently of repeated records. A related CNAME is an explicit
continuation, not permission to accept another owner's addresses. Views retain
at most the admitted packet record count of service references; hints borrow
packet storage, and related metadata holds at most two entries per unique IP.
Allocation is fallible. Neither API performs I/O or authorizes route/output
publication. The parent still must validate every dependency's winning domain
policy, traverse all service/address/fallback paths with shared budgets, and
reject disabled families or unrouteable exposed endpoints before handoff.

### Selected service-binding discovery

`TcpTransport::discover_service_bindings` owns one request permit through the
complete HTTPS/SVCB graph. It pins the caller's immutable domain policy and
backend, original deadline/cancellation and attempt budget. It walks all
AliasMode alternatives, CNAMEs and ServiceMode priorities, validates every
non-root dependency/target against the original backend's winning rule before
querying, and never owns a direct connector. Reuse same-question responses
within the request with their original observation times. Missing service or
address RRsets use canonical dependency questions through that same transport.

Retain every hint and reachable related address, and resolve missing target
families. A family disabled for capture rejects any exposed endpoint of that
family. Valid negative address dependencies are final only when that family
has no passed-through hint depending on it; other dependency failures reject
the whole discovery. After a non-root AliasMode transition, include A/AAAA
fallbacks for the final canonical service owner, in addition to every advertised
ServiceMode target. An unavailable root alias never becomes a root lookup.
Ordinary non-SVCB fallback and caches remain within the documented selective
DNS coverage limits, not a general kill switch.

The result retains the original packet, backend, unique endpoint coverage and
bounded per-contribution alias/service/address provenance. Each contribution
references a parent-indexed path arena and uses the minimum original expiry
along that path. `ServiceDiscoveryLimits` supplies alias hops, unique addresses,
IPv6 policy and a work/metadata admission bound (`work_items`, 1–65536). Each
path, queued step, saved response and endpoint contribution charges that bound;
charges are not refunded within a request. This bounds both retained capacity
and repeated graph work independently of unique IP count. The driver yields
between steps so cancellation/deadline and unrelated requests can progress.
There are no child tasks, background queues, timers or automatic retries.
This per-request count bound is not NET-12's global byte/lease admission, and
successful discovery is not permission to publish routes or DNS output.

### Production DNS lease ledger

[`warper_core::dns::lease::Ledger`](../crates/warper-core/src/dns/lease.rs)
implements [ADR 0026](adr/0026-bounded-dns-lease-ledger.md) as a serialized
metadata owner, independent of packet libraries, backends and platform I/O. `QuestionKey` contains the selected
backend and canonical question/class/type; `Contribution` adds an endpoint IP
and original monotonic freshness expiry. Reserve the whole response atomically
before native route mutation. Duplicate IP/path contributions coalesce to their
greatest justified expiry. Same-key renewals share one lease, and distinct
questions consume separate leases even when one address/route is shared.

Construction preallocates lease slots, address owners, fixed hash indexes,
free lists, request blocks, flow slots and drop markers. It charges actual
container capacities, fixed names, optional expiry fields, indexes, free slots,
reserved response/flow handles and one notification waiter against the byte
budget. The configured lease count is an upper bound: construction chooses the
largest fixed capacity that fits the byte budget, or fails if even one cannot
fit. Renewals allocate nothing and update expiry in place; there is no timer
heap. Arc control-header padding is charged conservatively; allocator metadata,
Tokio task/waker allocation and unrelated transport buffers are documented
separate costs, not a whole-process RSS claim. Reusable response caching is
currently absent; positive/negative responses allocate no global cache entries.
Request-local discovery snapshots remain transient data-plane buffers.

Opaque response/flow handles mark their fixed control slot on Drop and notify
one owner waiter. `changes()` issues a single owned waiter so an actor can
await without retaining a ledger borrow or lock. `advance(now)` reclaims those references and expired timed
leases with bounded scans. Every time-bearing operation advances the same
monotonic elapsed clock; backward time is rejected. Live pending output never
expires merely because its deadline passes: cancellation must first destroy
its I/O owner, then drop/cancel the response handle. Synchronous `handoff`
refuses expired requests. Successful handoff checks every address's committed publication,
then atomically exchanges pending references for retention through the greater
of original expiry or `now + grace`, without shortening prior retention.
Dropping/cancelling a response creates no grace lease.

Flows pin address ownership independently of DNS lease keys, so expired names
can be reclaimed while existing flows keep their route/backend. New flows need
committed, referenced coverage. Drop/release frees only that flow reference;
service supervision still enforces actual flow deadlines and joins tasks before
releasing pins. Flow pins never expire solely from a metadata clock update.
Address ownership persists after its final reference until explicit retirement,
preventing a competing backend from reusing an address during kernel cleanup.

Route handles are fenced to this ledger and one address-owner generation.
`confirm_publication` records an externally proven handler/kernel/journal
commit; it performs no platform operation itself. Only then may handoff/flow
admission succeed. `begin_retirement` requires zero pending/timed/flow coverage
and blocks renewal/admission. `finish_retirement` requires external verified
withdrawal; `restore_committed` requires proven unchanged owned state after a
definitive failure. Uncertain native operations remain retiring. These methods
are metadata transitions, not native ACK evidence or permission to replay an
uncertain operation. The service route manager must serialize native intent,
ACK/ownership reconciliation and these transitions; daemon DNS remains disabled
until that integration and NET-10–NET-12 native gates pass.

The owner arms one timer from `next_expiry()` and one coalesced owned
`Changes::wait()` notification. Successful output completion/handoff, explicit
response cancellation, explicit flow release and the first admission closure
also notify this owner. An idle
coordinator must recheck timers and retirement eligibility after these state
changes, even when no guard is dropped. Repeated closure is idempotent and all
notifications share the same single coalesced permit.
Ordinary renewals skip expiry scans until that timestamp is due; releasing a
response checks only its own lease slots. Extending a lease can
leave one early wake, which recomputes the timestamp without adding records.
`mark_uncertain` withdraws metadata publication readiness while retaining all
references, until the service proves the same owned route committed again or
performs checked retirement. `close` rejects new reservations, flow admission
and handoff. After external DNS withdrawal and output/flow cancellation/join,
`finish_drain` clears timed leases; it refuses live references and retains every
address owner for native withdrawal. It does not report completed Disconnect.

### DNS output authorization and delayed completion

[ADR 0027](adr/0027-dns-output-completion.md) separates asynchronous output
authorization from successful-delivery finalization. `begin_output(now,
response)` consumes one pending response and validates its original deadline,
open admission and every committed route before any positive byte is written.
It returns one opaque non-cloneable `lease::Output` carrying the same pending
reference; it allocates no additional slot or timer. The byte budget charges the
larger of the response/output handle layouts for each pending slot.

After complete message delivery, `complete_output(now, output, grace)` exchanges
pending ownership for retention through at least `now + grace`, preserving any
longer original expiry or prior retention. It does not reapply the request
deadline: delivery may already have occurred before completion is observed.
Existing authorized output can also finalize after admission closes or native
publication becomes uncertain. This grants no new I/O permission and never
restores route readiness. Reapplying those checks after delivery would erase
the first-connection grace of an answer the client already received.

The service controller exposes both transitions with its shared monotonic
clock. A writer must keep its pending output owned during partial I/O and
completion processing. Every I/O poll still uses the original request deadline
and cancellation; output authorization never renews them.
Destroy/join failed or cancelled I/O before dropping
the guard; incomplete output creates no grace. After successful delivery,
retain the guard through metadata contention/errors and finalization, rather
than treating a late completion as undelivered cancellation. Session shutdown
still closes admission, destroys/joins output owners, and explicitly drains
retained leases before native cleanup. These are ownership transitions;
actual listener/writer integration, TTL aging and native output gates remain
required before daemon DNS can be enabled.

### Virtual UDP DNS endpoint and native delivery receipts

The packet runtime may own one explicitly configured virtual DNS endpoint.
The concrete adapter is `warper_stack::runtime::udp_dns::{Config, Endpoint,
Datagram}`; `runtime::delivery::{Packet, Receipt}` crosses the native writer
boundary without protocol-library types or native authority.
Its address is reserved for local DNS processing; packets for other ports or
protocols at that address never enter backend selection. UDP datagrams use
smoltcp's checked IP/UDP parsing and serialization, preserve source/destination
and datagram boundaries, reject fragments/extensions and malformed checksums,
and admit at most 1,232 payload bytes. TCP uses the separate local role below;
an allocated UDP handler alone grants no native DNS-route publication authority.

Bound queued, handling and replying datagrams with one retained admission
permit per request. The permit survives reply submission, queued native output,
and cancelled receipt observation until both the output packet and its receipt
owner are released. Charge two MTU-sized adapter input/output payload
reservations per admitted request, in addition to existing runtime packet
queues and service-owned decoded/encoded DNS buffers. Channel/receipt and
allocator metadata require separate global accounting before daemon integration.
There is no waiting admission queue or detached endpoint task.

Reply submission consumes the received datagram and preserves its original
peer. It validates payload size and an original cancellation/deadline request
before bounded queue admission. A receipt acknowledges only the original
native packet writer's successful full-packet write, never runtime enqueueing.
Cancelled receipt waits retain the same accepted operation for resumed join.
The service retains its DNS output guard through that join and finalizes its
advertised-TTL/grace retention after delivery. Known pre-write cancellation or
expiry permits failed-output cancellation; lost/failed/partial native delivery
is uncertain and requires session cleanup, without payload replay.

The native writer clamps each original deadline by its own write deadline and
observes both operation and supervisor cancellation. A tracked reply that
expires/cancels before write is discarded without stopping unrelated packet
traffic. Native I/O/partial-write failures still terminate the packet pump and
surface the primary failure. Runtime quiescence rejects new datagrams while
already admitted work remains owned; forced cancellation drains queued replies.
Its cancellation signal also travels with extracted/queued native output, so
forced cancellation or runtime loss prevents a late native write.
Endpoint consumer loss is a supervised runtime failure. Shutdown still retains
and joins DNS writers, runtime and native packet pump before releasing routes.

### Virtual TCP DNS endpoint

`Runtime::with_dns` reserves the same explicit address for UDP and TCP port 53.
TCP input at that address enters `HostAdapter`'s local DNS role rather than
backend selection. Other TCP ports at the reserved address are rejected. The
UDP-only constructor retains its earlier behavior and does not enable TCP.
Checked TCP/IP parsing still applies before admission; malformed input cannot
create a flow or fall through to a backend.

`Channels::tcp_dns` carries `AcceptedDnsFlow` with `StreamMetadata` containing
the original source/destination tuple and driver ID. It has no backend ID and
no conversion to a backend `CapturedTcp`. Backend acceptance keeps its existing
metadata and queue. Local DNS lifetimes own no backend route selection; both
roles share the same TCP socket, lifetime and payload-buffer admission. Each
accept queue is bounded by the host accept limit, and queued/retained streams
keep their lifetime permits after driver slot retirement. The extra queue is
fixed metadata, not another payload-buffer pool or a total RSS reservation.

Local streams preserve TCP ordering, backpressure and half-close. Quiescence
aborts pending local handshakes and rejects new ones while retaining accepted
streams; forced cancellation terminates both roles and releases storage only
after retained application handles drop. Runtime supervision treats loss of
either DNS consumer as a failure and joins shutdown as for backend consumption.

This is a transport role, not output authorization. `AcceptedStream::flush`
only flushes its duplex buffer. `AcceptedStream::dns_output` supplies a local
DNS-only acknowledgment control; backend streams return a typed unsupported
capability. Begin with the original response request before writing its frame,
then obtain exactly one receipt after the entire frame enters the stream.
Another response cannot begin until that receipt joins successfully. Empty
receipts, overlapping responses and requests beyond 30 seconds are rejected.

The host separately counts accepted duplex bytes, bytes enqueued into the TCP
socket and bytes acknowledged by the peer. A receipt covers the accepted-byte
snapshot, including the frame prefix, rather than a duplex flush or an empty
socket queue before the bridge runs. A live socket's remaining send queue
determines acknowledgment. Reset/closed and timeout checks precede that
calculation: resetting a socket clears its queue without delivering its bytes.
Counters are checked and the control retains fixed metadata, no payload copy.
Control clones retain the host flow lifetime permit after stream/slot retirement.
Each unconsumed receipt also retains that permit, including across cancelled
observations; a definitive joined result or dropping the receipt releases its
reference. Only releasing every stream, control and unconsumed receipt permits
new flow admission. Receipt metadata therefore cannot accumulate outside the
existing flow count by repeatedly closing streams and retaining their handles.
Joined receipts clear their request and progress references; retaining an empty
joined receipt cannot retain heap metadata outside that admission.
After all payload is acknowledged and its receipt joins, dropping a stream
after peer EOF still permits the host bridge to finish the FIN handshake.
Writes remain closed; pending requests, unjoined receipts, unacknowledged data,
reset, cancellation and expiry never acquire that close-only exception.

Dropping or cancelling an observation does not consume the receipt or renew
the original deadline. Original cancellation/expiry and connection termination
are terminal; confirmed acknowledgment remains joinable after later closure.
No task is detached. The caller must retain the positive response's route guard
until acknowledgment or joined connection/native-output cleanup. This primitive
does not hold a route guard itself or enable production daemon DNS. A supervised
routed TCP owner remains required. The controlled native fixture joins
each receipt before starting its conservative workload-wide route grace.

Before retiring a flow, the host attaches the original response request and
connection cancellation receiver to queued DNS TCP packets carrying payload.
Pure TCP ACK/FIN/RST packets carry no DNS answer and retain ordinary transport
output lifetime; stopping the native packet owner still cancels them globally.
Metadata stays
with each packet through the runtime egress queue; no per-segment task, payload
copy or delivery receipt is added. Existing packet count/MTU limits still apply.
Native output checks the original deadline and both cancellation owners before
and during writes. Closing the stream, terminating the flow or a terminal
receipt cancels retained packets even after the host slot is reused. Dropping
an observation alone does not cancel output. Segments already acknowledged
retain their original context rather than acquiring a later response deadline.
Connection handshake/control packets outside a response use ordinary output.
`HostAdapter::take_packet` strips delivery metadata for controlled peers; the
production runtime uses the metadata-preserving output path. Native writer
failure still requires supervised connection/pump cleanup and route retention;
packet cancellation alone cannot prove that a prior write was not delivered.

### Server-side DNS TCP framing

`dispatch::Dispatcher` owns the immutable domain policy, selected transport
groups and preserved direct transports for a DNS service session. Selection is
made once per validated question. Selected groups retain their configured
upstream order and routing mode; only connection/transport failures may try the
next server in that same group. Negative answers, protocol/policy failures,
resource exhaustion and cancellation are final. All attempts and dependency
queries share the original request and query budget. Missing selected groups
fail explicitly and cannot become direct requests.

Unmatched questions use the preserved direct list only in global DNS mode,
with the same ordered transport-only retry rule. Direct replies own no capture
reservation. Split-mode unmatched questions fail without transport I/O.
Disabled IPv6 questions receive the documented local NODATA response, and bad
EDNS versions receive the existing local version/error response. Transport
construction must already have verified physical paths and loop-free literal
upstreams. The dispatcher does not discover resolvers or mutate the host.
Registry storage is bounded to 64 selected groups and 4,096 total configured
upstream transports, checked before constructing its owned session storage.

Linux `server::Workers` admits at most 64 UDP requests/TCP connections before
decoding or starting upstream I/O. UDP deadlines start at datagram receipt;
each TCP frame shares one original read/discovery/output deadline. TCP keeps
its admission while reading subsequent frames and joins clean EOF/FIN. The supervisor
retains and joins every task; a bounded per-slot owner holds routed output or
plain native receipts outside task futures, including across task panic/abort.
Selected positive replies use queued route publication; local, negative and
direct replies use joined native output without capture reservations. Parsed
dispatch failures synthesize SERVFAIL under the original deadline; UDP
pre-output size failure synthesizes TC. TCP native-mailbox admission rejection
currently closes the connection; its parsed SERVFAIL recovery remains open
for Phase 2 acceptance.
Malformed input and expired requests receive no new output deadline.

Stopping rejects admission and cancels original requests. Failed/uncertain
native output stops admission and remains owned until the parent joins native
packet I/O and discards queued frames, then explicitly releases retained slots.
The parent must retain the worker supervisor outside cancellable service work;
object drop is not a native cleanup acknowledgment. Request count admission is
separate from the still-required global transient byte accounting. This worker
pool does not enable daemon DNS or install resolver policy by itself.
Task join success means tasks joined, independently of native cleanup; typed
request/response diagnostics and shutdown failures remain separately available.

On Linux, `tcp_output::TcpOutput::begin_queued` takes an idle
`Connection<AcceptedStream>`, the validated query, a prepared positive reply and
its uncommitted reservation, and the supervised native commit mailbox. It
validates correlation, framing size, timestamps and retention before submission.
The owner retains the connection and response data across interrupted waits.
Only after native commit joins does it age TTLs against the original upstream
observation, acquire the positive output guard and begin the framed write under
the original request. It then joins the TCP acknowledgment receipt before
publishing TTL/grace retention. A successful join permits taking the connection
back for another query or FIN shutdown; no other stage permits stream reuse.

Original request, native commit, framing and acknowledgment failures close the
connection and routing controller. The failed owner retains its output guard
and flow control until its supervisor joins native output and discards queued
frames. Primary and routing-closure failures remain separately inspectable.
There is no automatic retry, direct fallback, detached task or native cleanup
claim on object drop. This owner is a service composition boundary; it does not
enable daemon DNS configurations or install resolver policy by itself.

`dns::connection::Connection` owns one stream and permits one framed read or
write at a time. The service begins each operation with its original deadline
and cancellation owner, then observes it using separately bounded waits.
Partial two-byte prefixes, payload reads and writes retain their exact offsets
across dropped, cancelled or expired observations. Resuming observation never
restarts the frame or renews the operation deadline. Completed operations allow
the next frame on that same stream; pipelined input remains in the stream until
the service begins the next read.

Frame lengths must be at least a DNS header and within the configured packet
limit before payload allocation or decoding. Clean EOF between frames ends the
connection; EOF within a prefix or body, malformed input, I/O failure and an
expired/cancelled original operation make it terminal. Terminal connections
cannot accept new operations or reinterpret remaining bytes as another frame.
Excess/invalid operation submission leaves the existing operation unchanged.
The adapter starts no task and owns no routing permission.

Write completion means only that the owned stream accepted the full framed
message. It does not establish native delivery or authorize release of a
positive response's route guard. Virtual TCP DNS still requires a separately
joined native output barrier and the supervisor must retain routing ownership
through that barrier or uncertain-output cleanup. Stream flush is not such a
barrier.

### Routed UDP reply ownership

`linux::dns_routes::queue` supplies a count-bounded commit mailbox and a
caller-driven native driver with 1–64 retained request slots. One shared
admission permit spans each accepted
command and its result receipt. Dropping a receipt cannot free admission while
native work is still owned; completed results retain admission until consumed
or dropped. Submission never waits or creates an unbounded waiter queue.
An original request accompanies every command, including queued time.

The driver retains exclusive access to the unique native manager and keeps the
active reply sender while awaiting its existing operation. `Driver::new`
borrows that manager; `Driver::owned` takes an owned guard from a supervisor's
`Arc<tokio::sync::Mutex<Manager>>` using immediate `try_lock_owned` admission.
It never creates a lock waiter. The owned driver can live in retained service
state without a borrow of another service field. The private async mutex is
only an exclusive actor-ownership gate; it is not a broad application lock.
The supervisor keeps its Arc and configuration/runtime lease independently of
the driver and all observation futures. Failed construction or driver loss
does not discard the manager or an accepted native task. Recovery after driver
loss still requires closing DNS admission, joining retained native work and
handling lost command receipts; it does not permit replay or automatic success.
`enable_maintenance` applies to either form, rejects invalid/duplicate/active
ownership and leaves the driver retained on error. Dropped/cancelled observation
resumes that same driver/manager state. Receipt waits likewise retain their
receiver on observer cancellation or expiry. Successful native completion
returns the original committed reservation; it performs no packet output.
Abandoned results release their reservation without replaying work. Known
pre-mutation request rejections can finish one command; manager failures close
mailbox admission and surface failure for session cleanup.
The driver's `failure()` retains the primary and closure errors; `join_error()`
retains an additional error encountered while joining failed work. Busy closure
keeps the active owner for resumed observation rather than releasing its guard.

The caller retains the driver, joins accepted work, joins DNS output/flow
owners, then releases the native manager for cleanup. Closing the driver
prevents new submission and drains accepted commands. The mailbox starts no
task. `Driver::with_maintenance` additionally owns the sole ledger change
observer and schedules retirement from the next lease deadline or a coalesced
reference-change notification. An idle driver with no deadline sleeps until a
notification or command arrives. It checks retirement between commits and
gives an already queued command a turn after each retirement. Neither a busy
metadata lock nor a busy native worker renews the maintenance operation's
original deadline. Each attempt has a configured positive timeout of at most
30 seconds and an independent session cancellation signal; observation
cancellation retains the operation and any accepted native job. Maintenance
failure closes admission and retains the same failure/cleanup reporting as
commit failure. Mailbox closure drains accepted commands without waiting for
all retained leases to expire; the supervisor still owns final withdrawal.
While idle, both driver modes poll the retained capture subscription alongside
their command/expiry waits. Dropping an observation preserves the subscription;
observation timeout or cancellation never invalidates it. A relevant native
change or lost notification closes admission and records the typed capture
failure for supervised cleanup. An enabled owner without capture has no capture
subscription to poll; accepting a publication supplies the next subscription.
Native operations continue to verify their own before/after capture state while
the unique owner is outside the driver. Global transient byte admission remains
an incomplete integration gate; the mailbox's request count does not stand in
for its budget.

`dns::prepare::Resolver` composes selected-backend A/AAAA and HTTPS/SVCB
discovery with one whole-response route reservation. It checks the original
domain's winning backend, unsigned synthesis eligibility and open routing
admission before I/O, retains the caller's request deadline and
dependency budget, and never tries direct DNS after selected-backend failure.
Disabled IPv6 IN AAAA requests produce local NODATA without upstream work.
Unsupported EDNS versions produce local BADVERS. Other query types remain
outside this routing preparation operation and return typed unsupported errors.

Complete discovery precedes route reservation. Carry original observation
times into contribution expiry, retain zero TTLs, and reject all contributions
on static/shared-IP conflict or disabled families. Empty endpoint sets retain
their original negative/CNAME response without creating a routing reservation.
Nonempty sets produce an uncommitted reservation: the caller must pass it
through the native coordinator and retain output ownership before replying.
Preparation neither confirms routes nor starts output, and dropping its future
cannot detach discovery work. Its contribution vector is bounded by the
configured endpoint count; full transient admission and daemon scheduling
remain separate, incomplete gates.

`Packet::local_reply` constructs record-free SERVFAIL, explicit TC and local
IN AAAA NODATA replies from a fully validated request. These grant no route
or output authorization. Preserve ID, question case, RD and CD; set RA for the
recursive service and clear AA/AD. Reject signed requests and non-EDNS
Additional records rather than copying authentication or unrelated data.
Disabled-family NODATA is available only for IN AAAA. No upstream query is
needed to construct it.

Local replies obey the smaller of configured wire capacity, the virtual UDP
1232-byte ceiling and the client's EDNS capacity (512 without EDNS; clamp
smaller advertisements to 512). An EDNS request receives a fresh version-zero
OPT, echoes DO, advertises server capacity and omits unsupported options and
reserved flags. Unsupported EDNS versions produce BADVERS, ahead of the
requested local reply kind. Encode the complete empty reply before setting
intentional TC; never expose a partially encoded address set. These semantics
follow [RFC 1035 section 4.1.1](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1)
and [RFC 6891 section 6](https://datatracker.ietf.org/doc/html/rfc6891#section-6).
The caller retains admission and joins native output; this primitive performs
no I/O and does not enable daemon DNS.

Shared packet-runtime construction obtains an opaque native seed before
mutation. Linux retains nonblocking `getrandom` through rustix. macOS uses
the already locked `getrandom` 0.4.3 library's `getentropy(2)` backend for one
eight-byte seed; errors remain typed and redacted with no weaker fallback or
configured seed. This portable primitive enables controlled packet-runtime
tests on macOS; it grants no native macOS interface/helper capability.

`warper_service::dns::output::UdpOutput` consumes one validated routed reply,
its pending route reservation and the original virtual datagram. The caller
must have completed address/service discovery and reserved the complete
reachable endpoint set for that reply. Before submission, correlate the reply
ID and canonical question against the incoming query envelope, age wire TTLs
from the original upstream observation, enforce UDP size, and authorize the
complete committed route set. Preparation/submission failures start no I/O.
The routed reply carries the UDP payload limit derived from its validated
original query. Validate it against the virtual endpoint ceiling and enforce
it during encoding, including the 512-byte default without EDNS. An oversized
positive reply leaves the datagram available for a record-free TC reply.
Preparation/authorization leaves the caller's original datagram available for
a bounded SERVFAIL/TC response. Direct `begin` takes it when packet submission begins;
cancellation/expiry/closed output at that point cannot admit a fallback reply.

On Linux, `begin_queued` also owns native publication through the bounded
mailbox. Validate correlation, size, timestamps and retention arithmetic before
queue admission; validation encoding does not subtract elapsed TTL time.
After admission, the same owner retains the datagram, original operation and
commit receipt. Wait for the committed reservation before starting packet
output, then age TTLs once from the original observation. Observation loss
preserves both phases and cannot replay either submission. The supervisor
must retain/run the native driver until all accepted work joins, including
when output observation ends. A joined commit rejection or pre-output error
permits `take_unsubmitted_datagram` for a bounded negative reply under the
original request; it cannot extract input while accepted work remains pending.
The driver's failure/cleanup report remains independently required.

After submission, retain the output guard and original native receipt in the
same owner. Cancelled/dropped observation resumes that same operation. Native
success changes to metadata completion without awaiting again or replaying
payload. Retry busy metadata admission; observer expiry cannot erase delivered
bytes or pending coverage. Finalize with the larger of configured grace and
the largest advertised remaining TTL, measured from successful completion
observation. Known pre-write cancellation/expiry destroys the completed I/O
ownership before releasing its output reference. Uncertain delivery or a
non-retryable metadata failure closes routing admission, preserves the primary
error alongside closure errors and retains the guard for supervised cleanup.
The caller retains/joins this owner; it spawns no background task.

This is route/output composition. Upstream discovery, coordinator scheduling,
global transient admission, virtual TCP and daemon/resolver wiring still need
their complete production integration and native acceptance.

### DNS response TTL aging

Discovery retains the original response's observation timestamp, separately
from dependency observations. Immediately before gated output encoding, age
the owned response by the elapsed time since that observation. Subtract the
ceiling of elapsed seconds from each Answer, Authority and ordinary Additional
record TTL, saturating at zero. A high-bit TTL becomes zero, as for discovery
expiry. This conservative rounding cannot advertise a cache lifetime beyond
the original expiry. Zero remains zero; route grace never changes a wire TTL.
EDNS flags/extended RCODE and record data (including RRSIG Original TTL) are
not TTL counters. Preserve them and existing header flags without asserting
new authority or authentication. Reject signed-message mutation (TSIG/SIG(0)).
These boundaries follow [RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8),
[RFC 6891 section 6.1.3](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.3)
and [RFC 4035 section 5.3](https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3).

Aging mutates existing bounded packet storage without copying a decoded
message. The caller needs exclusive packet ownership; service discovery's
shared observations are released on return. Aging returns the largest remaining
ordinary record TTL. For successful delivery, finalize the output guard with
the maximum of that duration and configured route grace. This conservatively
retains all response routes through the advertised cache lifetimes, including
time spent encoding/writing and delayed completion observation. Pending output
references protect them until that finalization. This may retain some routes
longer than their individual dependency TTLs; it never renews DNS cache data.
Aging alone does not prove the native listener/output gate.

### Serialized Linux DNS route coordinator

The service's Linux DNS route coordinator owns one original TUN owner and at
most one accepted commit or retirement. Construction validates the runtime's
selector identity, preallocates bounded route scratch and endpoint exclusions,
and validates their byte reservation before taking native ownership. The caller
supplies every preserved physical backend/direct-DNS endpoint exclusion. The
reported reservation covers coordinator-owned structures and capacities;
existing native-owner, allocator and admitted-worker overhead remain separately
bounded. No queue or task is spawned for the coordinator itself.

A commit takes the complete pending response. Validate every address's native
capture eligibility, backend, family and exclusion before the first mutation.
Publish/verify each route with
the retained native worker, then apply its metadata commit exactly once after
joining the worker. A known native result waiting for metadata admission cannot
be replayed. Only the complete successful set returns its pending response for
pre-I/O output authorization. Cancellation/deadline before another native step
fails that response without giving output permission; unreferenced additions
remain owned until checked retirement. Active-flow references survive that
rollback.

Caller observation uses a separate wait request. Cancelling/dropping a wait
leaves the accepted operation, response, native job and original device retained
for resumed observation or supervised shutdown. The original operation request
still bounds each native step. Retirement checks zero references before moving
the owner into a worker, and releases metadata only after joined native absence
or retained-static-coverage proof. Definitively unmutated rejected retirements
remain a bounded deferred candidate for the next maintenance attempt.
IPv4 addresses rejected before publication still receive checked-absence
retirement, so an unsupported answer cannot strand unreferenced metadata.

An unchanged successful journal revision around an operation proves no intent
or mutation was attempted. Only typed pre-mutation rejections with a quiet
retained capture monitor may leave the session usable. Post-intent/uncertain
failure, lost ownership or invalid capture closes routing admission and retains
the owner for whole-session cleanup. Preserve the primary error alongside
capture-validation/closure failures. Native ownership cannot be released while
an accepted operation or worker remains. Caller supervision still owns expiry
notifications, DNS output tasks, packet/flow draining and actual daemon wiring.

### Live route selection and TCP flow pins

`warper_core::routing::FlowSelector` separates immutable static policy from
live mapping observation and atomic flow selection. `static_policy()` returns
the original capture snapshot; `lookup()` observes a mapping without granting
flow ownership. `select_flow()` returns a `Selection` containing the backend
and, for DNS-owned destinations, an owned lease flow pin. The static `Policy`
implements this interface without a DNS pin. Core selection knows no backend
implementations or platform operations.

`HostAdapter::with_selector` and `Runtime::with_selector` use that interface.
The first SYN acquires its selection before a listener becomes usable; errors
release the selection immediately. Retransmissions and existing-flow packets
reuse their original metadata and reference. The selection remains inside the
shared driver/application lifetime until both are destroyed, including queued
or retained accepted streams after runtime cancellation. Temporary selector
contention/unready ownership rejects admission without choosing another route;
selector failure terminates the runtime and reaches its supervisor.

A runtime publication observes the same selector and static snapshot used by
admission. Its live mapping observation does not acquire a flow pin and grants
no kernel authority. The service must publish that mapping before native route
addition and retain it through verified withdrawal. Runtime-created publication
still establishes allocated mapping/ingress ownership, not native readiness.

`warper_service::dns::routes::Controller` supplies the live selector using one
shared core ledger and immutable static snapshot. Each synchronous operation
uses `try_lock`; no caller receives a mutex guard or holds it across native
I/O/await. Busy selection drops the new SYN for bounded TCP retry; poisoned
state is fatal and cannot select a static/direct alternative. Selection and
lease-pin acquisition run under the same lock as retirement, closing the
SYN/retirement race. Static winner conflicts and static-mode coverage gaps fail
whole-response reservation before metadata changes. A committed static winner
can continue serving after its DNS metadata expires; dynamic destinations
without protected references remain unready until checked retirement.

The wrapper preallocates duplicate-address scratch and charges its own storage,
control header and runtime selector handles before constructing the ledger.
Its `reserved_bytes()` includes that overhead. One shared Tokio monotonic origin
converts discovery expiry/deadline instants to core elapsed durations; already
expired freshness remains zero. Native endpoint exclusions, ACK/journal proofs,
DNS output completion and the service readiness gate remain separate required
composition. The controller never creates kernel routes or claims them ready.

### Incremental native IPv4 capture publication

The retained Linux TUN owner may extend its capture batch with one IPv4 host
whose backend mapping is already observable in the same live runtime. The
caller retains the DNS reservation and serializes publication with retirement;
it must exclude physical backend and direct DNS endpoints before calling. This
operation grants no DNS output permission and does not confirm ledger state.

Verify the prior committed batch, device, rules and quiet change subscription
before mutation. Existing owned coverage may be reused only after full native
verification and a matching live backend observation. For a new host, journal
the union of all old keys and the new /32 as Routing before an exclusive add.
Await its correlated ACK without replay, subscribe afresh and verify the full
union, device and live mapping before committing Captured. Preserve the runtime
identity and full intent on failure. Any post-intent failure is sticky; uncertain
delivery never authorizes another add. The same runtime mapping stays retained
until checked withdrawal, including active TCP pins.

This increment retains WTUN version four's bounded 4096-key snapshot and its
conservative abandoned-owner recovery. Whole-batch withdrawal still requires
runtime quiescence, drained packet work and zero retained flows. Per-address
retirement, larger native admission aligned with configured DNS capacity, and
supervised DNS session integration remain required before enabling daemon DNS.
This operation refreshes the capture monitor, not existing protected socket
proofs. Their narrowly scoped continuity policy is defined below; it needs
separate native acceptance before live DNS session integration.

### Physical socket continuity across capture host updates

After physical path preparation, each protected TCP/UDP association subscribes
with its immutable peer/source/gateway and excluded capture interface. It may
discard only a canonical IPv4 /32 main-table static unicast link-scope route
notification on that interface, with the capture metric's high bit and no
unknown attributes, gateway, preferred source or route flags. The host address
must differ from the physical peer, source and gateway. This narrow exception
does not authorize mutation or trust an ownership claim; the disjoint host
route cannot select this socket's verified physical tuple or next hop.

All other changes retain the existing fail-closed behavior, including rule,
link and address changes, broader routes, another interface, and routes to any
physical path address. Parse every message and trailing byte before discarding
a datagram. Mixed batches, truncation, overflow, unexpected senders and malformed
input still invalidate. A check/poll consumes at most 64 datagrams of at most
64 messages each before declaring uncertainty, so an unrelated notification
flood cannot stall forwarding or be mistaken for a proven empty queue. No
socket is reopened, payload replayed, monitor task spawned or kernel path proof
replaced. Connector preparation remains globally conservative.

### Individual native DNS host retirement

`FlowSelector::verify_retirement` verifies the same live address owner used for
SYN admission: matching backend, Retiring state and zero lease/output/flow
references. Static-only selectors reject this operation. A runtime publication
forwards the check to its own selector while the runtime mapping remains
published; quiescent admission is allowed, but a stopped runtime is not proof.
The service serializes retirement, renewal and native work and cannot restore
or release that owner while its native worker is still running.

The retained TUN owner may withdraw an individual /32 after this check without
quiescing unrelated flows. Verify the same runtime, full committed batch, device
and quiet subscription first. Static /32 coverage is preserved. A missing
recorded host requires checked absence of its exact owned route key. Otherwise,
journal RoutesRetiring with the complete old batch before removing the one
exact owned key. Check retirement again around the deletion; require its ACK,
fresh absence, verified remaining batch and device before committing the smaller
Captured batch, or Enabled with no capture batch when the final key is gone.
Keep the live mapping until the caller completes ledger retirement after the
joined native result. Repeating a successful native withdrawal before releasing
that owner is safe and does not delete another key.

Failure after intent retains the full old batch and sticky failure. Do not retry
an uncertain deletion or silently restore availability; supervised whole-batch
drain/withdrawal or abandoned-owner reconciliation remains necessary. A changed
or foreign route is preserved. This operation grants no DNS output permission.
