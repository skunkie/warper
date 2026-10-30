<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Canonical Configuration and CLI Contract

Status: offline YAML/schema/semantic validation is implemented; the CLI and
runtime preflight remain unimplemented.
Core implements offline path resolution and injectable invoking-account
validation in `crates/warper-core/src/configuration/paths.rs`, with Unix OS
account lookup in `crates/warper-config/src/identity.rs`. Bounded YAML decoding
is implemented in `warper-config::yaml`, following
[ADR 0006](adr/0006-bounded-yaml-decoding.md). `warper-config::schema::Config::parse`
applies the offline contract with injected paths and an explicit platform. CLI
integration remains unimplemented. This document defines the initial schema.
Update it, its examples, and fixtures together when a justified decision changes
the contract.

## 1. Parsing and Path Rules

- Accept one UTF-8 YAML document containing a mapping. Reject unknown keys at every level, duplicate mapping keys, null values, custom tags, anchors/aliases, multiple documents, and wrong scalar types. A boolean must be a boolean; integer fields do not accept strings, floats, or booleans. Secrets and addresses are strings. An omitted optional value uses its documented default.
- Do not interpolate environment variables or execute substitutions. Treat `$`, backticks, and similar characters literally, including in passwords.
- Import, offline validation, and foreground diagnostics use `--config PATH` or the invoking user's `~/.warp.yaml`. The installed service uses an approved managed snapshot, never a home-directory search or sudo environment at boot. With elevated sudo, resolve and cross-check `SUDO_UID`/`SUDO_USER`; reject inconsistent identity information. With neither set, use the current account. Define this lookup through an injectable identity provider for offline tests.
- Expand `~` and `~/` to the invoking user's home, including under sudo; reject `~otheruser`. Resolve relative paths inside YAML against the configuration file's directory. Resolve a relative `--config` against the original working directory. Do not change identity/home semantics for privilege preflight.
- Resolve accounts from OS records rather than `HOME`. Only an elevated root caller uses sudo identity fields; an ordinary user cannot select another account through those variables. Reject empty paths and embedded NUL bytes. Resolution is lexical: preserve symlinks and `..`, and do not require referenced files to exist during offline validation.
- File-valued secrets are UTF-8, nonempty, and limited to 16 KiB; remove one final LF or CRLF, preserving all other characters. At runtime, require a regular file, owned by the invoking user or root, without group/other permissions. Read with checks that avoid a check/open race; never print its contents.
- `check-config` performs parsing, normalization, path resolution, and semantic validation without opening credential/trust files, making network requests, or changing host state. Import reads selected credential/trust material in the ordinary-user native client. Service preflight reads only its protected managed material, validates keys, detects host conflicts, and checks privileges; a control request never redirects privileged file reads.

### Decoder boundary

The YAML decoder is a separate stage from schema and semantic validation.
Decoding success alone never authorizes import, route publication, or service
startup. Accept at most 1 MiB of UTF-8 source, 65,536 value/key nodes, and value
depth 16 (the root is depth zero). These fixed admission limits also apply to
offline input; configuration fields cannot raise them. Check source size before
UTF-8 validation or parser construction. Third-party scanner/container overhead
is additional to source size; these bounds are not a whole-process memory cap.

Use YAML 1.2 core scalar resolution: quoted and block scalars are strings;
unquoted booleans, integers, and floats retain their types. Preserve integer
spelling until field-specific range checks, so overflow cannot turn an integer
into a string or float. Core `str`, `bool`, `int`, `float`, `map`, and `seq` tags
may specify the corresponding type; reject custom/unsupported tags, mismatched
tags, and all null values. The non-specific `!` tag preserves scalar strings
or the corresponding container kind. Mapping keys must be strings. Do not
expand merge keys; the schema rejects them as unknown fields.

Decoder errors contain a stable category, reason, and bounded field path.
Use only recognized schema key names in decoder paths; redact other keys as
`[key]`. Never retain a scanner's source excerpt in an error, or expose values
through decoded-value `Debug` output. Schema validation will additionally
reject unknown keys, missing fields, and type/semantic violations. Its fixture
expectations remain distinct from decoder-only fixture checks.

### Offline schema validation

The validator receives an explicit Linux/macOS target and prepared source paths;
it does not infer privileges, read files, resolve hosts, or inspect interfaces.
Successful offline validation does not establish runtime capability, trust,
cryptographic validity, endpoint reachability, or readiness to mutate host state.
Unknown key names use the decoder's redacted `[key]` path convention, including
migration diagnostics. Required fields and known invalid fields retain their
exact schema paths.

Normalize configured domains and endpoint hostnames with idna 1.1.0 UTS 46,
nontransitional processing, STD3 ASCII rules, first/last hyphen checks, and DNS
length verification. Normalize case and Unicode dot equivalents before removing
one terminal dot; reject empty/root names, empty labels, wildcards, underscores,
and IP literals as domain rules. This configuration profile is not used to
validate wire-format DNS names such as `_service._tcp.example.test`.

Reject unspecified, multicast, and IPv4 broadcast DNS addresses. TUN and
WireGuard local addresses additionally exclude loopback and IPv6 link-local.
These are offline safety checks; discovered collisions and routing loops remain
preflight work. Unsigned numeric schema fields accept decimal, hexadecimal, and
octal YAML integers within their target range, including a leading plus on
decimal values; strings, floats, negative values, and overflow are invalid.

## 2. Root and Tunnel Fields

| Key | Type | Required/default | Rules |
| --- | --- | --- | --- |
| `tunnel` | mapping | Required | Fields below |
| `protocols` | sequence of mappings | Required, nonempty | Backend entries below |
| `ipv6` | boolean | `false` | Enables captured IPv6 data and AAAA route discovery; does not disable physical host IPv6 |
| `dns` | mapping | `{}` | Only `direct_upstreams`, described below |
| `timeouts` | mapping | `{}` | Millisecond fields in section 5 |
| `limits` | mapping | `{}` | Integer budgets in section 5 |
| `service` | mapping | `{}` | Only `autoconnect`, a boolean defaulting to false; enables connection intent on a fresh boot after recovery |

| `tunnel` key | Type | Required/default | Rules |
| --- | --- | --- | --- |
| `name` | string | Omitted: OS-selected name | Linux: nonempty ASCII interface name, at most 15 bytes, no whitespace, NUL, `/`, or `:`, and not `.` or `..`; macOS: `utun` followed by digits. Validate availability at runtime; use the actual returned identity |
| `ip` | string | Required | Bare unicast IPv4 address for local TUN DNS; reject CIDR syntax, unspecified, loopback, broadcast, and multicast addresses |
| `ipv6_address` | string | Omitted | Required when `ipv6: true`, forbidden when false; bare unicast IPv6 address, not unspecified, loopback, multicast, or link-local |
| `serve_dns` | boolean | `false` | False: split DNS for configured domains; true: forward unmatched queries through direct upstreams |
| `mtu` | integer | `1280` | Schema range 1280–9000; the initial host default is 1280; the experimental TCP link supports up to 1500 with downward PMTU to 1280, while UDP/reassembly remain capped at 1280; reject unsupported adapter/platform combinations before mutation |

Assign tunnel addresses as local host addresses (`/32` and `/128` or the platform's equivalent), without automatically capturing an entire surrounding subnet. Explicit DNS reachability is the driver's responsibility. Reject address collisions with discovered host state during preflight.

`dns.direct_upstreams` is a sequence of distinct bare IP strings, default `[]`. Port is fixed at 53 in the initial schema. Explicit entries replace platform-discovered direct resolvers for bootstrap and unmatched forwarding. Empty means discover actual physical upstreams before mutation. Reject syntactically unsafe addresses and, at runtime, loop-producing choices such as the TUN DNS endpoint or a stub that routes back to it. This list never replaces a selected backend's DNS on failure.

## 3. Backend Entries and Routing

Each `protocols` item has exactly one of `ssh`, `socks5`, or `wireguard`, whose value is a mapping. Its only other allowed sibling is optional `id`. Common routing keys belong inside the backend mapping, preserving the Go YAML shape.

| Key | Type | Required/default | Rules |
| --- | --- | --- | --- |
| `id` (item sibling) | string | `<type>-<one-based-list-position>` | Match `[a-z][a-z0-9_-]{0,63}`; unique across entries. Use explicit IDs for stable naming across reordering |
| `domains` | sequence of strings | `[]` | Exact or subdomain rules; normalize case, one terminal dot, and IDNA to ASCII; reject invalid names, wildcards, root/empty names, IP literals, and duplicate normalized assignments |
| `ips` | sequence of strings | `[]` | Canonical IPv4/IPv6 CIDRs with no host bits; reject duplicates and identical cross-backend assignments. Different-length overlaps follow longest prefix |
| `dns` | sequence of strings | `[]` | Bare IP addresses, fixed port 53; nonempty if `domains` is nonempty. Reject unspecified/multicast addresses and duplicates; check backend family support |
| `routing_mode` | string enum | `static` if `ips` is nonempty, otherwise `dynamic` | Only `static`, `dynamic`, or `mixed` |

- `static` requires nonempty `ips`; domains may exist and use the selected DNS, but never add DNS routes.
- `dynamic` requires nonempty `domains` and empty `ips`.
- `mixed` requires both nonempty `ips` and `domains` and enables both route sources.
- Reject an entry with neither domains nor CIDRs. Reject IPv6 capture CIDRs with `ipv6: false`. Preserve global domain precedence and shared-IP conflict policy from `docs/implementation-plan.md` section 4.3.
- Backend DNS servers are attempted in listed order within one total DNS request deadline. Retry connection/transport failure against another server of the same backend; valid negative answers are final. Never cross to another backend or direct upstreams. Apply the same order/deadline rule within the direct-upstream list.
- For configuration domain names, record the chosen IDNA implementation/profile in the stack decision and lock normalization fixtures before production use. Wire-format DNS names remain subject to DNS label validation; non-hostname record names such as `_service._tcp.example.com` must remain queryable and match the configured suffix.
- Matched HTTPS/SVCB discovery follows [the DNS endpoint policy](adr/0003-dns-endpoint-routing.md). All non-root alias and effective target names must match configured domains whose winning rule selects the original backend, including names outside the original suffix. Add such names to that backend's `domains` explicitly. An unmatched target, a rule selecting another backend, malformed data, or an unrouteable endpoint yields SERVFAIL with a redacted reason; never send dependent queries through direct DNS or silently learn new system resolver domains. This restriction keeps follow-up client queries on the same backend in split DNS mode.
- Resolve service-binding endpoint A/AAAA records through that backend, include usable IP hints and related Additional records in the routing transaction, and preserve DNS wire semantics. All exposed endpoint families must be enabled and supported. If `ipv6: false` and a matched response exposes an IPv6 endpoint hint/related address, fail that service-binding response with SERVFAIL instead of passing it through or rewriting signed records. Static mode may release service endpoints only when all their addresses are covered by that backend's winning static routes; it never creates dynamic routes.

## 4. Backend-Specific Fields

### SSH

| Key | Type | Required/default | Rules |
| --- | --- | --- | --- |
| `host` | string | Required | DNS hostname or bare IP, with no port; use `port` separately |
| `port` | integer | `22` | 1–65535 |
| `user` | string | Required | Nonempty |
| `password` | string | Omitted | Nonempty secret; authentication alternatives below |
| `password_file` | path string | Omitted | File-valued password |
| `private_key_file` | path string | Omitted | Local OpenSSH-compatible private key; supported formats must be recorded/tested |
| `private_key_passphrase_file` | path string | Omitted | Only with `private_key_file`; required at runtime if the key is encrypted |
| `known_hosts` | path string | `~/.ssh/known_hosts` unless a pin is supplied | Verify the exact host/port; missing trust or mismatched key fails before authentication |
| `pinned_host_key_sha256` | string | Omitted | `SHA256:` plus unpadded Base64 encoding of a 32-byte host-key fingerprint |

Require exactly one of `password`, `password_file`, or `private_key_file`. If a fingerprint pin is supplied, do not apply the default known-hosts path; reject an explicitly supplied `known_hosts` together with a pin. Do not prompt for or automatically accept trust during unattended operation. SSH agent authentication and multiple authentication fallback methods are deferred.

### SOCKS5

| Key | Type | Required/default | Rules |
| --- | --- | --- | --- |
| `host` | string | Required | `hostname:port`, `IPv4:port`, or `[IPv6]:port`; port 1–65535 |
| `user` | string | Omitted | Nonempty, at most 255 UTF-8 bytes when set |
| `password` | string | Omitted | Nonempty, at most 255 UTF-8 bytes; mutually exclusive with `password_file` |
| `password_file` | path string | Omitted | Runtime value must satisfy the same password length limit |

Allow either no authentication fields or `user` plus exactly one password source. Reject partial credentials instead of silently ignoring them. TCP is the required initial capability; no UDP enablement key is reserved until that extension has a tested contract.

### WireGuard

| Key | Type | Required/default | Rules |
| --- | --- | --- | --- |
| `private_key` | string | Required | Standard padded Base64 decoding to 32 bytes; secret |
| `peer_public_key` | string | Required | Standard padded Base64 decoding to 32 bytes; reject an all-zero peer key |
| `preshared_key` | string | Omitted | Optional Base64 32-byte secret |
| `endpoint` | string | Required | Same host/port syntax as SOCKS5; physical UDP transport |
| `address` | string | Required | Bare unicast tunnel IP; retain original single-address key |
| `extra_addresses` | sequence of strings | `[]` | Additional bare unicast tunnel addresses; no duplicates, initially at most one address per family including `address` |
| `persistent_keepalive_secs` | integer | `5` | 0–65535; zero disables it. Default preserves the original implementation |
| `inner_mtu` | integer | Omitted: derived at runtime | 576–9000 for IPv4-only, minimum 1280 when IPv6 is enabled for this backend; must fit the outer path after overhead |

Effective data address families come from `address` plus `extra_addresses`. Static capture CIDRs and tunneled DNS must use available inner families. Dynamic/mixed discovery requires an IPv4 inner address, and also an IPv6 inner address when global `ipv6` is true. Static-only IPv4 backends may coexist with global IPv6 support. Physical endpoint address families are independent of captured data families. Parse/length checks do not replace runtime cryptographic validation and a real peer handshake.

## 5. Timeouts and Resource Defaults

All values below are positive integers; none accepts an unlimited sentinel. Reject zero and integer overflow; `persistent_keepalive_secs: 0` is the explicit exception in the backend schema above. Treat these as initial configurable budgets, not measured performance promises; change defaults only with documentation and tests.

| `timeouts` key | Default (ms) | Meaning |
| --- | --- | --- |
| `connect_ms` | 10000 | One TCP/backend establishment attempt |
| `dns_ms` | 5000 | Whole request, including same-backend retries and route commit |
| `dns_route_grace_ms` | 30000 | Minimum route retention after a positive answer is handed to the host; independent of DNS cache TTL |
| `tcp_idle_ms` | 300000 | Established TCP with no payload progress |
| `udp_idle_ms` | 60000 | UDP flow without datagrams |
| `flow_max_age_ms` | 86400000 | Absolute captured-flow lifetime; bounds retained route ownership even for active flows |
| `shutdown_ms` | 10000 | Total graceful drain budget before cancellation/cleanup |
| `control_ms` | 5000 | One local request/acceptance exchange, separate from an accepted operation's completion |

| `limits` key | Default | Meaning |
| --- | --- | --- |
| `max_tcp_flows` | 1024 | Admitted TCP flows |
| `max_udp_flows` | 1024 | Admitted UDP flows |
| `max_dns_requests` | 128 | Admitted client DNS requests; internal dependencies remain charged to their parent |
| `max_dns_alias_hops` | 8 | Maximum combined CNAME and service-binding alias transitions along one dependency path; detect loops as well |
| `max_dns_dependency_queries` | 32 | Total upstream query attempts, including retries and endpoint lookups, per client request |
| `max_dns_endpoint_addresses` | 64 | Unique endpoint IPs retained/validated per client response, counting hints and related addresses |
| `max_dns_lease_entries` | 32768 | Global logical DNS lease entries, including pending reservations; independent of unique route count |
| `max_dns_cache_entries` | 4096 | Global reusable positive/negative cache entries, if caching is implemented |
| `max_dns_state_bytes_total` | 16777216 | Retained DNS lease/cache/provenance/name/index/timer storage, including reserved capacity |
| `max_route_entries` | 16384 | Managed capture entries, including static entries; reject oversized static config |
| `max_pending_route_ops` | 256 | Queued route transactions |
| `max_queued_datagrams_per_flow` | 64 | Per-flow pending datagrams |
| `max_buffered_bytes_total` | 67108864 | Aggregate warper-controlled data-plane queue/buffer budget; account for adapter buffers and document any library-owned overhead |
| `max_log_entries` | 2000 | UI log ring size |
| `max_log_message_bytes` | 4096 | Maximum retained/rendered log message length |
| `max_control_clients` | 16 | Concurrent authenticated local clients |
| `max_control_message_bytes` | 1048576 | Maximum encoded logical control message/configuration import |
| `max_control_inflight_requests` | 64 | Pending control requests across clients |
| `max_control_events_per_client` | 256 | Subscriber queue limit before disconnect/resynchronization |
| `max_control_buffered_bytes_total` | 8388608 | Aggregate control buffers, separate from data-plane buffers |
| `max_control_operations` | 256 | Retained operation records; active operations are not silently evicted |

Do not evict an active committed route to admit a new one. DNS/route queue exhaustion returns a defined failure (SERVFAIL for a parsed DNS request); new TCP admission fails, excess UDP datagrams are dropped with a counter, and UI logs use a bounded drop-oldest ring. TCP buffers use backpressure within budgets. Charge one allocation to one budget owner; account for actual capacities rather than advertised payload length. Set and document additional stack-internal limits in the post-feasibility contracts.

DNS answers retain their original or normally aged TTLs. Zero-TTL answers are never cached for reuse, and `dns_route_grace_ms` never raises a wire/cache TTL. For each exposed address contribution, retain its route until at least `handoff_time + max(remaining_dependency_ttl_ms, dns_route_grace_ms)`, then also honor active-flow references. Use the minimum remaining TTL along that contribution's alias/service/address path; a hint uses its containing service record's path. A response reference pins all required routes while output is queued; before handoff, recheck/renew coverage atomically, then exchange that reference for the timed lease without a gap. Concurrent answers may extend retention, while failed/cancelled responses add no new grace lease. A connection arriving only after all lease/grace/flow references expire remains outside the coverage guarantee.

Count each actual upstream attempt against `max_dns_dependency_queries`, including same-server retries. Coalesce duplicate dependencies; reject loops, exhausted budgets, or an incomplete endpoint set with SERVFAIL. Never drop unprocessed records merely to fit the budget and then forward their addresses. Positive-cache entries remain subject to DNS TTL even while routing ownership is retained. Charge transient buffers to the data-plane budget and retained DNS buffers to the DNS-state budget as defined below.

Do not make an admitted request wait for a fresh client-admission slot to run its own dependencies. Specify bounded upstream concurrency and cancellation under the parent's deadline in the implementation contracts; include dependency buffers in the existing global accounting.

### Retained DNS State Admission

Enforce the lease-entry, cache-entry, and retained-byte limits across all
backends, independently of concurrent requests and unique kernel routes.
A logical lease key is `(backend_id, normalized_qname, qtype, qclass,
endpoint_ip)`. Coalesce duplicate paths for that key using their greatest
justified route-retention deadline. Successful renewal updates the existing
entry without shortening earlier committed retention; it does not append
another name/lease/timer record for every response. Distinct names still
consume distinct logical lease entries even when they share one IP/route.

Reserve capacity for every new lease/provenance record before kernel mutation
and before releasing an answer. Pending reservations count immediately, and
failed/cancelled transactions release only their own charges. Bound backing
container capacities, expiry indexes, stale timer nodes, and optional
diagnostic provenance as well as record payloads. Update expiry in place or
compact stale timer nodes within the same byte budget; renewal cannot grow
an unbounded heap. Document conservative allocation accounting and any
allocator/library overhead separately; this is not a whole-process RSS cap.

Evict expired leases and expired/LRU cache records when appropriate. Cache
eviction does not withdraw a committed routing lease, grace, or flow
reference. A new response may skip optional cache insertion if cache capacity
is exhausted; it must still reserve every routing lease it needs. If protected
lease state cannot fit after safe reclamation, return SERVFAIL without
publishing new endpoints or evicting unexpired leases/active-flow ownership.
An existing-key renewal can proceed at the count limit when it needs no
additional state and all other budgets/deadlines permit it.

Reusable cache keys include backend identity as well as question/class/type;
positive and negative entries share the cache budget. TTL-zero answers never
enter the reusable cache. Charge each allocation once: retained cache wire
buffers belong to DNS state, while transient request/packet buffers use their
existing buffer budget. Transfer budget ownership atomically when retaining
a buffer; do not leave an unaccounted duplicate.

## 6. Desktop, Service, and Diagnostic CLI

Configuration errors include a stable category, field path, and actionable
reason; never print secrets or raw configuration excerpts. The
[service/client contract](service-and-client.md) defines the primary Tauri
GUI and managed bundle. Closing the GUI leaves the service running.

Required command forms, when the CLI/service are introduced:

```text
warper status [--json]
warper up [--wait-ms N | --no-wait]
warper down [--wait-ms N | --no-wait]
warper routes [--json]
warper connections [--json]
warper logs [--follow]
warper explain NAME [--json]
warper check-config [--config PATH]
warper config install [--config PATH]
warper recover [--inspect]
warper --help
warper --version
warperd service
warperd run [--config PATH] [--headless] [--verbose] [--debug]
warperd recover [--inspect]
```

Bare `warper` shows status; it never starts an engine or terminal UI. Client
`--debug`, when provided, changes client logging only. `warperd run` is an
explicit privileged foreground diagnostic mode sharing the service lock;
`--headless`/`--verbose` are accepted legacy aliases there. Its signals stop
that foreground runtime. GUI/CLI exit never implicitly disconnects.

`up`/`down` return an operation ID and wait for completion by default, with
`--wait-ms` default 30000. Wait expiry exits 1 and prints the operation ID;
the accepted service operation continues. `--no-wait` exits 0 on acceptance
without claiming Connected/Disconnected. Retries reuse operation identity
and configuration generation instead of creating another TUN.

`check-config` validates without IPC, file-secret reads, or network changes.
Import/configuration installation is a separate authorized operation. The
native client reads selected files with user access and submits normalized
data/material for protected atomic storage. The service does not read arbitrary
client-supplied paths. Initially installation requires a disconnected session;
otherwise return Busy. Editing source YAML does not live-reload the service.
Owner enrollment and administrative authorization are service policy, not
owner fields accepted from arbitrary imported YAML.

`warper recover` uses the authorized service with administrative rights.
`warperd recover` is the stopped-service administrative path and requires
its instance lock; inspection is read-only/redacted. Neither requires backend
DNS. Logs go to stderr; stdout contains command results only.

Exit codes: 0 for completed success, valid inspection, or explicitly requested
operation acceptance; 2 for CLI/configuration errors; 1 for runtime, preflight,
authorization, wait-timeout, recovery, or cleanup failure. A valid inspection
of dirty state reports that state with exit 0; malformed/unreadable state
exits 1. A signal-driven runtime shutdown succeeds only when cleanup succeeds.

Service availability, OS approval, and tunnel connectivity are separate.
Missing service, approval required/denied, unauthorized peer, incompatible
API, Busy, and RecoveryRequired have typed actionable diagnostics. Explain
uses current config/snapshots without issuing DNS or changing routing. The
service reads its protected managed store (Linux: `/etc/warper`; macOS:
`/Library/Application Support/warper`), with credentials protected separately
from redacted observable configuration. It never uses `SUDO_USER` at boot.

Development peer enrollment follows [ADR 0005](adr/0005-macos-development-authentication.md).
It is a separate administratively installed trust manifest, not a field in
imported YAML or an owner-controlled RPC override. Unknown fields such as
`development_auth` remain invalid in this configuration schema. Production
artifacts reject development launch/enrollment commands and ignore that
manifest; paid-signed deployment and no-paid-account local acceptance have
separate gates.

## 7. Examples and Compatibility Fixtures

Complete schema examples are in `../examples/ssh.yaml`, `../examples/socks5.yaml`, and `../examples/wireguard.yaml`. They intentionally use documentation hosts and synthetic credentials/keys. They must pass offline validation once implemented; replace peer details, trust files, and keys before attempting real networking. Synthetic WireGuard keys are public test data and are not credentials for a real peer.

Phase 0 must capture original-shaped valid inputs plus explicit migration-error fixtures for unknown fields, missing SSH trust at preflight, missing DNS, partial SOCKS credentials, invalid CIDRs/keys, and conflicting routing modes. Phase 1 must register the examples and fixtures in executable parser/CLI tests. Do not label the specification or examples as implemented before those tests pass.

The Phase 0 catalog is `tests/fixtures/configuration/cases.toml`. It records
canonical examples, original-shaped synthetic inputs, normalization,
migration/error expectations, and the required backend capability matrix.
Decoder-only tests in `crates/warper-config/tests/yaml_fixtures.rs` register
these inputs and reject the duplicate-key fixture. `tests/schema.rs` in the
same package reads the catalog and verifies offline validity/errors, generated
backend IDs, routing modes, domain normalization, and required protocol metadata.
Those requirements describe the support contract, not runtime availability.
CLI and preflight expectations remain unverified. Unknown-field diagnostics
use `$[key]` rather than echoing an arbitrary key, matching decoder redaction.
Missing SSH trust is represented as a preflight failure with a nonexistent
trust store, rather than an offline read of the developer's trust files.

## Development-Only Outer Fragment Fixture

`python3 -m scripts.probe_outer_fragment` takes no arguments and is separate
from the installed service/CLI contract. Run it only inside disposable Linux
user, network, and mount namespaces, as shown in the development guide. It
uses private loopback, captures kernel UDP fragments, and restores the original
loopback MTU and link state before exit. It does not enable fragmentation for
the experimental WireGuard transport or change YAML configuration.

The separate command `python3 -m scripts.probe_wireguard_fragment ABSOLUTE_BINARY`
requires an absolute path to the built `wireguard-stack` executable and runs it
with the experimental `--outer-fragment-check` argument. Run the wrapper inside
disposable Linux user, network, and mount namespaces as documented in the
development guide. The wrapper sets private loopback MTU 1280, captures outer
fragments, supervises the child, and restores loopback state. The executable
uses local BoringTun fixture peers and explicit socket fragmentation options;
a no-fragment negative control must fail with the kernel's size error. It
refuses the wrong namespace or route MTU. This is not a service option and
does not change the production transport's path budget or YAML configuration.

Adding `--kernel-peer` after the binary selects the separate experimental
`--kernel-outer-fragment-check` child and requires the disposable harness to
create and later remove its own `wg-feasibility` interface. This mode uses the
Linux kernel WireGuard peer; it is not a service configuration and does not
change the production path budget.

The separate `python3 -m scripts.probe_wireguard_fragment_loss ABSOLUTE_BINARY`
wrapper supervises the experimental `--kernel-outer-fragment-loss` child. It
requires the disposable Linux kernel-peer harness, private loopback MTU 1280,
and `tc`. The wrapper adds only its own private loopback qdisc and temporary
fragment-drop filters, coordinates the child over bounded standard-input and
output pipes, checks drop counters, then removes and verifies its network state.
It is not an installed service option and does not change the production path
budget or YAML configuration.

## Development-Only Outer MTU Probes

The experimental `wireguard-stack --outer-mtu-check`,
`wireguard-stack --kernel-mtu-check` and
`wireguard-stack --router-mtu-check` executables are separate from the installed
service/CLI contract. Run any scope through `scripts/verify-feasibility.sh` with
`wireguard-stack SCOPE` on Linux, choosing exactly one of those scopes.
The harness creates disposable user/network/mount namespaces and sets that
namespace's loopback MTU to 1400 for the local scopes. The kernel scope also
creates and removes an owned WireGuard interface with MTU 1500. The executable refuses an unmapped
namespace and requires the configured MTU fixture. No YAML fields or installed
commands change. Combining any scope with `--rekey`, another scope, or the
host-stack executable is invalid. Success establishes local UDP MTU-error
handling and retained TCP recovery; the kernel scope uses an independent
kernel peer. ADR 0002 selects the demonstrated Linux stack roles; general
production physical-egress/PMTU integration remains unverified.

The router scope instead creates client, forwarding-router and kernel-peer
network namespaces with 1600-byte ingress and 1400-byte egress links. It requires
`nsenter`, `sysctl`, `readlink`, `sleep`, `mount` and `umount` in addition to the usual harness tools
(on systems with administrative tools outside PATH, add `/usr/sbin`). It uses
explicit no-fragment PROBE socket mode to measure remote errors independently
of cached PMTU; the declared budget continues to guard sends. The internal
`--router-mtu-peer DIRECTORY` mode is launched only by the harness in the peer
namespace; its private ready/stop files contain no keys or payloads. It accepts
no rekey combination. For each family combination it verifies a failed UDP
operation without replay and a retained TCP connection across sizing, matching
a router report before committing each reduction. General path trust and
shorter quotes remain unresolved.

The internal `--router-mtu-check DIRECTORY` form is reserved for the isolated
router harness. Its private control directory coordinates interruption and
restoration of a fixture-owned link, private policy route, rule, and address; the probe does not
configure host links or routes.
The standalone no-directory form remains available for the existing routed
checks and does not request an interruption. Both forms require a mapped user
namespace and controlled router topology; they are not production commands.

The host experiment supports `--adapter-mtu-check` for the narrow fixed-sizing
and reassembly experiments. `--mtu-check` instead exercises the actual owned
runner's dynamic TCP PMTU path, including concurrent flows and transient seed
retry. `--tun-pmtu-check` uses genuine private kernel-router ICMP transitions;
its internal `--tun-pmtu-bridge` mode belongs only to that fixture. The raw stack
negative control has the separate `--raw-mtu-check` flag and intentionally
fails. These commands do not add installed CLI or YAML fields. The link ingress
MTU and TCP egress path budget are separate; the supported downward PMTU floor
is 1280, with below-range feedback failing the selected stream explicitly.
