<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0003. DNS route retention and service-binding endpoints

- Status: accepted policy; runtime implementation and acceptance evidence pending.
- Date: 2026-10-26
- Related: [configuration](../configuration.md),
  [DNS and routing plan](../implementation-plan.md#42-dns-selection-and-forwarding),
  [implementation contracts](../implementation-contracts.md), NET-10, NET-11,
  and NET-12 in the [acceptance contract](../acceptance.md).

## Context

DNS freshness and route ownership have different lifetimes. A zero-TTL
answer can be used immediately without being cached. Capture must survive
long enough for its first connection, including when DNS output is delayed.

HTTPS/SVCB responses can advertise usable addresses and alternative names
before separate A/AAAA queries finish. A response may therefore expose more
endpoints than an ordinary address answer. With split DNS, a client query
for a target outside the configured domains may bypass warper entirely.

## Alternatives

- Expire routes with DNS freshness alone. This gives no first-connection
  interval for zero-TTL answers.
- Raise DNS TTLs or cache zero-TTL answers. This changes freshness semantics.
- Pass service bindings through and wait for client address queries. Hints
  and separately resolved target names can precede capture.
- Dynamically learn target names and install system resolver policies. This
  adds resolver ownership, expiry, conflict, rollback, and recovery machinery
  that needs a separate design and native acceptance evidence.
- Reserve bounded route grace and validate all service endpoints before
  publishing a response, requiring targets to use configured backend domains.

## Decision

Use the final approach. Add `timeouts.dns_route_grace_ms`, default 30000 ms.
Keep wire/cache TTLs unchanged except normal aging; never cache a zero-TTL
answer for reuse. A pending-response reference pins required routes through
output and is exchanged atomically at handoff for retention lasting at least
the greater of remaining dependency TTL and grace. Active flows hold
independent references. Same-backend successful answers can extend routing
retention; cancelled/failed answers cannot create a new grace lease.

For a matched HTTPS/SVCB answer, resolve and validate the reachable endpoint
set through the original selected backend. Cover hints, related Additional
addresses, resolved addresses, and applicable fallback targets before
release. Preserve parameter/mode semantics and account for alias/service/
address TTL paths. Do not select only the preferred endpoint.

Every non-root dependency/target name must already match a configured domain
rule selecting the same backend. Require explicit additional domains where
necessary. Unmatched/cross-backend names return SERVFAIL with a diagnostic;
do not depend on implicit learned resolver domains. This keeps client
follow-up lookups on the selected backend in split mode as well as global
mode. Static mode requires existing winning static coverage for all exposed
addresses; dynamic/mixed modes may add routes.

If the complete passed-through endpoint set cannot be validated and routed
within family, address/query/hop, request-deadline, or route budgets, return
SERVFAIL. Do not rewrite signed records to conceal an unsupported endpoint,
silently change backend, or forward partially prepared data. In particular,
an exposed IPv6 endpoint cannot pass when IPv6 capture is disabled.

## Consequences

- TTL-zero and short-TTL answers have a bounded first-connection interval
  without becoming reusable cached DNS answers.
- Retained routes consume existing route/buffer budgets. Exhaustion rejects
  new discovery rather than evicting another response's protected routes.
- Retained DNS state has independent global lease/cache counts and a 16 MiB
  byte budget, covering names, provenance, indexes, and timers. Distinct names
  sharing one IP consume lease capacity; same-key renewals coalesce without
  appending unlimited expiry records. Cache eviction cannot cancel routing
  ownership, and optional cache insertion may be skipped. NET-12 covers
  metadata admission, exhaustion, reclamation, and rollback independently of
  the kernel route count.
- Service-binding discovery requires more DNS work and route commits before
  response release, bounded by the original request deadline and explicit
  hop/query/address limits.
- Cross-domain targets require configuration on the same backend. IPv6-
  disabled configurations can reject service responses exposing IPv6 hints;
  broader support requires a policy for safe record transformation.
- Late connections after final lease/grace/flow expiry remain outside the
  selective-routing coverage guarantee. Existing caches and application-
  managed DNS remain separate documented limits.

## Validation and reconsideration

Implement deterministic clock/output-readiness cases for NET-10, including
zero TTL, lease expiry before handoff, first-flow admission, cancellation,
renewal, and final retirement. NET-11 requires controlled service-binding
peers and physical captures with deliberately delayed address resolution and
kernel ACKs, plus split DNS, alternate targets, disabled families, and
budget/failure cases. These runtime cases are not implemented yet.

Keep raw evidence in `target/evidence/` or CI artifacts and update the phase
ledger only when the gates have evidence. Revisit this decision if dynamic
target-domain learning or signed-record transformation is needed; include
its platform DNS lifecycle and recovery before expanding the policy.

Protocol references: [RFC 1035 section 3.2.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.1)
and [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html), especially its
target-name, mode, client-fallback, and IP-hint rules.
