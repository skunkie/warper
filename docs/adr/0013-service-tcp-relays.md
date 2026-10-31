<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0013. Retained service TCP relay workers

- Status: accepted relay boundary; daemon/platform composition pending.
- Date: 2026-10-31
- Related: ADR 0011, ADR 0012, contract section 29, NET-01, NET-06.

## Context and alternatives

The core stream boundary and production SOCKS5/host adapters now exist. Their
owner must enforce flow lifetimes, retain workers and surface failures without
coupling clients to networking tasks. Running copies in a request handler would
make client disconnect control network lifetime. Detached per-flow tasks would
hide failures and allow completion records to grow outside admission budgets.

## Decision

Introduce `warper-service` for real service responsibilities, starting with
`relay::Relays`. Register immutable backend IDs/capabilities once, and open only
the backend already selected by captured metadata. Enforce a single setup
deadline independently of the backend, capped by absolute flow age. Never retry
or select another backend after failure.

Retain at most the configured 1..1024 workers and unjoined completion records.
Reject duplicate live IDs, unknown backends and unsupported families before
spawning work. Two 8192-byte copy buffers preserve independent TCP half-close.
Positive read/write progress renews established idle expiry; absolute age still
bounds an active flow. Count completed positive writes on failure, without
retaining application payload for replay. A fixed 64-entry backend-registration
ceiling bounds registry lookup/allocation; runtime preflight must reject larger
configurations rather than truncate them.

A worker panic closes admission, cancels other workers and is returned to the
supervisor. Explicit shutdown cancels and joins workers under a configured
budget, then aborts/joins remaining async workers. This requires nonblocking
backend polling. Report aborted workers explicitly; their unreturned byte counts
cannot be inferred. Drop aborts as a safety net but is not the required shutdown
path. Networking tasks remain owned by the service after any client exits.

## Consequences and evidence

Core does not depend on the service or backend implementations. The service
library currently depends only on core and Tokio; real SOCKS5 is an integration
test dependency until daemon composition needs it. No placeholder executable,
connected state, physical connector or TUN driver is introduced here.

Controlled duplex tests cover setup enforcement, FIN/bytes, capacity, duplicate
IDs, unsupported families, idle renewal, absolute expiry, partial I/O failure,
cancellation before any backend poll and joined panic supervision. Real local
SOCKS5/target peers cover all four destination/transport IP-family combinations
with 64 KiB duplex/FIN behavior and exact counts. Every successful peer/relay
worker is joined and checked.

```sh
cargo test --locked -p warper-service
cargo test --locked --release -p warper-service --test socks5 service_workload -- --ignored --exact --nocapture
cargo llvm-cov --locked -p warper-service --all-features --html
scripts/check.sh
```

The separate workload measures 100 actual loopback exchanges in batches of four
with latency distributions, process CPU/RSS, exact application byte counts and
loopback drop deltas. Fixture peers share the measured process. Retain raw logs,
environment, binary/source hashes and coverage review under
`target/evidence/phase-1/service-relays/`. This does not establish kernel TUN
performance, physical-path protection or a Rust/Go comparison. Authenticated
service lifecycle, startup rollback, OS ownership/recovery and actual application
TUN traffic remain Phase 1 gates.

Shutdown reports retain the first typed flow failure and worker failure alongside
aggregate counters and any shutdown deadline/clock error. Expected cancellation
is counted separately. Thus explicit teardown preserves an initial operational
failure even when workers finish while shutdown is joining them; bounded reports
do not silently replace errors with successful cleanup.
