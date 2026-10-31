<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# 0014. Safe Linux TUN API boundary

- Status: accepted scoped Linux API; journaled production driver pending.
- Date: 2026-10-31
- Related: ADR 0002, ADR 0012, ADR 0013, NET-01, NET-05.

## Context and alternatives

The initial service adapters need a real Linux TUN owner without introducing
local unsafe ioctl code. Phase 0 established kernel TUN feasibility through a
fixture bridge, but it did not select a production Rust OS API. Required state
must be journaled before mutation, and a configured interface name must never
attach to or alter a foreign interface.

The released `tun` 0.8.14 uses WTFPL, outside the existing dependency policy.
Direct local ioctl code would expand the unsafe boundary. The candidate
[tun-rs 2.8.16](https://crates.io/crates/tun-rs/2.8.16) is Apache-2.0 and exposes
safe creation, rename, MTU and Tokio packet I/O. Keep its default address
management and offload/framing features disabled. It is currently a Linux-only
development dependency for an executable probe, not a production driver choice.
The lockfile retains its exact registry checksums and platform dependency graph;
no existing package versions are upgraded.

## Candidate and limitations

The upstream Linux builder does not request `IFF_TUN_EXCL` for a supplied name.
Never construct it with a configured name. Create an unnamed nonpersistent
interface, initially down, then rename the newly owned interface; a name
collision must fail and preserve the existing interface. Validate the protected
TUN character device before invoking the builder so its missing-device repair
path cannot mutate the host filesystem. Production native calls need supervised
bounded workers, retained identity, journal intent and acknowledged operations.
No wrapper/fork or local unsafe code is selected here.

The native probe retains a separately created TUN at the kernel's first name,
then creates a second unnamed TUN with a different MTU. It requires a typed
rename collision and unchanged foreign metadata, exercises async packet I/O,
and checks last-owner interface removal. Before capture-route publication it
allocates the validated policy/host/backend/relay owners and retains the runtime
task. Actual kernel TCP passes through production adapters to a controlled
SOCKS5 proxy/target, with exact 64 KiB traffic, duplex response and FIN. The proxy
verifies the invented original destination and maps it to its loopback fixture.
This is an API/integration probe, not a running authenticated service or general
physical transport proof.

## Reproduction and decision gate

```sh
cargo test --locked -p warper-service --example linux_network_probe
cargo build --locked -p warper-service --example linux_network_probe
sudo -n python3 scripts/control_acceptance.py \
  --probe "$PWD/target/debug/examples/linux_network_probe" \
  --evidence "$PWD/target/evidence/phase-1/tun-api/native"
```

Use only a disposable Linux VM. The harness retains the initial user namespace,
requires actual root, and isolates mount/network/PID namespaces, state, resolver,
bus and device nodes. It independently reaps the process group and compares host
links/routes/resolver and TUN device metadata. Creating private `/dev/net/tun`
never creates/repairs the host node. The owner-dispatched CI gate runs this
probe; PR/push events cannot start root acceptance. Retain exact revision/binary
hashes and raw logs/artifacts under `target/evidence/phase-1/tun-api/`.

Acceptance needs successful native creation/collision/I/O/drop evidence and
independent host preservation. The production driver still needs immutable
instance identity, native route/conflict handling, physical endpoint exemptions,
journaled startup rollback/recovery, task supervision and actual daemon/control
lifecycle evidence. Fixture `ip` commands are bounded test setup, never a
replacement for the required production netlink driver.

## Accepted native scope

The [owner-dispatched native gate](https://github.com/skunkie/warper/actions/runs/41191632642)
passes at `e2e1f99`. Its exact probe/artifact demonstrates two independently
owned unnamed TUNs, typed rename collision with unchanged foreign state, actual
kernel TCP through the prepared production adapters, exact application bytes,
duplex response after FIN, joined workers and last-owner interface removal.
The independent harness reports no timeout and preserved host links/routes,
resolver and device metadata. The existing root control/recovery gate also
passes with the private device mount.

Accept the exact released API for a thin Linux adapter using unnamed creation,
nonpersistent descriptor ownership and collision-safe naming. Do not promote
fixture shell operations into production or infer general physical egress,
journaling/recovery, SIGKILL handling or daemon/control lifecycle from this run.
Retained raw results are under
`target/evidence/phase-1/privileged-control-ci/run-41191632642/`. Production
modules must preserve the ownership/admission conditions above and add their
own acknowledged driver and lifecycle evidence.
