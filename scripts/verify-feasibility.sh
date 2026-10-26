#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Initial packet-level harness. Full kernel/independent-peer gates remain open.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! "$1" =~ ^(host-stack|wireguard-stack)$ ]]; then
    echo "usage: scripts/verify-feasibility.sh {host-stack|wireguard-stack} [--packet-only]" >&2
    exit 2
fi
probe=$1
scope=${2:-gate}
if [[ "$scope" != gate && "$scope" != --packet-only ]]; then
    echo "Unknown scope: $scope" >&2
    exit 2
fi
for tool in cargo rustc git timeout unshare ip bash; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required feasibility tool is missing: $tool" >&2
        exit 1
    fi
done
if [[ $(uname -s) != Linux ]]; then
    echo "This isolation harness requires Linux; native macOS acceptance is not implemented." >&2
    exit 1
fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"
evidence_root="$repository_root/target/evidence/phase-0"
mkdir -p "$evidence_root"
run_directory=$(mktemp -d "$evidence_root/$probe.XXXXXXXX")
echo "Evidence: $run_directory"
{
    echo "probe=$probe"
    echo "scope=$scope"
    echo "command=./scripts/verify-feasibility.sh $probe ${2-}"
    echo "isolation=disposable user, network, and mount namespaces; no DNS or host-state mutation"
    date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
    uname -srm
    rustc --version --verbose
    cargo --version
    git rev-parse HEAD
    git status --short
} > "$run_directory/environment.txt"
cp Cargo.lock "$run_directory/Cargo.lock"

# Build before isolation: the probe namespace has no external network.
if ! cargo build --locked --target-dir "$repository_root/target" -p "$probe" > "$run_directory/build.log" 2>&1; then
    cat "$run_directory/build.log" >&2
    echo "FAIL build" > "$run_directory/result.txt"
    exit 1
fi
status=0
# timeout owns the process group; unshare kills its namespace child if it exits.
# Namespace destruction independently releases sockets even on probe failure.
# No resolver, system bus, journal, routes, or persistent interfaces are touched.
# The positional parameter must expand in the namespace's child shell.
# shellcheck disable=SC2016
timeout --signal=TERM --kill-after=2s 20s \
    unshare --user --map-root-user --net --mount --fork --kill-child=KILL \
    bash -euc 'ip link set lo up
exec "$1"' bash "$repository_root/target/debug/$probe" > "$run_directory/probe.log" 2>&1 || status=$?
cat "$run_directory/probe.log"
{
    echo "probe_exit=$status"
    echo "cleanup=namespace child reaped by unshare; no persistent network state allocated"
    echo "NOT RUN kernel TUN/utun traffic, two backend instances, independent WireGuard implementation"
    echo "NOT RUN MTU/ICMP acceptance, outage/cancellation injection, native macOS"
    echo "NOT RUN long-lived rekey (use cargo run --locked -p wireguard-stack -- --rekey separately)"
} > "$run_directory/result.txt"
if [[ "$status" -ne 0 ]]; then
    exit "$status"
fi
if [[ "$scope" == gate ]]; then
    echo "Phase 0 gate incomplete: only packet-level evidence is implemented." >&2
    echo "INCOMPLETE full feasibility gate" >> "$run_directory/result.txt"
    exit 1
fi
echo "PASS packet-only probe; full Phase 0 gate remains open." >> "$run_directory/result.txt"
