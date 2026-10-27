#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Packet and independent kernel-peer probes; full Phase 0 gates remain open.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 || ! "$1" =~ ^(host-stack|wireguard-stack)$ ]]; then
    echo "usage: scripts/verify-feasibility.sh {host-stack|wireguard-stack} [--packet-only|--kernel-peer|--mtu-check|--outer-mtu-check|--kernel-mtu-check|--router-mtu-check] [--rekey]" >&2
    exit 2
fi
probe=$1
scope=${2:-gate}
rekey=${3:-}
if [[ "$scope" != gate && "$scope" != --packet-only && "$scope" != --kernel-peer && "$scope" != --mtu-check && "$scope" != --outer-mtu-check && "$scope" != --kernel-mtu-check && "$scope" != --router-mtu-check ]]; then
    echo "Unknown scope: $scope" >&2
    exit 2
fi
if [[ "$scope" == --kernel-peer && "$probe" != wireguard-stack ]]; then
    echo "--kernel-peer requires wireguard-stack" >&2
    exit 2
fi
if [[ "$scope" == --mtu-check && "$probe" != host-stack ]]; then
    echo "--mtu-check requires host-stack" >&2
    exit 2
fi
if [[ ( "$scope" == --outer-mtu-check || "$scope" == --kernel-mtu-check || "$scope" == --router-mtu-check ) && "$probe" != wireguard-stack ]]; then
    echo "$scope requires wireguard-stack" >&2
    exit 2
fi
if [[ -n "$rekey" && ( "$rekey" != --rekey || "$probe" != wireguard-stack || "$scope" == gate || "$scope" == --outer-mtu-check || "$scope" == --kernel-mtu-check || "$scope" == --router-mtu-check ) ]]; then
    echo "--rekey requires wireguard-stack with a packet or kernel probe scope" >&2
    exit 2
fi
probe_arguments=()
isolation_mode=packet
if [[ "$scope" == --mtu-check ]]; then probe_arguments+=(--mtu-check); fi
if [[ "$scope" == --outer-mtu-check ]]; then
    probe_arguments+=(--outer-mtu-check)
    isolation_mode=outer
fi
if [[ "$scope" == --kernel-peer ]]; then
    probe_arguments+=(--kernel-peer)
    isolation_mode=kernel
fi
if [[ "$scope" == --kernel-mtu-check ]]; then
    probe_arguments+=(--kernel-mtu-check)
    isolation_mode=kernel-mtu
fi
if [[ "$scope" == --router-mtu-check ]]; then
    probe_arguments+=(--router-mtu-check)
    isolation_mode=router
    for tool in nsenter sysctl readlink sleep; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "Required router fixture tool is missing: $tool" >&2
            exit 1
        fi
    done
fi
timeout_seconds=20
if [[ "$scope" == --kernel-peer ]]; then timeout_seconds=50; fi
if [[ "$rekey" == --rekey ]]; then
    probe_arguments+=(--rekey)
    timeout_seconds=150
    if [[ "$scope" == --kernel-peer ]]; then timeout_seconds=200; fi
fi
for tool in cargo rustc git timeout unshare ip bash python3 cat; do
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
    echo "command=./scripts/verify-feasibility.sh $probe ${2-} ${3-}"
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
# Kernel-peer changes are confined to the namespace child and independently removed.
timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" \
    unshare --user --map-root-user --net --mount --fork --kill-child=KILL \
    bash "$repository_root/scripts/run-feasibility-isolated.sh" "$isolation_mode" \
    "$repository_root/target/debug/$probe" "${probe_arguments[@]}" > "$run_directory/probe.log" 2>&1 || status=$?
cat "$run_directory/probe.log"
{
    echo "probe_exit=$status"
    if [[ "$scope" == --mtu-check ]]; then echo "mtu_probe_exit=$status"; fi
    if [[ "$scope" == --outer-mtu-check ]]; then
        echo "outer_local_mtu_probe_exit=$status"
        echo "NOT RUN remote router MTU discovery or concurrent physical-path TCP sizing"
    fi
    echo "cleanup=namespace child reaped by unshare; no persistent network state allocated"
    echo "NOT RUN kernel TUN/utun traffic, distinct SSH/SOCKS protocol backend instances"
    if [[ "$scope" == --router-mtu-check ]]; then
        echo "router_mtu_probe_exit=$status"
        echo "NOT RUN retained TCP sizing from remote errors or general physical-path policy"
    fi
    if [[ "$scope" == --kernel-mtu-check ]]; then
        echo "kernel_mtu_probe_exit=$status"
        echo "NOT RUN remote router MTU discovery or concurrent physical-path TCP sizing"
    fi
    if [[ "$scope" == --kernel-peer || "$scope" == --kernel-mtu-check || "$scope" == --router-mtu-check ]]; then
        echo "kernel_peer_probe_exit=$status"
    else
        echo "NOT RUN independent WireGuard implementation"
    fi
    echo "NOT RUN MTU/ICMP acceptance, backend outage/crash injection, native macOS"
    if [[ "$rekey" == --rekey ]]; then
        echo "rekey_probe_exit=$status"
    else
        echo "NOT RUN long-lived rekey (use wireguard-stack --packet-only --rekey)"
    fi
} > "$run_directory/result.txt"
if [[ "$status" -ne 0 ]]; then
    exit "$status"
fi
if [[ "$scope" == gate ]]; then
    echo "Phase 0 gate incomplete: required TUN, contract, and failure evidence remains open." >&2
    echo "INCOMPLETE full feasibility gate" >> "$run_directory/result.txt"
    exit 1
fi
echo "PASS ${scope#--} probe; full Phase 0 gate remains open." >> "$run_directory/result.txt"
