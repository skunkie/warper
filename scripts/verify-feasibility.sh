#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Reproducible Linux role gates and individually runnable feasibility scopes.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 || ! "$1" =~ ^(host-stack|wireguard-stack)$ ]]; then
    echo "usage: scripts/verify-feasibility.sh {host-stack|wireguard-stack} [--packet-only|--tun|--tun-crash-check|--tun-fragment-check|--kernel-peer|--mtu-check|--raw-mtu-check|--tun-pmtu-check|--adapter-mtu-check|--outer-mtu-check|--kernel-mtu-check|--router-mtu-check] [--rekey]" >&2
    exit 2
fi
probe=$1
scope=${2:-gate}
rekey=${3:-}
if [[ "$scope" != gate && "$scope" != --packet-only && "$scope" != --tun && "$scope" != --tun-crash-check && "$scope" != --tun-fragment-check && "$scope" != --kernel-peer && "$scope" != --mtu-check && "$scope" != --raw-mtu-check && "$scope" != --tun-pmtu-check && "$scope" != --adapter-mtu-check && "$scope" != --outer-mtu-check && "$scope" != --kernel-mtu-check && "$scope" != --router-mtu-check ]]; then
    echo "Unknown scope: $scope" >&2
    exit 2
fi
if [[ "$scope" == --kernel-peer && "$probe" != wireguard-stack ]]; then
    echo "--kernel-peer requires wireguard-stack" >&2
    exit 2
fi
if [[ ( "$scope" == --mtu-check || "$scope" == --raw-mtu-check || "$scope" == --tun-pmtu-check || "$scope" == --adapter-mtu-check || "$scope" == --tun || "$scope" == --tun-crash-check || "$scope" == --tun-fragment-check ) && "$probe" != host-stack ]]; then
    echo "$scope requires host-stack" >&2
    exit 2
fi
if [[ ( "$scope" == --outer-mtu-check || "$scope" == --kernel-mtu-check || "$scope" == --router-mtu-check ) && "$probe" != wireguard-stack ]]; then
    echo "$scope requires wireguard-stack" >&2
    exit 2
fi
if [[ -n "$rekey" && ( "$rekey" != --rekey || "$probe" != wireguard-stack || "$scope" == gate || "$scope" == --tun || "$scope" == --tun-crash-check || "$scope" == --tun-fragment-check || "$scope" == --outer-mtu-check || "$scope" == --kernel-mtu-check || "$scope" == --router-mtu-check ) ]]; then
    echo "--rekey requires wireguard-stack with a packet or kernel probe scope" >&2
    exit 2
fi
# A role gate runs its required real-traffic scopes rather than accepting a
# packet-only result. Each nested scope retains its own environment and cleanup.
if [[ "$scope" == gate ]]; then
    repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    cd "$repository_root"
    mkdir -p target/evidence/phase-0
    gate_directory=$(mktemp -d "$repository_root/target/evidence/phase-0/$probe.gate.XXXXXXXX")
    echo "Evidence: $gate_directory"
    {
        date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
        uname -srm
        git rev-parse HEAD
        git status --short
    } > "$gate_directory/environment.txt"
    cp Cargo.lock "$gate_directory/Cargo.lock"
    # Include untracked contract sources, without persisting raw configuration.
    source_roots=(experiments scripts docs)
    if [[ -d crates ]]; then source_roots+=(crates); fi
    find "${source_roots[@]}" -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.sh' -o -name '*.py' -o -name '*.md' \) -print0 \
        | sort -z | xargs -0 sha256sum > "$gate_directory/sources.sha256"
    status=0
    scripts/check.sh > "$gate_directory/checks.log" 2>&1 || status=$?
    echo "workspace_checks_exit=$status" > "$gate_directory/result.txt"
    if [[ "$status" -ne 0 ]]; then
        cat "$gate_directory/checks.log" >&2
        exit "$status"
    fi
    if [[ "$probe" == host-stack ]]; then
        scopes=(--packet-only --tun --tun-crash-check --tun-fragment-check --adapter-mtu-check --mtu-check --tun-pmtu-check)
    else
        scopes=(--packet-only --kernel-peer --kernel-mtu-check --router-mtu-check)
    fi
    for child_scope in "${scopes[@]}"; do
        child_arguments=("$probe" "$child_scope")
        if [[ "$child_scope" == --kernel-peer ]]; then child_arguments+=(--rekey); fi
        status=0
        bash scripts/verify-feasibility.sh "${child_arguments[@]}" \
            > "$gate_directory/${child_scope#--}.log" 2>&1 || status=$?
        cat "$gate_directory/${child_scope#--}.log"
        echo "$child_scope exit=$status" >> "$gate_directory/result.txt"
        if [[ "$status" -ne 0 ]]; then exit "$status"; fi
    done
    echo "PASS Linux $probe role gate; native macOS and production acceptance NOT RUN" \
        | tee -a "$gate_directory/result.txt"
    exit 0
fi

probe_arguments=()
isolation_mode=packet
if [[ "$scope" == --mtu-check || "$scope" == --raw-mtu-check || "$scope" == --adapter-mtu-check ]]; then probe_arguments+=("$scope"); fi
if [[ "$scope" == --tun-pmtu-check ]]; then
    isolation_mode=tun
    probe_arguments+=(--pmtu)
    for tool in nsenter sysctl sleep mount umount; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "Required TUN PMTU fixture tool is missing: $tool" >&2
            exit 1
        fi
    done
fi
if [[ "$scope" == --tun ]]; then isolation_mode=tun; fi
if [[ "$scope" == --tun-crash-check ]]; then
    isolation_mode=tun
    probe_arguments+=(--crash-after-udp)
fi
if [[ "$scope" == --tun-fragment-check ]]; then
    isolation_mode=tun
    probe_arguments+=(--fragmented-ipv4)
fi
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
if [[ "$scope" == --mtu-check ]]; then timeout_seconds=40; fi
if [[ "$scope" == --tun-pmtu-check ]]; then timeout_seconds=75; fi
if [[ "$scope" == --tun ]]; then timeout_seconds=35; fi
if [[ "$scope" == --tun-crash-check ]]; then timeout_seconds=60; fi
if [[ "$scope" == --tun-fragment-check ]]; then timeout_seconds=50; fi
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
if [[ "$scope" == --router-mtu-check ]] && ! command -v tc >/dev/null 2>&1; then
    echo "Required feasibility tool is missing: tc" >&2
    exit 1
fi
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
if [[ "$scope" == --tun-pmtu-check ]]; then
    mkdir "$run_directory/state"
    probe_arguments+=("$run_directory/state")
fi
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
    if [[ "$scope" == --mtu-check || "$scope" == --raw-mtu-check || "$scope" == --adapter-mtu-check ]]; then echo "mtu_probe_exit=$status"; fi
    if [[ "$scope" == --outer-mtu-check ]]; then
        echo "outer_local_mtu_probe_exit=$status"
        echo "NOT RUN remote router MTU discovery or concurrent physical-path TCP sizing"
    fi
    echo "cleanup=namespace child reaped by unshare; no persistent network state allocated"
    if [[ "$scope" == --tun || "$scope" == --tun-crash-check || "$scope" == --tun-fragment-check || "$scope" == --tun-pmtu-check ]]; then
        echo "kernel_tun_probe_exit=$status"
        if [[ "$scope" == --tun-pmtu-check ]]; then echo "tun_runtime_pmtu_exit=$status"; fi
        if [[ "$scope" == --tun-crash-check ]]; then echo "tun_crash_probe_exit=$status"; fi
        if [[ "$scope" == --tun-fragment-check ]]; then echo "tun_fragment_probe_exit=$status"; fi
        echo "NOT RUN native macOS utun or distinct SSH/SOCKS protocol backend instances"
    else
        echo "NOT RUN kernel TUN/utun traffic, distinct SSH/SOCKS protocol backend instances"
    fi
    if [[ "$scope" == --router-mtu-check ]]; then
        echo "router_mtu_probe_exit=$status"
        echo "NOT RUN short-quote support or general physical-path policy"
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
    echo "NOT RUN production MTU/ICMP acceptance, backend/service crash recovery, native macOS"
    if [[ "$rekey" == --rekey ]]; then
        echo "rekey_probe_exit=$status"
    else
        echo "NOT RUN long-lived rekey (use wireguard-stack --packet-only --rekey)"
    fi
} > "$run_directory/result.txt"
if [[ "$status" -ne 0 ]]; then
    exit "$status"
fi
echo "PASS ${scope#--} probe; this scope alone is not the full role gate." >> "$run_directory/result.txt"
