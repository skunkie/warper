#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Internal namespace child. Never configure networking in the invoking host.
set -euo pipefail
if [[ $# -lt 2 || ! "$1" =~ ^(packet|kernel|outer|kernel-mtu)$ ]]; then
    echo "usage: run-feasibility-isolated.sh {packet|kernel|outer|kernel-mtu} PROBE [ARG...]" >&2
    exit 2
fi
mode=$1
shift
mapping=$(cat /proc/self/uid_map)
read -r inside outside count extra <<< "$mapping"
if [[ "$mapping" == *$'\n'* || "$inside" != 0 || "$count" != 1 || -n "${extra:-}" || ! "$outside" =~ ^[0-9]+$ ]]; then
    echo "Feasibility setup requires a fresh single-UID user and network namespace." >&2
    exit 1
fi
# A newly mapped user namespace has no CAP_NET_ADMIN in the host network
# namespace. The parent also creates a new net/mount namespace with unshare.
ip link set lo up
if [[ "$mode" == outer || "$mode" == kernel-mtu ]]; then
    ip link set lo mtu 1400
    echo "FIXTURE private loopback MTU set to 1400"
    if [[ "$mode" == outer ]]; then exec "$@"; fi
fi
if [[ "$mode" == packet ]]; then
    exec "$@"
fi

interface=wg-feasibility
created=false
cleanup() {
    local status=$?
    local cleanup_failed=false
    trap - EXIT
    if [[ "$created" == true ]]; then
        if ! ip link del dev "$interface"; then
            echo "FAIL independent kernel interface cleanup" >&2
            cleanup_failed=true
        fi
        if ! ip -j link show | python3 -c 'import json, sys; sys.exit(any(link["ifname"] == "wg-feasibility" for link in json.load(sys.stdin)))'; then
            echo "FAIL kernel interface retirement verification" >&2
            cleanup_failed=true
        fi
        if [[ "$cleanup_failed" == true ]]; then
            if [[ "$status" -eq 0 ]]; then status=1; fi
        else
            echo "CLEANUP independent kernel WireGuard interface removed and verified"
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ip link add "$interface" type wireguard
created=true
ip addr add 10.66.66.10/24 dev "$interface"
ip -6 addr add fd66:66::10/64 dev "$interface" nodad
link_mtu=1280
if [[ "$mode" == kernel-mtu ]]; then link_mtu=1500; fi
ip link set dev "$interface" mtu "$link_mtu" up
"$@"
