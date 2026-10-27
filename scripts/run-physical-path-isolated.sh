#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Internal private router fixture. Never configure the invoking host.
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 || ! "$2" =~ ^(4|6)$ || ! "${3:-$2}" =~ ^(4|6)$ ]]; then
    echo "usage: run-physical-path-isolated.sh PROBE INNER [OUTER] (families 4 or 6)" >&2
    exit 2
fi
mapping=$(cat /proc/self/uid_map)
read -r inside outside count extra <<< "$mapping"
if [[ "$mapping" == *$'\n'* || "$inside" != 0 || "$count" != 1 || -n "${extra:-}" || ! "$outside" =~ ^[0-9]+$ ]]; then
    echo "Physical-path fixture requires a fresh single-UID user and network namespace." >&2
    exit 1
fi
probe=$1
inner_family=$2
outer_family=${3:-$inner_family}
control_directory=$(mktemp -d /tmp/warper-path.XXXXXXXX)
mounted=false
client_anchor=
server_anchor=
client_process=
peer_process=
links=()
cleanup() {
    local status=${1:-$?}
    local failed=false
    local child_status
    trap - EXIT
    if [[ -n "$client_process" ]]; then
        if kill -0 "$client_process" 2>/dev/null; then
            if ! kill -- -"$client_process" 2>/dev/null; then failed=true; fi
        fi
        child_status=0
        wait "$client_process" || child_status=$?
        if [[ "$child_status" != 0 && "$child_status" != 1 && "$child_status" != 143 ]]; then failed=true; fi
    fi
    if [[ -n "$peer_process" ]]; then
        : > "$control_directory/peer.stop"
        if kill -0 "$peer_process" 2>/dev/null; then
            if ! kill -- -"$peer_process" 2>/dev/null; then failed=true; fi
        fi
        child_status=0
        wait "$peer_process" || child_status=$?
        if [[ "$child_status" != 0 && "$child_status" != 1 && "$child_status" != 143 ]]; then failed=true; fi
    fi
    for log in "$control_directory/client.log" "$control_directory/peer.log"; do
        if [[ -f "$log" ]] && ! cat "$log"; then failed=true; fi
    done
    for link in "${links[@]}"; do
        if ip link show dev "$link" >/dev/null 2>&1; then
            if ! ip link del dev "$link"; then failed=true; fi
        fi
    done
    if ! ip -j link show | python3 -c 'import json,sys; sys.exit(any(row["ifname"] in ("routerc0","routers0") for row in json.load(sys.stdin)))'; then failed=true; fi
    for anchor in "$client_anchor" "$server_anchor"; do
        if [[ -n "$anchor" ]]; then
            if kill -0 "$anchor" 2>/dev/null; then
                if ! kill "$anchor" 2>/dev/null; then failed=true; fi
            fi
            child_status=0
            wait "$anchor" || child_status=$?
            if [[ "$child_status" != 0 && "$child_status" != 143 ]]; then failed=true; fi
        fi
    done
    if [[ "$mounted" == true ]]; then
        if ! umount "$control_directory"; then failed=true; fi
    fi
    if ! rmdir -- "$control_directory"; then failed=true; fi
    if [[ "$failed" == true ]]; then
        echo "FAIL independent physical-path cleanup" >&2
        if [[ "$status" == 0 ]]; then status=1; fi
    else
        echo "CLEANUP physical-path links removed and verified; namespace processes reaped"
    fi
    exit "$status"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mount -t tmpfs -o mode=700 tmpfs "$control_directory"
mounted=true
unshare --net sleep 60 &
client_anchor=$!
unshare --net sleep 60 &
server_anchor=$!
router_namespace=$(readlink /proc/$$/ns/net)
for anchor in "$client_anchor" "$server_anchor"; do
    ready=false
    for _ in {1..100}; do
        if child_namespace=$(readlink "/proc/$anchor/ns/net") && [[ "$child_namespace" != "$router_namespace" ]]; then ready=true; break; fi
        sleep 0.01
    done
    if [[ "$ready" != true ]]; then echo "FAIL child network namespace startup" >&2; exit 1; fi
done
ip link add routerc0 type veth peer name client0
links+=(routerc0)
ip link set client0 netns "$client_anchor"
ip link add routers0 type veth peer name server0
links+=(routers0)
ip link set server0 netns "$server_anchor"
ip addr add 198.18.0.1/24 dev routerc0
ip -6 addr add fd77:1::1/64 dev routerc0 nodad
ip addr add 198.19.0.1/24 dev routers0
ip -6 addr add fd77:2::1/64 dev routers0 nodad
ip link set routerc0 mtu 1600 up
ip link set routers0 mtu 1600 up
sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
nsenter --net="/proc/$client_anchor/ns/net" bash -eu -c '
    ip link set lo up
    ip addr add 198.18.0.2/24 dev client0
    ip -6 addr add fd77:1::2/64 dev client0 nodad
    ip link set client0 mtu 1600 up
    ip route add default via 198.18.0.1
    ip -6 route add default via fd77:1::1
'
nsenter --net="/proc/$server_anchor/ns/net" bash -eu -c '
    ip link set lo up
    ip addr add 198.19.0.2/24 dev server0
    ip -6 addr add fd77:2::2/64 dev server0 nodad
    ip link set server0 mtu 1600 up
    ip route add default via 198.19.0.1
    ip -6 route add default via fd77:2::1
'
helper=$(dirname "${BASH_SOURCE[0]}")/run-feasibility-isolated.sh
timeout --signal=TERM --kill-after=2s 48s nsenter --net="/proc/$server_anchor/ns/net" \
    bash "$helper" kernel-mtu "$probe" --physical-path-peer "$control_directory" "$inner_family" "$outer_family" > "$control_directory/peer.log" 2>&1 &
peer_process=$!
wait_for() {
    local marker=$1
    local process=$2
    for _ in {1..3000}; do
        if [[ -f "$control_directory/$marker" ]]; then return 0; fi
        if ! kill -0 "$process" 2>/dev/null; then
            local child_status=0
            wait "$process" || child_status=$?
            if [[ "$process" == "$client_process" ]]; then client_process=; fi
            if [[ "$process" == "$peer_process" ]]; then peer_process=; fi
            echo "FAIL physical-path coordination: $marker" >&2
            if [[ "$child_status" == 0 ]]; then child_status=1; fi
            return "$child_status"
        fi
        sleep 0.01
    done
    echo "FAIL physical-path coordination deadline: $marker" >&2
    return 1
}
wait_for peer.ready "$peer_process"
timeout --signal=TERM --kill-after=2s 40s nsenter --net="/proc/$client_anchor/ns/net" \
    "$probe" --physical-path-client "$control_directory" "$inner_family" "$outer_family" > "$control_directory/client.log" 2>&1 &
client_process=$!
wait_for down.request "$client_process"
ip link set dev routers0 down
ip -j link show dev routers0 | python3 -c 'import json,sys; sys.exit("UP" in json.load(sys.stdin)[0]["flags"])'
echo "PASS private router egress down and verified"
printf '%s\n' down > "$control_directory/down.ready"
wait_for up.request "$client_process"
ip link set dev routers0 up
ip -6 addr replace fd77:2::1/64 dev routers0 nodad
ip -j link show dev routers0 | python3 -c 'import json,sys; sys.exit("UP" not in json.load(sys.stdin)[0]["flags"])'
ip -j -6 addr show dev routers0 | python3 -c 'import json,sys; sys.exit(not any(a.get("local") == "fd77:2::1" for r in json.load(sys.stdin) for a in r.get("addr_info", [])))'
echo "PASS private router egress and IPv6 address restored and verified"
printf '%s\n' up > "$control_directory/up.ready"
client_status=0
wait "$client_process" || client_status=$?
client_process=
printf '%s\n' stop > "$control_directory/peer.stop"
peer_status=0
wait "$peer_process" || peer_status=$?
peer_process=
if [[ "$client_status" != 0 ]]; then exit "$client_status"; fi
if [[ "$peer_status" != 0 ]]; then exit "$peer_status"; fi
cleanup 0
