#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Internal three-namespace router fixture. No host resolver, bus or mount changes.
set -euo pipefail
if [[ $# -ne 2 || "$2" != --router-mtu-check ]]; then
    echo "usage: run-router-mtu-isolated.sh PROBE --router-mtu-check" >&2
    exit 2
fi
mapping=$(cat /proc/self/uid_map)
read -r inside outside count extra <<< "$mapping"
if [[ "$mapping" == *$'\n'* || "$inside" != 0 || "$count" != 1 || -n "${extra:-}" || ! "$outside" =~ ^[0-9]+$ ]]; then
    echo "Router fixture requires a fresh single-UID user and network namespace." >&2
    exit 1
fi
probe=$1
control_directory=$(mktemp -d /tmp/warper-path.XXXXXXXX)
mounted=false
client_anchor=
server_anchor=
peer_process=
control_process=
links=()
cleanup() {
    local status=${1:-$?}
    local failed=false
    local child_status
    trap - EXIT
    if [[ -n "$control_process" ]]; then
        if kill -0 "$control_process" 2>/dev/null; then
            if ! kill "$control_process" 2>/dev/null; then failed=true; fi
        fi
        child_status=0
        wait "$control_process" || child_status=$?
        if [[ "$child_status" != 0 && "$child_status" != 1 && "$child_status" != 143 ]]; then failed=true; fi
    fi
    if [[ -n "$peer_process" ]]; then
        : > "$control_directory/stop"
        if kill -0 "$peer_process" 2>/dev/null; then
            if ! kill -- -"$peer_process" 2>/dev/null; then failed=true; fi
        fi
        child_status=0
        wait "$peer_process" || child_status=$?
        if [[ "$child_status" != 0 && "$child_status" != 1 && "$child_status" != 143 ]]; then failed=true; fi
        if ! cat "$control_directory/server.log" >&2; then failed=true; fi
    fi
    for link in "${links[@]}"; do
        if ip link show dev "$link" >/dev/null 2>&1; then
            if ! ip link del dev "$link"; then failed=true; fi
        fi
    done
    if ! ip -j link show | python3 -c 'import json,sys; sys.exit(any(row["ifname"] in ("routerc0","routerc1","routers0") for row in json.load(sys.stdin)))'; then failed=true; fi
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
    if [[ -f "$control_directory/control.log" ]] && ! cat "$control_directory/control.log" >&2; then failed=true; fi
    if [[ "$mounted" == true ]]; then
        if ! umount "$control_directory"; then failed=true; fi
    fi
    if ! rm -r -- "$control_directory"; then failed=true; fi
    if [[ "$failed" == true ]]; then
        echo "FAIL independent router fixture cleanup" >&2
        if [[ "$status" == 0 ]]; then status=1; fi
    else
        echo "CLEANUP router veth links removed and verified; namespace processes reaped"
    fi
    exit "$status"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mount -t tmpfs -o mode=700 tmpfs "$control_directory"
mounted=true
unshare --net sleep 30 &
client_anchor=$!
unshare --net sleep 30 &
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
ip link add routerc1 type veth peer name client1
links+=(routerc1)
ip link set client1 netns "$client_anchor"
ip link add routers0 type veth peer name server0
links+=(routers0)
ip link set server0 netns "$server_anchor"
ip addr add 198.18.0.1/24 dev routerc0
ip -6 addr add fd77:1::1/64 dev routerc0 nodad
ip addr add 198.20.0.1/24 dev routerc1
ip -6 addr add fd77:3::1/64 dev routerc1 nodad
ip addr add 198.19.0.1/24 dev routers0
ip -6 addr add fd77:2::1/64 dev routers0 nodad
ip link set routerc0 mtu 1600 up
ip link set routerc1 mtu 1600 up
ip link set routers0 mtu 1400 up
# Delay router-generated feedback on its way to the client, inside this
# disposable network namespace. Other traffic retains the default priority.
tc qdisc add dev routerc0 root handle 1: prio priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
tc qdisc add dev routerc0 parent 1:3 handle 30: netem delay 100ms
tc filter add dev routerc0 protocol ip parent 1: prio 1 u32 match ip protocol 1 0xff flowid 1:3
tc filter add dev routerc0 protocol ipv6 parent 1: prio 2 u32 match ip6 protocol 58 0xff flowid 1:3
sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
nsenter --net="/proc/$client_anchor/ns/net" bash -eu -c '
    ip link set lo up
    ip addr add 198.18.0.2/24 dev client0
    ip -6 addr add fd77:1::2/64 dev client0 nodad
    ip addr add 198.20.0.2/24 dev client1
    ip -6 addr add fd77:3::2/64 dev client1 nodad
    ip link set client0 mtu 1600 up
    ip link set client1 mtu 1600 up
    ip route add default via 198.18.0.1
    ip -6 route add default via fd77:1::1
    ip route add 198.20.0.0/24 dev client1 table 100
    ip route add default via 198.20.0.1 dev client1 table 100
    ip rule add from 198.20.0.2/32 table 100
    ip -6 route add fd77:3::/64 dev client1 table 100
    ip -6 route add default via fd77:3::1 dev client1 table 100
    ip -6 rule add from fd77:3::2/128 table 100
'
nsenter --net="/proc/$server_anchor/ns/net" bash -eu -c '
    ip link set lo up
    ip addr add 198.19.0.2/24 dev server0
    ip -6 addr add fd77:2::2/64 dev server0 nodad
    ip link set server0 mtu 1400 up
    ip route add default via 198.19.0.1
    ip -6 route add default via fd77:2::1
'
helper=$(dirname "${BASH_SOURCE[0]}")/run-feasibility-isolated.sh
timeout --signal=TERM --kill-after=2s 16s nsenter --net="/proc/$server_anchor/ns/net" \
    bash "$helper" kernel-mtu "$probe" --router-mtu-peer "$control_directory" > "$control_directory/server.log" 2>&1 &
peer_process=$!
ready=false
for _ in {1..300}; do
    if [[ -f "$control_directory/ready" ]]; then ready=true; break; fi
    if ! kill -0 "$peer_process" 2>/dev/null; then break; fi
    sleep 0.01
done
if [[ "$ready" != true ]]; then echo "FAIL router kernel peer startup" >&2; exit 1; fi
wait_marker() {
    local marker=$1
    for _ in {1..5000}; do
        if [[ -f "$control_directory/$marker" ]]; then return 0; fi
        sleep 0.002
    done
    echo "FAIL router control deadline: $marker" >&2
    return 1
}
supervise_interruptions() {
    local suffix
    for suffix in 00 01 10 11; do
        wait_marker "down.$suffix.request"
        ip link set dev routerc1 down
        : > "$control_directory/down.$suffix.ready"
        wait_marker "up.$suffix.request"
        ip link set dev routerc1 up
        ip -6 addr replace fd77:3::1/64 dev routerc1 nodad
        : > "$control_directory/up.$suffix.ready"
        wait_marker "route.down.$suffix.request"
        if [[ "$suffix" == *0 ]]; then
            nsenter --net="/proc/$client_anchor/ns/net" ip route del default via 198.20.0.1 dev client1 table 100
        else
            nsenter --net="/proc/$client_anchor/ns/net" ip -6 route del default via fd77:3::1 dev client1 table 100
        fi
        : > "$control_directory/route.down.$suffix.ready"
        wait_marker "route.up.$suffix.request"
        if [[ "$suffix" == *0 ]]; then
            nsenter --net="/proc/$client_anchor/ns/net" ip route replace default via 198.20.0.1 dev client1 table 100
        else
            nsenter --net="/proc/$client_anchor/ns/net" ip -6 route replace default via fd77:3::1 dev client1 table 100
        fi
        : > "$control_directory/route.up.$suffix.ready"
    done
}
supervise_interruptions > "$control_directory/control.log" 2>&1 &
control_process=$!
status=0
nsenter --net="/proc/$client_anchor/ns/net" "$probe" --router-mtu-check "$control_directory" || status=$?
if [[ "$status" == 0 ]]; then
    control_status=0
    wait "$control_process" || control_status=$?
    control_process=
    if [[ "$control_status" != 0 ]]; then status=$control_status; fi
fi
: > "$control_directory/stop"
peer_status=0
wait "$peer_process" || peer_status=$?
peer_process=
cat "$control_directory/server.log"
if [[ "$status" == 0 ]]; then status=$peer_status; fi
cleanup "$status"
