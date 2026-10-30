#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Observe Linux UDP fragmentation inside disposable namespaces."""

import json
import select
import socket
import struct
import subprocess
import sys
import time

from scripts.tun_feasibility import isolated_namespace

MTU = 1280
PAYLOAD = bytes((0x53,)) * 1312


def link_state():
    result = subprocess.run(["ip", "-j", "link", "show", "dev", "lo"], check=True,
                            capture_output=True, text=True)
    links = json.loads(result.stdout)
    if len(links) != 1:
        raise RuntimeError("unexpected loopback inventory")
    return links[0]["mtu"], "UP" in links[0]["flags"]


def configure_loopback(mtu, up):
    subprocess.run(["ip", "link", "set", "dev", "lo", "mtu", str(mtu),
                    "up" if up else "down"], check=True)


def fragment(frame, ipv6):
    """Return identity, offset, more flag, first UDP ports and IP length."""
    if len(frame) < 14:
        return None
    packet = frame[14:]
    if ipv6:
        if len(packet) < 48 or packet[0] >> 4 != 6 or packet[6] != 44 or packet[40] != socket.IPPROTO_UDP:
            return None
        field = struct.unpack_from("!H", packet, 42)[0]
        offset = field & 0xFFF8
        identity = struct.unpack_from("!I", packet, 44)[0]
        more = bool(field & 1)
        header = 48
    else:
        if len(packet) < 20 or packet[0] != 0x45 or packet[9] != socket.IPPROTO_UDP:
            return None
        field = struct.unpack_from("!H", packet, 6)[0]
        offset = (field & 0x1FFF) * 8
        more = bool(field & 0x2000)
        if not offset and not more:
            return None
        identity = struct.unpack_from("!H", packet, 4)[0]
        header = 20
    if not offset:
        if len(packet) < header + 8:
            return None
        ports = struct.unpack_from("!HH", packet, header)
    else:
        ports = None
    return identity, offset, more, ports, len(packet)


def exercise(capture, ipv6):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    address = "::1" if ipv6 else "127.0.0.1"
    level = socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP
    discover = 23 if ipv6 else 10  # IPV6_MTU_DISCOVER / IP_MTU_DISCOVER
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((address, 0))
        receiver.settimeout(2)
        sender.settimeout(2)
        sender.bind((address, 0))
        sender.setsockopt(level, discover, 0)  # PMTUDISC_DONT
        if sender.getsockopt(level, discover) != 0:
            raise RuntimeError("fragmentation mode was not applied")
        ports = (sender.getsockname()[1], receiver.getsockname()[1])
        if sender.sendto(PAYLOAD, receiver.getsockname()) != len(PAYLOAD):
            raise RuntimeError("partial UDP send")
        actual, peer = receiver.recvfrom(len(PAYLOAD) + 1)
        if actual != PAYLOAD or peer[:2] != sender.getsockname()[:2]:
            raise RuntimeError("fragmented UDP payload or source changed")
        if sender.sendto(b"", receiver.getsockname()) != 0:
            raise RuntimeError("empty UDP send changed")
        actual, peer = receiver.recvfrom(1)
        if actual != b"" or peer[:2] != sender.getsockname()[:2]:
            raise RuntimeError("empty UDP datagram or source changed")
        fragments = {}
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            ready, _, _ = select.select([capture], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            try:
                item = fragment(capture.recv(65535), ipv6)
            except BlockingIOError:
                continue
            if item is None:
                continue
            identity, offset, more, first_ports, length = item
            if length > MTU:
                raise RuntimeError("observed outer fragment exceeds link MTU")
            # The namespace contains only this fixture; bound observations even
            # if the kernel produces unexpected unrelated control traffic.
            if identity not in fragments and len(fragments) >= 8:
                raise RuntimeError("fragment observation capacity exceeded")
            observations = fragments.setdefault(identity, set())
            if len(observations) >= 8 and (offset, more, first_ports) not in observations:
                raise RuntimeError("fragment range capacity exceeded")
            observations.add((offset, more, first_ports))
            if any((0, True, ports) in observed and any(off > 0 and not flag for off, flag, _ in observed)
                   for observed in fragments.values()):
                break
        else:
            raise RuntimeError("fragment capture deadline exceeded")
        if not any((0, True, ports) in observed and any(off > 0 and not flag for off, flag, _ in observed)
                   for observed in fragments.values()):
            raise RuntimeError("expected complete outer UDP fragment set not observed")
        print(f"PASS fragmented outer UDP and empty datagram: IPv6={ipv6}", flush=True)


def run():
    if sys.platform != "linux":
        raise RuntimeError("outer fragment fixture requires Linux")
    if not isolated_namespace():
        raise RuntimeError("fragment fixture requires a fresh single-UID user namespace")
    original = link_state()
    primary = None
    try:
        configure_loopback(MTU, True)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
            capture.bind(("lo", 0))
            capture.setblocking(False)
            for ipv6 in (False, True):
                exercise(capture, ipv6)
    except BaseException as error:
        primary = error
    finally:
        try:
            configure_loopback(*original)
            if link_state() != original:
                raise RuntimeError("loopback state was not restored")
            print("CLEANUP loopback MTU and link state restored", flush=True)
        except Exception as error:
            if primary is None:
                primary = error
            else:
                print(f"loopback cleanup failure: {error}", file=sys.stderr, flush=True)
    if primary is not None:
        raise primary


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("usage: python3 -m scripts.probe_outer_fragment")
    run()
