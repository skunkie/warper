#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Observe connected Linux UDP sender behavior after isolated TUN feedback."""

import asyncio
import errno
import fcntl
import json
import os
import socket
import struct
import subprocess
import sys

from scripts.tun_feasibility import IFF_NO_PI, IFF_TUN, TUNSETIFF, ip, isolated_namespace, ready

INTERFACE = "pmtu-test"
INITIAL_MTU = 1500
REDUCED_MTU = 1280


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def feedback(packet, ipv6):
    """Construct a fixture-only ICMP response quoting the captured UDP packet."""
    if ipv6:
        source, destination = packet[24:40], packet[8:24]
        icmp = struct.pack("!BBHI", 2, 0, 0, REDUCED_MTU) + packet[:1232]
        pseudo = source + destination + struct.pack("!I3xB", len(icmp), 58)
        icmp = icmp[:2] + struct.pack("!H", checksum(pseudo + icmp)) + icmp[4:]
        return struct.pack("!IHBB16s16s", 6 << 28, len(icmp), 58, 64, source, destination) + icmp
    source, destination = packet[16:20], packet[12:16]
    icmp = struct.pack("!BBHHH", 3, 4, 0, 0, REDUCED_MTU) + packet[:548]
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0,
                         source, destination)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + icmp


async def read_udp(fd, ipv6, source, destination, payload):
    """Ignore unrelated kernel control packets while awaiting this fixture datagram."""
    version = 6 if ipv6 else 4
    header = 40 if ipv6 else 20
    source_bytes = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, source)
    destination_bytes = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, destination)
    while True:
        await ready(fd)
        try:
            packet = os.read(fd, INITIAL_MTU + 1)
        except BlockingIOError:
            continue
        if len(packet) != header + 8 + len(payload) or packet[0] >> 4 != version:
            continue
        protocol = packet[6 if ipv6 else 9]
        addresses = (packet[8:24], packet[24:40]) if ipv6 else (packet[12:16], packet[16:20])
        if (protocol == socket.IPPROTO_UDP and addresses == (source_bytes, destination_bytes)
                and struct.unpack_from("!HH", packet, header) == (41001, 9000)
                and packet[header + 8:] == payload):
            return packet


async def exercise(fd, ipv6):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    level = socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP
    discover = 23 if ipv6 else 10  # IPV6_MTU_DISCOVER / IP_MTU_DISCOVER
    mtu_option = 24 if ipv6 else 14  # IPV6_MTU / IP_MTU
    source = "fd66:67::2" if ipv6 else "10.66.67.2"
    destination = "fd66:67::91" if ipv6 else "10.66.67.91"
    with socket.socket(family, socket.SOCK_DGRAM) as sender:
        sender.setblocking(False)
        sender.setsockopt(level, discover, 2)  # PMTUDISC_DO
        sender.bind((source, 41001))
        sender.connect((destination, 9000))
        if sender.getsockopt(level, mtu_option) != INITIAL_MTU:
            raise RuntimeError("unexpected initial path MTU")
        payload = b"\x71" * 1400
        if sender.send(payload) != len(payload):
            raise RuntimeError("partial UDP send")
        packet = await read_udp(fd, ipv6, source, destination, payload)
        response = feedback(packet, ipv6)
        if os.write(fd, response) != len(response):
            raise RuntimeError("partial TUN feedback write")
        for _ in range(100):
            if sender.getsockopt(level, mtu_option) == REDUCED_MTU:
                break
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("kernel did not apply feedback before deadline")
        if sender.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != errno.EMSGSIZE:
            raise RuntimeError("missing asynchronous too-big error")
        try:
            sender.send(payload)
        except OSError as error:
            if error.errno != errno.EMSGSIZE:
                raise
        else:
            raise RuntimeError("oversized send unexpectedly succeeded")
        small = b"\x53" * 1200
        if sender.send(small) != len(small):
            raise RuntimeError("partial reduced UDP send")
        await read_udp(fd, ipv6, source, destination, small)
        print(f"PASS Linux UDP path MTU 1500 to 1280, oversized refusal and smaller send: IPv6={ipv6}", flush=True)


async def run():
    if not isolated_namespace():
        raise RuntimeError("TUN fixture requires a fresh single-UID user namespace")
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    created = False
    primary = None
    try:
        request = bytearray(40)
        struct.pack_into("16sH", request, 0, INTERFACE.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, request, True)
        created = True
        ip("link", "set", "dev", INTERFACE, "mtu", str(INITIAL_MTU), "up")
        ip("addr", "add", "10.66.67.2/32", "dev", INTERFACE)
        ip("-6", "addr", "add", "fd66:67::2/128", "dev", INTERFACE, "nodad")
        ip("route", "add", "10.66.67.0/24", "dev", INTERFACE)
        ip("-6", "route", "add", "fd66:67::/64", "dev", INTERFACE)
        for ipv6 in (False, True):
            await asyncio.wait_for(exercise(fd, ipv6), 5)
    except BaseException as error:
        primary = error
    finally:
        os.close(fd)
        if created:
            try:
                result = subprocess.run(["ip", "-j", "link", "show"], check=True,
                                        capture_output=True, text=True)
                if any(link["ifname"] == INTERFACE for link in json.loads(result.stdout)):
                    raise RuntimeError("TUN interface remained after descriptor close")
                print("CLEANUP TUN interface removal verified", flush=True)
            except Exception as error:
                if primary is None:
                    primary = error
                else:
                    print(f"TUN cleanup failure: {error}", file=sys.stderr, flush=True)
    if primary is not None:
        raise primary


if __name__ == "__main__":
    asyncio.run(run())
