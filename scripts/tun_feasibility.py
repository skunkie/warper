#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Run kernel socket traffic through a disposable TUN and the Rust adapter."""

import asyncio
import fcntl
import json
import os
from pathlib import Path
import socket
import signal
import struct
import subprocess
import sys
import tempfile

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
# Linux UAPI values; force kernel fragmentation for this isolated fixture.
IP_MTU_DISCOVER = 10
IPV6_MTU_DISCOVER = 23
PMTUDISC_DONT = 0
INTERFACE = "tun-feasibility"
MTU = 1280
TRANSFER = 65536
RESPONSE = b"tun-fixture-response-after-fin"


def isolated_namespace():
    fields = Path("/proc/self/uid_map").read_text().split()
    return len(fields) == 3 and fields[0] == "0" and fields[2] == "1" and fields[1].isdigit()


def ip(*args):
    subprocess.run(["ip", *args], check=True)


async def ready(fd, *, write=False):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    register = loop.add_writer if write else loop.add_reader
    remove = loop.remove_writer if write else loop.remove_reader
    register(fd, lambda: not future.done() and future.set_result(None))
    try:
        await future
    finally:
        remove(fd)


def boundary_udp_flow(packet, ipv6):
    header = 40 if ipv6 else 20
    version = 6 if ipv6 else 4
    if (len(packet) != MTU or packet[0] >> 4 != version
            or packet[6 if ipv6 else 9] != socket.IPPROTO_UDP
            or (not ipv6 and packet[0] & 0x0F != 5)):
        return None
    if ipv6:
        if struct.unpack_from("!H", packet, 4)[0] != MTU - header:
            return None
    elif (struct.unpack_from("!H", packet, 2)[0] != MTU
          or struct.unpack_from("!H", packet, 6)[0] & 0x3FFF):
        return None
    source, destination, length = struct.unpack_from("!HHH", packet, header)
    if length != MTU - header:
        return None
    return source, destination


def udp_fragment(packet, ipv6):
    if ipv6:
        if len(packet) < 48 or packet[0] >> 4 != 6 or packet[6] != 44 or packet[40] != socket.IPPROTO_UDP:
            return None
        field = struct.unpack_from("!H", packet, 42)[0]
        identity = struct.unpack_from("!I", packet, 44)[0]
        destination = socket.inet_ntop(socket.AF_INET6, packet[24:40])
        return destination, identity, field >> 3, bool(field & 1)
    if len(packet) < 20 or packet[0] != 0x45 or packet[9] != socket.IPPROTO_UDP:
        return None
    field = struct.unpack_from("!H", packet, 6)[0]
    if not field & 0x3FFF:
        return None
    identity = struct.unpack_from("!H", packet, 4)[0]
    destination = socket.inet_ntop(socket.AF_INET, packet[16:20])
    return destination, identity, field & 0x1FFF, bool(field & 0x2000)


async def from_tun(fd, bridge, ipv6=False, boundary=None, fragments=None):
    loop = asyncio.get_running_loop()
    while True:
        await ready(fd)
        try:
            packet = os.read(fd, MTU + 1)
        except BlockingIOError:
            continue
        if not packet or len(packet) > MTU:
            raise RuntimeError("invalid TUN packet length")
        if boundary is not None:
            flow = boundary_udp_flow(packet, ipv6)
            if flow is not None:
                boundary.add(flow)
        if fragments is not None:
            fragment = udp_fragment(packet, ipv6)
            if fragment is not None:
                destination, identity, offset, more = fragment
                key = (destination, identity)
                if key not in fragments and len(fragments) >= 4:
                    raise RuntimeError("fragment observation capacity exceeded")
                observed = fragments.setdefault(key, set())
                if (offset, more) not in observed and len(observed) >= 4:
                    raise RuntimeError("fragment range observation capacity exceeded")
                observed.add((offset, more))
        await loop.sock_sendall(bridge, packet)


async def to_tun(fd, bridge, ipv6=False, boundary=None):
    loop = asyncio.get_running_loop()
    while True:
        packet = await loop.sock_recv(bridge, MTU + 1)
        if not packet or len(packet) > MTU:
            raise RuntimeError("invalid adapter packet length")
        while True:
            try:
                written = os.write(fd, packet)
                break
            except BlockingIOError:
                await ready(fd, write=True)
        if written != len(packet):
            raise RuntimeError("partial TUN packet write")
        if boundary is not None:
            flow = boundary_udp_flow(packet, ipv6)
            if flow is not None:
                boundary.add(flow)


async def tcp_exchange(source, destination, offset):
    reader, writer = await asyncio.open_connection(
        destination, 9000 if offset == 1 else 9100,
        local_addr=(source, 40000 + offset),
    )
    try:
        payload = bytes((0x60 + offset,)) * TRANSFER
        writer.write(payload[:1024])
        await writer.drain()
        if await reader.readexactly(1024) != payload[:1024]:
            raise RuntimeError("TCP full-duplex prefix changed")
        if not writer.can_write_eof():
            raise RuntimeError("TCP half-close unavailable")

        async def send_remaining():
            writer.write(payload[1024:])
            await writer.drain()
            writer.write_eof()

        async def receive_remaining():
            if await reader.readexactly(TRANSFER - 1024) != payload[1024:]:
                raise RuntimeError("TCP full-duplex payload changed")
            return await reader.readexactly(len(RESPONSE))

        async with asyncio.TaskGroup() as group:
            group.create_task(send_remaining())
            response_task = group.create_task(receive_remaining())
        response = response_task.result()
        if response != RESPONSE or await reader.read(1) != b"":
            raise RuntimeError("TCP response or EOF changed")
    finally:
        writer.close()
        await writer.wait_closed()


async def udp_exchange(source, destination, offset, ipv6):
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.setblocking(False)
        client.bind((source, 41000 + offset))
        target = (destination, 9000 if offset == 1 else 9100)
        maximum = MTU - (48 if ipv6 else 28)
        client.setsockopt(socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP,
                          IPV6_MTU_DISCOVER if ipv6 else IP_MTU_DISCOVER, PMTUDISC_DONT)
        await loop.sock_sendto(client, b"\x7f" * (maximum + 1), target)
        try:
            await asyncio.wait_for(loop.sock_recvfrom(client, MTU + 1), 0.2)
        except TimeoutError:
            pass
        else:
            raise RuntimeError("oversized fragmented UDP received a reply")
        for payload in (b"", b"\x31", b"\x72" * 257, b"\x53" * maximum):
            await loop.sock_sendto(client, payload, target)
            actual, sender = await loop.sock_recvfrom(client, MTU + 1)
            if actual != payload or sender[:2] != target:
                raise RuntimeError("UDP datagram or source changed")


async def exchange(fd, executable, ipv6, directory, crash_after_udp=False):
    loop = asyncio.get_running_loop()
    local = str(Path(directory) / "fixture.sock")
    remote = str(Path(directory) / "adapter.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as bridge:
        bridge.setblocking(False)
        bridge.bind(local)
        process = await asyncio.create_subprocess_exec(executable, "--tun-bridge", remote, local)
        tasks = []
        try:
            for _ in range(200):
                if os.path.exists(remote):
                    break
                if process.returncode is not None:
                    raise RuntimeError("adapter exited before bridge setup")
                await asyncio.sleep(0.01)
            else:
                raise RuntimeError("adapter bridge setup deadline exceeded")
            bridge.connect(remote)
            ingress_boundary, egress_boundary, fragments = set(), set(), {}
            tasks = [asyncio.create_task(from_tun(fd, bridge, ipv6, ingress_boundary, fragments)),
                     asyncio.create_task(to_tun(fd, bridge, ipv6, egress_boundary))]
            source = "fd66:66::2" if ipv6 else "10.66.66.2"
            destinations = ("fd66:66::91", "fd66:66::92") if ipv6 else ("10.66.66.91", "10.66.66.92")
            # Keep both UDP associations live concurrently to exercise dispatch.
            async with asyncio.TaskGroup() as group:
                for i, destination in enumerate(destinations, 1):
                    group.create_task(udp_exchange(source, destination, i, ipv6))
            if crash_after_udp:
                # Stop the external packet bridge before killing its peer so
                # teardown cannot race a send against the dead Unix socket.
                for task in tasks:
                    task.cancel()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                tasks = []
                for result in results:
                    if isinstance(result, Exception):
                        raise RuntimeError("packet bridge failed before adapter kill") from result
                process.kill()
                if await asyncio.wait_for(process.wait(), 2) != -signal.SIGKILL:
                    raise RuntimeError("adapter did not terminate with SIGKILL")
                print(f"PASS adapter SIGKILL after TUN UDP traffic: IPv6={ipv6}", flush=True)
                return
            async with asyncio.TaskGroup() as group:
                for i, destination in enumerate(destinations, 1):
                    group.create_task(tcp_exchange(source, destination, i))
            if ingress_boundary != {(41001, 9000), (41002, 9100)} or egress_boundary != {(9000, 41001), (9100, 41002)}:
                raise RuntimeError("maximum UDP datagrams did not cross the TUN at its MTU")
            for destination in destinations:
                if not any(address == destination and (0, True) in observed
                           and any(offset > 0 and not more for offset, more in observed)
                           for (address, _), observed in fragments.items()):
                    raise RuntimeError("oversized UDP did not produce a complete kernel fragment set")
            await loop.sock_sendall(bridge, b"")
            if await asyncio.wait_for(process.wait(), 2) != 0:
                raise RuntimeError("adapter failed during shutdown")
            for task in tasks:
                if task.done():
                    task.result()
            print(f"PASS kernel TUN 64 KiB TCP, 1280-byte UDP and oversized UDP fragment rejection: IPv6={ipv6}", flush=True)
        finally:
            primary = sys.exception()
            for task in tasks:
                task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            cleanup_errors = []
            for result in results:
                if isinstance(result, Exception):
                    cleanup_errors.append(str(result))
            if process.returncode is None:
                process.kill()
                await process.wait()
            if cleanup_errors:
                if primary is not None:
                    print(f"bridge cleanup failures: {cleanup_errors}", file=sys.stderr)
                else:
                    raise RuntimeError(f"bridge cleanup failures: {cleanup_errors}")


async def run(executable, crash_after_udp=False):
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
        ip("link", "set", "dev", INTERFACE, "mtu", str(MTU), "up")
        ip("addr", "add", "10.66.66.2/32", "dev", INTERFACE)
        ip("-6", "addr", "add", "fd66:66::2/128", "dev", INTERFACE, "nodad")
        ip("route", "add", "10.66.66.0/24", "dev", INTERFACE)
        ip("-6", "route", "add", "fd66:66::/64", "dev", INTERFACE)
        for ipv6 in (False, True):
            if crash_after_udp:
                with tempfile.TemporaryDirectory(prefix="warper-tun-") as directory:
                    await asyncio.wait_for(exchange(fd, executable, ipv6, directory, True), 12)
            with tempfile.TemporaryDirectory(prefix="warper-tun-") as directory:
                await asyncio.wait_for(exchange(fd, executable, ipv6, directory), 12)
    except BaseException as error:
        primary = error
    finally:
        os.close(fd)
        if created:
            try:
                result = subprocess.run(["ip", "-j", "link", "show"], check=True, capture_output=True, text=True)
                if any(link["ifname"] == INTERFACE for link in json.loads(result.stdout)):
                    raise RuntimeError("TUN interface remained after descriptor close")
                print("CLEANUP TUN descriptor closed and interface removal verified", flush=True)
            except Exception as error:
                if primary is None:
                    primary = error
                else:
                    print(f"TUN cleanup failure: {error}", file=sys.stderr)
    if primary is not None:
        raise primary


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--crash-after-udp"):
        raise SystemExit("usage: tun_feasibility.py HOST_STACK_EXECUTABLE [--crash-after-udp]")
    asyncio.run(run(sys.argv[1], len(sys.argv) == 3))
