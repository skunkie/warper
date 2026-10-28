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
import struct
import subprocess
import sys
import tempfile

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
INTERFACE = "tun-feasibility"
MTU = 1280
REQUEST = b"tun-fixture-request"
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


async def from_tun(fd, bridge):
    loop = asyncio.get_running_loop()
    while True:
        await ready(fd)
        try:
            packet = os.read(fd, MTU + 1)
        except BlockingIOError:
            continue
        if not packet or len(packet) > MTU:
            raise RuntimeError("invalid TUN packet length")
        await loop.sock_sendall(bridge, packet)


async def to_tun(fd, bridge):
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


async def tcp_exchange(source, destination, offset):
    reader, writer = await asyncio.open_connection(
        destination, 9000 if offset == 1 else 9100,
        local_addr=(source, 40000 + offset),
    )
    try:
        writer.write(REQUEST)
        await writer.drain()
        if not writer.can_write_eof():
            raise RuntimeError("TCP half-close unavailable")
        writer.write_eof()
        response = await reader.readexactly(len(RESPONSE))
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
        for payload in (b"", b"\x31", b"\x72" * 257):
            await loop.sock_sendto(client, payload, target)
            actual, sender = await loop.sock_recvfrom(client, 1024)
            if actual != payload or sender[:2] != target:
                raise RuntimeError("UDP datagram or source changed")


async def exchange(fd, executable, ipv6, directory):
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
            tasks = [asyncio.create_task(from_tun(fd, bridge)), asyncio.create_task(to_tun(fd, bridge))]
            source = "fd66:66::2" if ipv6 else "10.66.66.2"
            destinations = ("fd66:66::91", "fd66:66::92") if ipv6 else ("10.66.66.91", "10.66.66.92")
            # Keep both UDP associations live concurrently to exercise dispatch.
            await asyncio.gather(*(udp_exchange(source, dest, i, ipv6) for i, dest in enumerate(destinations, 1)))
            await asyncio.gather(*(tcp_exchange(source, dest, i) for i, dest in enumerate(destinations, 1)))
            await loop.sock_sendall(bridge, b"")
            if await asyncio.wait_for(process.wait(), 2) != 0:
                raise RuntimeError("adapter failed during shutdown")
            for task in tasks:
                if task.done():
                    task.result()
            print(f"PASS kernel TUN TCP/UDP metadata, half-close and boundaries: IPv6={ipv6}", flush=True)
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


async def run(executable):
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
    if len(sys.argv) != 2:
        raise SystemExit("usage: tun_feasibility.py HOST_STACK_EXECUTABLE")
    asyncio.run(run(sys.argv[1]))
