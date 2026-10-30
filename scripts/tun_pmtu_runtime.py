# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Genuine kernel-router PMTU errors delivered through the owned TUN runner."""

import asyncio
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

if __package__:
    from . import tun_feasibility as tun
else:
    import tun_feasibility as tun

INTERFACE = "tun-pmtu"
ROUTER = "pmtu-router"
CLIENT = "pmtu-client"
LINK_MTU = 1500

# Fixed synthetic kernel client; all destinations and source tuples are fixture
# inputs. It runs in a separate child network namespace with no resolver use.
CLIENT_PROGRAM = r'''
import asyncio
import sys

async def exchange(destination, source, port, offset, barrier, resumed):
    reader, writer = await asyncio.open_connection(destination, port,
        local_addr=(source, int(sys.argv[2]) + offset))
    try:
        payload = bytes((0x60 + offset,)) * 65536
        prefix = 16384
        writer.write(payload[:prefix])
        await writer.drain()
        if await reader.readexactly(prefix) != payload[:prefix]:
            raise RuntimeError("first-stage bytes changed")
        if await barrier.wait() == 0:
            print("READY", flush=True)
        await resumed.wait()
        writer.write(payload[prefix:])
        await writer.drain()
        writer.write_eof()
        trailer = b"tun-fixture-response-after-fin"
        response = await reader.readexactly(65536 - prefix + len(trailer))
        if response != payload[prefix:] + trailer:
            raise RuntimeError("second-stage bytes changed")
        if await reader.read(1) != b"":
            raise RuntimeError("missing FIN")
    finally:
        writer.close()
        await writer.wait_closed()

async def run():
    ipv6 = sys.argv[1] == "6"
    source = "fd66:66::2" if ipv6 else "10.66.66.2"
    barrier, resumed = asyncio.Barrier(2), asyncio.Event()
    loop = asyncio.get_running_loop()
    control = asyncio.StreamReader(limit=128)
    transport, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(control), sys.stdin)
    async def resume():
        if await control.readline() != b"go\n":
            raise RuntimeError("missing route-change acknowledgement")
        resumed.set()
    try:
        async with asyncio.TaskGroup() as group:
            group.create_task(resume())
            for offset in (1, 2):
                destination = ("fd66:66::" if ipv6 else "10.66.66.") + str(90 + offset)
                group.create_task(exchange(destination, source, 9000 if offset == 1 else 9100, offset, barrier, resumed))
    finally:
        transport.close()

asyncio.run(asyncio.wait_for(run(), 12))
'''


def in_client(anchor, *command):
    subprocess.run(["nsenter", "-t", str(anchor.pid), "-n", *command], check=True)


async def wait_namespace(anchor):
    current = os.readlink("/proc/self/ns/net")
    for _ in range(100):
        if anchor.poll() is not None:
            raise RuntimeError("client namespace anchor exited")
        if os.readlink(f"/proc/{anchor.pid}/ns/net") != current:
            return
        await asyncio.sleep(0.01)
    raise RuntimeError("client namespace setup deadline")


async def exercise(fd, executable, anchor, ipv6, source_port, transition, state=None):
    with tempfile.TemporaryDirectory(prefix="warper-tun-pmtu-", dir=state) as directory, ExitStack() as cleanup:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        cleanup.callback(os.close, directory_fd)
        # Unix socket paths are short even when the checkout/evidence path is
        # long. Keep this directory descriptor alive until both children join.
        base = f"/proc/{os.getpid()}/fd/{directory_fd}"
        local = base + "/fixture.sock"
        remote = base + "/adapter.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as bridge:
            bridge.setblocking(False)
            bridge.bind(local)
            adapter = await asyncio.create_subprocess_exec(executable, "--tun-pmtu-bridge", remote, local, stdout=asyncio.subprocess.PIPE)
            tasks = []
            client = None
            primary = None
            try:
                for _ in range(200):
                    if Path(remote).exists():
                        break
                    if adapter.returncode is not None:
                        raise RuntimeError("adapter ended before readiness")
                    await asyncio.sleep(0.01)
                else:
                    raise RuntimeError("adapter readiness deadline")
                bridge.connect(remote)
                tasks = [asyncio.create_task(tun.from_tun(fd, bridge, ipv6, mtu=LINK_MTU)),
                         asyncio.create_task(tun.to_tun(fd, bridge, ipv6, mtu=LINK_MTU))]
                client = await asyncio.create_subprocess_exec(
                    "nsenter", "-t", str(anchor.pid), "-n", "python3", "-u", "-c", CLIENT_PROGRAM,
                    "6" if ipv6 else "4", str(source_port),
                    stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE)
                if await asyncio.wait_for(client.stdout.readline(), 10) != b"READY\n":
                    raise RuntimeError("client did not complete the first PMTU stage")
                if transition:
                    if ipv6:
                        tun.ip("-6", "route", "replace", "fd66:66::2/128", "dev", ROUTER, "mtu", "1280")
                    else:
                        tun.ip("route", "replace", "10.66.66.2/32", "dev", ROUTER, "mtu", "1280")
                client.stdin.write(b"go\n")
                await client.stdin.drain()
                client.stdin.close()
                if await asyncio.wait_for(client.wait(), 13) != 0:
                    raise RuntimeError("kernel TCP client failed")
                await asyncio.get_running_loop().sock_sendall(bridge, b"")
                if await asyncio.wait_for(adapter.wait(), 2) != 0:
                    raise RuntimeError("PMTU adapter failed or did not verify its sizing report")
                report = json.loads(await adapter.stdout.read(4096))
                expected = 2 if transition else 1
                if report["reductions"] < expected or report["deferred"] < 1 or report["feedback"] < expected:
                    raise RuntimeError("runtime did not complete each genuine router PMTU transition")
                print(f"PASS runtime-owned router feedback: {report}", flush=True)
            except BaseException as error:
                primary = error
            finally:
                for task in tasks:
                    task.cancel()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        if primary is None:
                            primary = result
                        else:
                            print(f"additional PMTU bridge failure: {result}", file=sys.stderr)
                for process in (client, adapter):
                    if process is not None and process.returncode is None:
                        try:
                            process.kill()
                            await asyncio.wait_for(process.wait(), 2)
                        except Exception as error:
                            if primary is None:
                                primary = error
                            else:
                                print(f"additional PMTU child cleanup failure: {error}", file=sys.stderr)
            if primary is not None:
                raise primary


async def run(executable, state=None):
    if not tun.isolated_namespace():
        raise RuntimeError("PMTU fixture requires a fresh single-UID namespace")
    if state is None:
        raise RuntimeError("PMTU fixture requires an owned private state mountpoint")
    state = Path(state)
    evidence = Path(__file__).resolve().parents[1] / "target/evidence/phase-0"
    if not state.is_absolute() or state.is_symlink() or not state.is_dir() or not state.resolve().is_relative_to(evidence.resolve()):
        raise RuntimeError("PMTU state mountpoint must be a real directory under the evidence root")
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    interface = INTERFACE
    anchor = None
    veth = False
    created = False
    mounted = False
    primary = None
    try:
        subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0700,size=1048576,nosuid,nodev", "tmpfs", str(state)], check=True)
        mounted = True
        request = bytearray(40)
        struct.pack_into("16sH", request, 0, INTERFACE.encode(), tun.IFF_TUN | tun.IFF_NO_PI)
        fcntl.ioctl(fd, tun.TUNSETIFF, request, True)
        interface = request[:16].split(b"\0", 1)[0].decode("ascii")
        created = True
        tun.ip("link", "set", "dev", interface, "mtu", str(LINK_MTU), "up")
        tun.ip("addr", "add", "10.66.66.253/32", "dev", interface)
        tun.ip("-6", "addr", "add", "fd66:66::fd/128", "dev", interface, "nodad")
        anchor = subprocess.Popen(["unshare", "--net", "sleep", "60"])
        await wait_namespace(anchor)
        tun.ip("link", "add", ROUTER, "type", "veth", "peer", "name", CLIENT)
        veth = True
        tun.ip("link", "set", CLIENT, "netns", str(anchor.pid))
        tun.ip("addr", "add", "10.66.66.254/24", "dev", ROUTER)
        tun.ip("-6", "addr", "add", "fd66:66::fe/64", "dev", ROUTER, "nodad")
        tun.ip("link", "set", ROUTER, "mtu", str(LINK_MTU), "up")
        in_client(anchor, "ip", "link", "set", "lo", "up")
        in_client(anchor, "ip", "addr", "add", "10.66.66.2/24", "dev", CLIENT)
        in_client(anchor, "ip", "-6", "addr", "add", "fd66:66::2/64", "dev", CLIENT, "nodad")
        in_client(anchor, "ip", "link", "set", CLIENT, "mtu", str(LINK_MTU), "up")
        # Only this disposable router namespace gets forwarding enabled.
        subprocess.run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"], check=True)
        for address in (91, 92):
            tun.ip("route", "add", f"10.66.66.{address}/32", "dev", interface, "src", "10.66.66.254")
            tun.ip("-6", "route", "add", f"fd66:66::{address}/128", "dev", interface, "src", "fd66:66::fe")
            in_client(anchor, "ip", "route", "add", f"10.66.66.{address}/32", "via", "10.66.66.254")
            in_client(anchor, "ip", "-6", "route", "add", f"fd66:66::{address}/128", "via", "fd66:66::fe")
        for mtu in (1400, 1280):
            # A route MTU limits only router egress, leaving 1500-byte client
            # ingress intact. These real kernel routes generate the feedback.
            tun.ip("route", "replace", "10.66.66.2/32", "dev", ROUTER, "mtu", str(mtu))
            tun.ip("-6", "route", "replace", "fd66:66::2/128", "dev", ROUTER, "mtu", str(mtu))
            for ipv6 in (False, True):
                await asyncio.wait_for(exercise(fd, executable, anchor, ipv6, 40000 if mtu == 1400 else 40100, mtu == 1400, str(state)), 17)
                path = "1500->1400->1280" if mtu == 1400 else "1500->1280"
                application_bytes = 2 * (65536 * 2 + len(tun.RESPONSE))
                print(f"PASS routed kernel TUN PMTU: IPv6={ipv6}, path={path}, flows=2, exact_TCP_bytes={application_bytes}, FIN=true", flush=True)
    except BaseException as error:
        primary = error
    finally:
        cleanup_errors = []
        try:
            os.close(fd)
        except OSError as error:
            cleanup_errors.append(error)
        if veth:
            try:
                tun.ip("link", "del", ROUTER)
            except Exception as error:
                cleanup_errors.append(error)
        if anchor is not None:
            if anchor.poll() is None:
                anchor.terminate()
            try:
                anchor.wait(timeout=2)
            except subprocess.TimeoutExpired:
                anchor.kill()
                anchor.wait()
                cleanup_errors.append(RuntimeError("namespace anchor did not stop before deadline"))
        try:
            links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"], text=True))
            if any(link["ifname"] in (interface, ROUTER, CLIENT) for link in links):
                cleanup_errors.append(RuntimeError("PMTU fixture link remained"))
        except Exception as error:
            cleanup_errors.append(error)
        if mounted:
            try:
                subprocess.run(["umount", str(state)], check=True)
            except Exception as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if primary is None:
                primary = cleanup_errors[0]
            else:
                print(f"additional PMTU cleanup failures: {cleanup_errors}", file=sys.stderr)
        else:
            print(f"CLEANUP routed TUN, veth, private state mount and namespace anchor verified; tun_created={created}", flush=True)
    if primary is not None:
        raise primary
