#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Privileged control evidence in disposable namespaces, retaining initial userns.

Run reviewed code on a disposable VM (including standard GitHub-hosted Ubuntu).
The outer supervisor never changes resolver, bus, routes or mount propagation.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

QUERY = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07fixture\x07invalid\x00\x00\x01\x00\x01"
BUS_CONFIG = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen>
<auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/>
<allow send_destination="*"/></policy></busconfig>
"""


def command(args, **kwargs):
    return subprocess.run(args, check=True, timeout=10, **kwargs)


def tool(name):
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required fixture tool unavailable: {name}")
    metadata = Path(path).stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError(f"fixture tool is not protected: {name}")
    return path


def namespace_identity(kind):
    metadata = Path(f"/proc/thread-self/ns/{kind}").stat()
    return metadata.st_dev, metadata.st_ino


def require_private_namespace(kind, anchor):
    label = os.readlink(f"/proc/self/fd/{anchor}")
    if not label.startswith(f"{kind}:[") or not label.endswith("]"):
        raise RuntimeError("fixture requires inherited namespace descriptors")
    metadata = os.fstat(anchor)
    if (metadata.st_dev, metadata.st_ino) == namespace_identity(kind):
        raise RuntimeError("fixture requires a distinct mount and network namespace")


def supervise(args, log, *, inherited=(), timeout=30):
    """Own and reap the whole process group, including timeout/failure paths."""
    process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                               pass_fds=inherited, start_new_session=True)
    timed_out = False
    try:
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait(timeout=5)
        return {"code": code, "timed_out": timed_out}
    finally:
        # Also kill descendants left after their immediate supervisor exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


@contextlib.contextmanager
def artifact(directory_fd, name):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o644, dir_fd=directory_fd)
    with os.fdopen(fd, "w") as file:
        os.fchmod(file.fileno(), 0o644)
        yield file


def snapshot():
    """Compare stable host state; exclude route expiry timers and traffic stats."""
    links = json.loads(command([tool("ip"), "-j", "link", "show"], capture_output=True).stdout)
    routes = []
    for family in ("-4", "-6"):
        values = json.loads(command([tool("ip"), "-j", family, "route", "show", "table", "all"], capture_output=True).stdout)
        for value in values:
            value.pop("expires", None)
            value.pop("cache", None)
        routes.append(values)
    resolver = Path("/etc/resolv.conf").read_bytes()
    return {"links": links, "routes": routes,
            "resolver_sha256": hashlib.sha256(resolver).hexdigest()}


def dns_response(query):
    # This is an isolated NXDOMAIN fixture, not the production DNS parser.
    if len(query) < 17 or len(query) > 512 or query[2] & 0x80 or query[4:6] != b"\x00\x01":
        return None
    offset = 12
    total = 0
    while offset < len(query):
        count = query[offset]
        offset += 1
        if count == 0:
            break
        if count > 63 or offset + count > len(query):
            return None
        total += count + 1
        if total > 255:
            return None
        offset += count
    if offset + 4 != len(query):
        return None
    return query[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:]


class Resolver:
    def __init__(self, port=53):
        self.stop = threading.Event()
        self.failures = []
        for attempt in range(8 if port == 0 else 1):
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.tcp.bind(("127.0.0.1", port))
                self.port = self.tcp.getsockname()[1]
                self.udp.bind(("127.0.0.1", self.port))
                self.tcp.listen(4)
                break
            except OSError:
                self.udp.close()
                self.tcp.close()
                if port != 0 or attempt == 7:
                    raise
        self.thread = threading.Thread(target=self.run, name="private-resolver")

    def run(self):
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(self.udp, selectors.EVENT_READ)
                ready.register(self.tcp, selectors.EVENT_READ)
                while not self.stop.is_set():
                    for key, _ in ready.select(0.1):
                        if key.fileobj is self.udp:
                            data, peer = self.udp.recvfrom(513)
                            response = dns_response(data)
                            if response is not None:
                                self.udp.sendto(response, peer)
                        else:
                            client, _ = self.tcp.accept()
                            with client:
                                client.settimeout(1)
                                size = read_exact(client, 2)
                                if len(size) != 2:
                                    continue
                                length = struct.unpack("!H", size)[0]
                                if length > 512:
                                    continue
                                response = dns_response(read_exact(client, length))
                                if response is not None:
                                    client.sendall(struct.pack("!H", len(response)) + response)
        except BaseException as error:
            self.failures.append(type(error).__name__)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, _kind, _error, _traceback):
        self.stop.set()
        self.thread.join(2)
        self.udp.close()
        self.tcp.close()
        if self.thread.is_alive():
            raise RuntimeError("private resolver did not join")
        if self.failures:
            raise RuntimeError("private resolver worker failed")


def read_exact(stream, length):
    result = bytearray()
    while len(result) < length:
        data = stream.recv(length - len(result))
        if not data:
            break
        result.extend(data)
    return bytes(result)


def resolver_health(port=53):
    expected = dns_response(QUERY)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(QUERY, ("127.0.0.1", port))
        if client.recv(512) != expected:
            raise RuntimeError("private UDP resolver health failed")
    with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
        client.sendall(struct.pack("!H", len(QUERY)) + QUERY)
        size = read_exact(client, 2)
        if len(size) != 2 or read_exact(client, struct.unpack("!H", size)[0]) != expected:
            raise RuntimeError("private TCP resolver health failed")


def inner(args):
    require_private_namespace("mnt", args.mount_fd)
    require_private_namespace("net", args.net_fd)
    command([args.probe, "--require-initial-root"])
    mount = tool("mount")
    command([mount, "--make-rprivate", "/"])
    # Entire /run and state parent are private: no host bus/resolver/owner paths.
    for path in ("/run", "/var/lib", "/etc"):
        command([mount, "-t", "tmpfs", "-o", "mode=755", "warper-fixture", path])
    command([mount, "-t", "proc", "proc", "/proc"])
    Path("/run/warper").mkdir(mode=0o755)
    Path("/run/dbus").mkdir(mode=0o755)
    Path("/var/lib/warper").mkdir(mode=0o700)
    Path("/etc/resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
    Path("/etc/passwd").write_text("root:x:0:0:fixture:/root:/bin/false\nowner:x:1000:1000:fixture:/nonexistent:/bin/false\nforeign:x:1001:1001:fixture:/nonexistent:/bin/false\n")
    Path("/etc/group").write_text("root:x:0:\nowner:x:1000:\nforeign:x:1001:\n")
    Path("/etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n")
    Path("/etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    Path("/etc/fixture-bus.conf").write_text(BUS_CONFIG)
    # Clients can execute the reviewed artifact without traversing runner homes.
    shutil.copyfile(args.probe, "/run/warper/peer-probe")
    Path("/run/warper/peer-probe").chmod(0o755)
    command([tool("ip"), "link", "set", "lo", "up"])
    bus = subprocess.Popen([tool("dbus-daemon"), "--nofork", "--nopidfile", "--config-file=/etc/fixture-bus.conf"])
    try:
        deadline = time.monotonic() + 3
        while not Path("/run/dbus/system_bus_socket").exists():
            if bus.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("private bus readiness failed")
            time.sleep(0.01)
        command([tool("dbus-send"), "--bus=unix:path=/run/dbus/system_bus_socket", "--type=method_call", "--print-reply",
                 "/org/freedesktop/DBus", "org.freedesktop.DBus.ListNames"], capture_output=True)
        with Resolver():
            resolver_health()
            command(["/run/warper/peer-probe", "--exercise", str(args.mount_fd), str(args.net_fd)],
                    pass_fds=(args.mount_fd, args.net_fd),
                    env=dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS="unix:path=/run/dbus/system_bus_socket"))
            resolver_health()
        print("PASS dedicated resolver/bus health and joined resolver worker", flush=True)
    finally:
        if bus.poll() is None:
            bus.terminate()
        try:
            bus.wait(timeout=2)
        except subprocess.TimeoutExpired:
            bus.kill()
            bus.wait(timeout=2)
        if bus.returncode not in (0, -signal.SIGTERM):
            raise RuntimeError("private bus worker failed")


def outer(args):
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        run_outer(args, evidence_fd)
    finally:
        os.close(evidence_fd)


def run_outer(args, evidence_fd):
    probe = Path(args.probe).resolve(strict=True)
    before = snapshot()
    after = None
    primary = None
    result = {"probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
              "revision": command(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
              "isolation": "private mount/network/PID namespaces, initial user namespace, private /run /var/lib /etc /proc, dedicated resolver and bus"}
    try:
        command([str(probe), "--require-initial-root"])
        mount_fd = os.open("/proc/thread-self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        try:
            net_fd = os.open("/proc/thread-self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            try:
                isolated_args = [tool("unshare"), "--mount", "--net", "--pid", "--fork", "--kill-child=KILL",
                                 sys.executable, str(Path(__file__).resolve()), "--inner", "--probe", str(probe),
                                 "--mount-fd", str(mount_fd), "--net-fd", str(net_fd)]
                with artifact(evidence_fd, "probe.log") as log:
                    result.update(supervise(isolated_args, log, inherited=(mount_fd, net_fd)))
            finally:
                os.close(net_fd)
        finally:
            os.close(mount_fd)
    except BaseException as error:
        primary = error
        result["primary_error"] = type(error).__name__
    finally:
        try:
            after = snapshot()
            result["host_state_preserved"] = before == after
        except BaseException as error:
            result["host_state_preserved"] = False
            result["cleanup_error"] = type(error).__name__
        for name, value in (("result.json", result), ("host-before.json", before), ("host-after.json", after)):
            with artifact(evidence_fd, name) as file:
                file.write(json.dumps(value, indent=2) + "\n")
    if primary is not None or not result["host_state_preserved"] or result.get("code") != 0 or result.get("timed_out", True):
        raise RuntimeError("privileged control gate or independent host-state check failed") from primary
    print("PASS privileged control gate and independent host-state preservation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--evidence")
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--mount-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--net-fd", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root on a disposable VM; rootless user namespaces are not accepted")
    if args.inner:
        if args.mount_fd is None or args.net_fd is None:
            parser.error("inner fixture requires inherited namespace handles")
        inner(args)
    else:
        if args.evidence is None:
            parser.error("--evidence is required")
        outer(args)


if __name__ == "__main__":
    main()
