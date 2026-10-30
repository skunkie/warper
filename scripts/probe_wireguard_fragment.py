#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Observe encrypted WireGuard UDP fragments in disposable Linux namespaces."""

import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import time

from scripts.probe_outer_fragment import MTU, configure_loopback, fragment, link_state
from scripts.tun_feasibility import isolated_namespace

MAX_OBSERVATIONS = 64
MAX_CHILD_OUTPUT = 16384


def observe(frame, observations, completed):
    """Track bounded fragment metadata without retaining packet payloads."""
    for ipv6 in (False, True):
        if ipv6 in completed:
            continue
        item = fragment(frame, ipv6)
        if item is None:
            continue
        identity, offset, more, ports, length = item
        if length > MTU:
            raise RuntimeError("observed encrypted fragment exceeds link MTU")
        packet = frame[14:]
        addresses = bytes(packet[8:40] if ipv6 else packet[12:20])
        key = (ipv6, addresses, identity)
        if key not in observations and len(observations) >= MAX_OBSERVATIONS:
            raise RuntimeError("encrypted fragment observation capacity exceeded")
        first_ports, final = observations.get(key, (None, False))
        header = 48 if ipv6 else 20
        if offset == 0 and more and ports is not None:
            # WireGuard data messages have a four-byte little-endian type 4.
            if packet[header + 8:header + 12] == b"\x04\x00\x00\x00":
                first_ports = ports
        if offset > 0 and not more:
            final = True
        observations[key] = first_ports, final
        directions = {first for (family, _, _), (first, last) in observations.items()
                      if family == ipv6 and first is not None and last}
        if any(source != destination and (destination, source) in directions
               for source, destination in directions):
            completed.add(ipv6)


def run_child(binary, capture, kernel_peer=False):
    flag = "--kernel-outer-fragment-check" if kernel_peer else "--outer-fragment-check"
    child = subprocess.Popen([binary, flag], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, bufsize=0)
    output = bytearray()
    observations, completed = {}, set()
    deadline = time.monotonic() + (90 if kernel_peer else 30)
    pipe_open = True
    try:
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(capture, selectors.EVENT_READ, "capture")
            selector.register(child.stdout, selectors.EVENT_READ, "child")
            while child.poll() is None or pipe_open or len(completed) != 2:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("encrypted fragment fixture deadline exceeded")
                events = selector.select(min(remaining, 0.1))
                if not events and child.poll() is not None and not pipe_open:
                    raise RuntimeError("encrypted fragment observations are incomplete")
                for key, _ in events:
                    if key.data == "capture":
                        try:
                            frame = capture.recv(65535)
                        except BlockingIOError:
                            continue
                        observe(frame, observations, completed)
                    else:
                        try:
                            chunk = os.read(child.stdout.fileno(), 4096)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(child.stdout)
                            pipe_open = False
                        elif len(output) + len(chunk) > MAX_CHILD_OUTPUT:
                            raise RuntimeError("encrypted fixture output capacity exceeded")
                        else:
                            output.extend(chunk)
                if child.poll() is not None and not pipe_open and child.returncode != 0:
                    raise RuntimeError(f"encrypted fixture failed with exit {child.returncode}")
        if child.returncode != 0:
            raise RuntimeError(f"encrypted fixture failed with exit {child.returncode}")
        lines = output.decode(errors="replace").splitlines()
        prefix = "independent kernel outer fragmentation" if kernel_peer else "encrypted outer fragmentation"
        expected = {f"PASS {prefix}: inner_ipv6={inner}, outer_ipv6={outer}"
                    for inner in ("false", "true") for outer in ("false", "true")}
        if not kernel_peer:
            expected.update({f"PASS outer no-fragment negative control: outer_ipv6={outer}"
                             for outer in ("false", "true")})
        if not expected.issubset(lines):
            raise RuntimeError("encrypted fixture did not report all family combinations and controls")
        print("PASS captured bidirectional fragmented WireGuard data: outer IPv4 and IPv6", flush=True)
        if kernel_peer:
            print("PASS independent kernel WireGuard peer: all family combinations", flush=True)
        else:
            print("PASS kernel no-fragment size-error controls: outer IPv4 and IPv6", flush=True)
    finally:
        primary = sys.exception()
        cleanup = []
        try:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
        except Exception as error:
            cleanup.append(str(error))
        try:
            child.stdout.close()
        except Exception as error:
            cleanup.append(str(error))
        if cleanup:
            if primary is None:
                raise RuntimeError(f"encrypted fixture cleanup failed: {cleanup}")
            print(f"encrypted fixture cleanup failures: {cleanup}", file=sys.stderr, flush=True)


def run(binary, kernel_peer=False):
    if sys.platform != "linux":
        raise RuntimeError("encrypted fragment fixture requires Linux")
    if not isolated_namespace():
        raise RuntimeError("encrypted fragment fixture requires a fresh single-UID user namespace")
    path = Path(binary)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("binary must be an absolute path to an executable file")
    original = link_state()
    primary = None
    try:
        configure_loopback(MTU, True)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
            capture.bind(("lo", 0))
            capture.setblocking(False)
            run_child(str(path), capture, kernel_peer)
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
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--kernel-peer"):
        raise SystemExit("usage: python3 -m scripts.probe_wireguard_fragment ABSOLUTE_BINARY [--kernel-peer]")
    run(sys.argv[1], len(sys.argv) == 3)
