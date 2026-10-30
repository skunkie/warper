#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Drop outer WireGuard fragment tails in a disposable Linux namespace."""

import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

from scripts.probe_outer_fragment import MTU, configure_loopback, link_state
from scripts.tun_feasibility import isolated_namespace


def tc(*args):
    result = subprocess.run(["tc", *args], check=True, capture_output=True,
                            text=True, timeout=3)
    return result.stdout


def qdiscs():
    return json.loads(tc("-j", "qdisc", "show", "dev", "lo"))


def filters():
    return json.loads(tc("-j", "-s", "filter", "show", "dev", "lo", "egress"))


def add_filter(outer):
    if outer:
        args = ["ipv6", "20", "match", "u8", "44", "0xff", "at", "6",
                "match", "u16", "0x04d0", "0xfff8", "at", "42"]
    else:
        args = ["ip", "10", "match", "ip", "protocol", "17", "0xff",
                "match", "u16", "0x009d", "0x1fff", "at", "6"]
    tc("filter", "add", "dev", "lo", "egress", "protocol", args[0],
       "pref", args[1], "u32", *args[2:], "action", "drop")


def remove_filter(outer):
    tc("filter", "del", "dev", "lo", "egress", "protocol",
       "ipv6" if outer else "ip", "pref", "20" if outer else "10")


def dropped(outer):
    pref, protocol = (20, "ipv6") if outer else (10, "ip")
    actions = [action for entry in filters()
               if entry.get("pref") == pref and entry.get("protocol") == protocol
               for action in entry.get("options", {}).get("actions", [])
               if action.get("kind") == "gact" and
               action.get("control_action", {}).get("type") == "drop"]
    return sum(action.get("stats", {}).get("drops", 0) for action in actions)


def run_child(binary):
    child = subprocess.Popen([binary, "--kernel-outer-fragment-loss"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    expected = [(inner, outer) for inner in (0, 1) for outer in (0, 1)]
    index, active, output, buffer = 0, None, 0, bytearray()
    expected_passes = {f"PASS fragmented outer loss: inner_ipv6={inner}, outer_ipv6={outer}"
                       for inner in ("false", "true") for outer in ("false", "true")}
    passed = set()
    deadline = time.monotonic() + 120
    try:
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                if time.monotonic() >= deadline:
                    raise RuntimeError("fragment loss fixture deadline exceeded")
                events = selector.select(0.1)
                if not events and child.poll() is not None:
                    raise RuntimeError(f"fragment loss fixture exited early: {child.returncode}")
                for _, _ in events:
                    chunk = os.read(child.stdout.fileno(), 4096)
                    if not chunk:
                        if child.wait(timeout=2) != 0 or index != len(expected) or active is not None or passed != expected_passes:
                            raise RuntimeError("fragment loss fixture incomplete")
                        return
                    output += len(chunk)
                    if output > 16384:
                        raise RuntimeError("fragment loss fixture output capacity exceeded")
                    buffer.extend(chunk)
                    while b"\n" in buffer:
                        raw, _, remainder = buffer.partition(b"\n")
                        buffer = bytearray(remainder)
                        line = raw.decode("ascii", errors="replace")
                        parts = line.split()
                        if len(parts) == 3 and parts[0] in ("READY", "RELEASE"):
                            case = tuple(int(value) for value in parts[1:])
                            if index >= len(expected) or case != expected[index]:
                                raise RuntimeError("unexpected fragment loss case")
                            if parts[0] == "READY" and active is None:
                                add_filter(case[1]); active = case[1]
                                child.stdin.write(b"D"); child.stdin.flush()
                            elif parts[0] == "RELEASE" and active == case[1]:
                                count = dropped(active)
                                if count < 1:
                                    raise RuntimeError("fragment filter recorded no drops")
                                remove_filter(active); active = None; index += 1
                                child.stdin.write(b"R"); child.stdin.flush()
                                print(f"PASS fragment drops: inner_ipv6={bool(case[0])}, outer_ipv6={bool(case[1])}, count={count}", flush=True)
                            else:
                                raise RuntimeError("invalid fragment loss control sequence")
                        elif line.startswith("PASS fragmented outer loss: "):
                            passed.add(line)
    finally:
        primary = sys.exception()
        errors = []
        if child.poll() is None:
            child.kill()
        try:
            child.wait(timeout=2)
            child.stdin.close(); child.stdout.close()
        except Exception as error:
            errors.append(str(error))
        if active is not None:
            try:
                remove_filter(active)
            except Exception as error:
                errors.append(str(error))
        if errors:
            if primary is None:
                raise RuntimeError(f"fragment loss child cleanup failed: {errors}")
            print(f"fragment loss child cleanup failed: {errors}", file=sys.stderr, flush=True)


def run(binary):
    if sys.platform != "linux" or not isolated_namespace():
        raise RuntimeError("fragment loss fixture requires a fresh mapped Linux namespace")
    path = Path(binary)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("binary must be an absolute path to an executable file")
    if any(q.get("kind") == "clsact" for q in qdiscs()):
        raise RuntimeError("loopback already has a clsact qdisc")
    original = link_state()
    owned = False
    primary = None
    try:
        configure_loopback(MTU, True)
        tc("qdisc", "add", "dev", "lo", "clsact"); owned = True
        run_child(str(path))
    except BaseException as error:
        primary = error
    finally:
        try:
            if owned:
                entries = [q for q in qdiscs() if q.get("kind") == "clsact"]
                if len(entries) != 1 or entries[0].get("handle") != "ffff:" or filters():
                    raise RuntimeError("loopback qdisc ownership changed")
                tc("qdisc", "del", "dev", "lo", "clsact")
                if any(q.get("kind") == "clsact" for q in qdiscs()):
                    raise RuntimeError("loopback qdisc remains")
        except Exception as error:
            if primary is None:
                primary = error
            else:
                print(f"qdisc cleanup failed: {error}", file=sys.stderr, flush=True)
        try:
            configure_loopback(*original)
            if link_state() != original:
                raise RuntimeError("loopback state was not restored")
            print("CLEANUP loopback MTU and link state restored", flush=True)
        except Exception as error:
            if primary is None:
                primary = error
            else:
                print(f"loopback cleanup failed: {error}", file=sys.stderr, flush=True)
    if primary is not None:
        raise primary


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 -m scripts.probe_wireguard_fragment_loss ABSOLUTE_BINARY")
    run(sys.argv[1])
