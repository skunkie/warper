# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Check the controlled router fixture's point-in-time source-bound routes."""

import errno
import json
import socket
import subprocess
import sys


# Linux rtnetlink multicast groups for link, IPv4/IPv6 addresses, routes,
# and rules. IPv6 rules use RTNLGRP_IPV6_RULE (group 19).
CHANGE_GROUPS = 0x1 | 0x10 | 0x100 | 0x40 | 0x400 | 0x80 | (1 << 18)

PATHS = (
    ("198.19.0.2", "198.18.0.2", "198.18.0.1", "client0"),
    ("198.19.0.2", "198.20.0.2", "198.20.0.1", "client1"),
    ("fd77:2::2", "fd77:1::2", "fd77:1::1", "client0"),
    ("fd77:2::2", "fd77:3::2", "fd77:3::1", "client1"),
)


def matches_route(rows, destination, source, gateway, interface):
    """Reject ambiguous or unexpected kernel route lookup results."""
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return False
    row = rows[0]
    return (
        row.get("dst") == destination
        and row.get("from") == source
        and row.get("gateway") == gateway
        and row.get("dev") == interface
        and row.get("type", "unicast") == "unicast"
        and "multipath" not in row
        and "nexthops" not in row
    )


def main():
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as monitor:
        monitor.bind((0, CHANGE_GROUPS))
        monitor.setblocking(False)
        for destination, source, gateway, interface in PATHS:
            result = subprocess.run(
                ["ip", "-j", "route", "get", destination, "from", source],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            rows = json.loads(result.stdout)
            if not matches_route(rows, destination, source, gateway, interface):
                raise ValueError(f"unexpected fixture route for {source} via {interface}")
        try:
            monitor.recvmsg(1)
        except BlockingIOError as error:
            if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
        else:
            raise ValueError("network notification arrived during route lookup")
    print("PASS source-bound fixture route lookups: IPv4 and IPv6, two paths")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"FAIL fixture route lookup: {error}", file=sys.stderr)
        sys.exit(1)
