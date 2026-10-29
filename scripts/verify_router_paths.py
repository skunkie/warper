# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Check the controlled router fixture's point-in-time source-bound routes."""

import argparse
import errno
import json
import socket
import subprocess
import sys


# Linux rtnetlink multicast groups for link, IPv4/IPv6 addresses, routes,
# and rules. IPv6 rules use RTNLGRP_IPV6_RULE (group 19).
CHANGE_GROUPS = 0x1 | 0x10 | 0x100 | 0x40 | 0x400 | 0x80 | (1 << 18)

class NetworkChanged(ValueError):
    """The snapshot observed a network change before it completed."""


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


def main(socket_path=None, after_first_query=None):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as monitor:
        monitor.bind((0, CHANGE_GROUPS))
        monitor.setblocking(False)
        paths = PATHS
        if socket_path is not None:
            source, source_port, destination, destination_port = socket_path
            if not (1 <= source_port <= 65535 and 1 <= destination_port <= 65535):
                raise ValueError("invalid fixture socket port")
            paths = tuple(path for path in PATHS if path[:2] == (destination, source))
            if len(paths) != 1:
                raise ValueError("unexpected fixture socket endpoints")
        for index, (destination, source, gateway, interface) in enumerate(paths):
            command = ["ip", "-j", "route", "get", destination, "from", source]
            if socket_path is not None:
                command += ["ipproto", "udp", "sport", str(source_port), "dport", str(destination_port)]
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            rows = json.loads(result.stdout)
            if not matches_route(rows, destination, source, gateway, interface):
                raise ValueError(f"unexpected fixture route for {source} via {interface}")
            if index == 0 and after_first_query is not None:
                after_first_query()
        try:
            monitor.recvmsg(1)
        except BlockingIOError as error:
            if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
        else:
            raise NetworkChanged("network notification arrived during route lookup")
    if socket_path is None:
        print("PASS source-bound fixture route lookups: IPv4 and IPv6, two paths")
    else:
        print("PASS candidate UDP socket route lookup")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--socket", nargs=4, metavar=("SOURCE", "SPORT", "DESTINATION", "DPORT"))
        args = parser.parse_args()
        socket_path = None
        if args.socket:
            source, source_port, destination, destination_port = args.socket
            socket_path = (source, int(source_port), destination, int(destination_port))
        main(socket_path)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"FAIL fixture route lookup: {error}", file=sys.stderr)
        sys.exit(1)
