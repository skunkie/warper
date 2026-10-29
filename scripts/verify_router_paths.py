# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Check the controlled router fixture's point-in-time source-bound routes."""

import json
import subprocess
import sys


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
    print("PASS source-bound fixture route lookups: IPv4 and IPv6, two paths")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"FAIL fixture route lookup: {error}", file=sys.stderr)
        sys.exit(1)
