# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Check fixture route lookup validation with synthetic kernel results."""

import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from verify_router_paths import main, matches_route


class RouteLookupTests(unittest.TestCase):
    def test_requires_one_unicast_route_with_expected_source_gateway_and_interface(self):
        expected = ("198.19.0.2", "198.20.0.2", "198.20.0.1", "client1")
        route = dict(zip(("dst", "from", "gateway", "dev"), expected))
        self.assertTrue(matches_route([route], *expected))
        for key in route:
            self.assertFalse(matches_route([{**route, key: "unexpected"}], *expected), key)
        for rows in ([], [route, route], {}, [None], [{**route, "type": "blackhole"}],
                     [{**route, "multipath": []}], [{**route, "nexthops": []}]):
            self.assertFalse(matches_route(rows, *expected), repr(rows))

    def test_lookup_fails_on_invalid_json_or_command_timeout(self):
        with patch("verify_router_paths.subprocess.run", return_value=SimpleNamespace(stdout="{")):
            with self.assertRaises(ValueError):
                main()
        with patch("verify_router_paths.subprocess.run", side_effect=subprocess.TimeoutExpired("ip", 2)):
            with self.assertRaises(subprocess.TimeoutExpired):
                main()


if __name__ == "__main__":
    unittest.main()
