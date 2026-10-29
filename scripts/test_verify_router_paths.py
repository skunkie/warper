# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Check fixture route lookup validation with synthetic kernel results."""

import errno
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from verify_router_paths import PATHS, main, matches_route


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
        with patch("verify_router_paths.socket.socket"):
            with patch("verify_router_paths.subprocess.run", return_value=SimpleNamespace(stdout="{")):
                with self.assertRaises(ValueError):
                    main()
            with patch("verify_router_paths.subprocess.run", side_effect=subprocess.TimeoutExpired("ip", 2)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    main()

    def test_idle_subscription_accepts_verified_routes(self):
        results = [
            SimpleNamespace(stdout=json.dumps([dict(zip(("dst", "from", "gateway", "dev"), path))]))
            for path in PATHS
        ]
        with patch("verify_router_paths.socket.socket") as factory:
            monitor = factory.return_value.__enter__.return_value
            monitor.recvmsg.side_effect = BlockingIOError(errno.EAGAIN, "idle")
            with patch("verify_router_paths.subprocess.run", side_effect=results):
                main()
            monitor.recvmsg.assert_called_once_with(1)

    def test_change_or_notification_loss_during_lookup_rejects_snapshot(self):
        results = [
            SimpleNamespace(stdout=json.dumps([dict(zip(("dst", "from", "gateway", "dev"), path))]))
            for path in PATHS
        ]
        for outcome in ((b"x", [], 0, (0, 0)), OSError("notification loss"), BlockingIOError(errno.EINPROGRESS, "uncertain")):
            with self.subTest(outcome=outcome):
                with patch("verify_router_paths.socket.socket") as factory:
                    monitor = factory.return_value.__enter__.return_value
                    if isinstance(outcome, OSError):
                        monitor.recvmsg.side_effect = outcome
                    else:
                        monitor.recvmsg.return_value = outcome
                    with patch("verify_router_paths.subprocess.run", side_effect=results):
                        with self.assertRaises((ValueError, OSError)):
                            main()
                    monitor.bind.assert_called_once()
                    monitor.setblocking.assert_called_once_with(False)


if __name__ == "__main__":
    unittest.main()
