# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Failure ownership checks for the routed TUN fixture without host mutation."""

import asyncio
import socket
import types
import unittest
from unittest.mock import AsyncMock, patch

from scripts import tun_pmtu_runtime as fixture


class FakeProcess:
    def __init__(self):
        self.returncode = None
        self.joined = False
        self.stdout = types.SimpleNamespace(readline=AsyncMock(return_value=b""))

    def kill(self):
        self.returncode = -9

    async def wait(self):
        self.joined = True
        return self.returncode


class TunPmtuRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_namespace_guard_precedes_device_and_process_creation(self):
        with patch.object(fixture.tun, "isolated_namespace", return_value=False), \
             patch.object(fixture.os, "open") as device, \
             patch.object(fixture.subprocess, "Popen") as process:
            with self.assertRaises(RuntimeError):
                await fixture.run("unused-probe")
            device.assert_not_called()
            process.assert_not_called()

    async def test_missing_private_state_precedes_device_or_process_mutation(self):
        with patch.object(fixture.tun, "isolated_namespace", return_value=True), \
             patch.object(fixture.os, "open") as device, \
             patch.object(fixture.subprocess, "Popen") as process:
            with self.assertRaises(RuntimeError):
                await fixture.run("unused-probe")
            device.assert_not_called()
            process.assert_not_called()

    async def test_client_readiness_failure_joins_owned_children_and_bridge_tasks(self):
        tun, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(tun.close)
        self.addCleanup(peer.close)
        adapter, client = FakeProcess(), FakeProcess()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(server.close)
        processes = iter([adapter, client])

        async def start(*arguments, **_options):
            process = next(processes)
            if process is adapter:
                server.bind(arguments[2])
            return process

        with patch.object(fixture.asyncio, "create_subprocess_exec", side_effect=start), \
             patch.object(fixture.tun, "ip") as mutation:
            with self.assertRaises(RuntimeError):
                await asyncio.wait_for(fixture.exercise(
                    tun.fileno(), "synthetic-probe", types.SimpleNamespace(pid=123),
                    False, 40000, True), 1)
            mutation.assert_not_called()
        self.assertEqual(adapter.returncode, -9)
        self.assertEqual(client.returncode, -9)
        self.assertTrue(adapter.joined and client.joined)

    async def test_namespace_anchor_failure_cannot_become_readiness(self):
        anchor = types.SimpleNamespace(pid=123, poll=lambda: 1)
        with patch.object(fixture.os, "readlink", return_value="synthetic-parent"):
            with self.assertRaises(RuntimeError):
                await fixture.wait_namespace(anchor)
