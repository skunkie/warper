# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Exercise the packet bridge without creating a kernel interface."""

import asyncio
import socket
import unittest

from scripts import tun_feasibility


class TunBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_bridge_preserves_packet_boundaries_and_joins_on_cancellation(self):
        tun, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        bridge, adapter = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        for endpoint in (tun, peer, bridge, adapter):
            self.addCleanup(endpoint.close)
            endpoint.setblocking(False)
        loop = asyncio.get_running_loop()
        tasks = [
            asyncio.create_task(tun_feasibility.from_tun(tun.fileno(), bridge)),
            asyncio.create_task(tun_feasibility.to_tun(tun.fileno(), bridge)),
        ]
        try:
            for packet in (b"one", b"two" * 100):
                await loop.sock_sendall(peer, packet)
                self.assertEqual(await asyncio.wait_for(loop.sock_recv(adapter, 1281), 1), packet)
                await loop.sock_sendall(adapter, packet)
                self.assertEqual(await asyncio.wait_for(loop.sock_recv(peer, 1281), 1), packet)
        finally:
            for task in tasks:
                task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            self.assertTrue(all(isinstance(result, asyncio.CancelledError) for result in results))

    async def test_bridge_rejects_oversized_packet(self):
        tun, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        bridge, adapter = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        for endpoint in (tun, peer, bridge, adapter):
            self.addCleanup(endpoint.close)
            endpoint.setblocking(False)
        task = asyncio.create_task(tun_feasibility.from_tun(tun.fileno(), bridge))
        await asyncio.get_running_loop().sock_sendall(peer, b"x" * (tun_feasibility.MTU + 1))
        with self.assertRaisesRegex(RuntimeError, "invalid TUN packet length"):
            await asyncio.wait_for(task, 1)


if __name__ == "__main__":
    unittest.main()
