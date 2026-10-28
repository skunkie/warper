# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Exercise the packet bridge without creating a kernel interface."""

import asyncio
import socket
import struct
import unittest

from scripts import tun_feasibility


class TunBridgeTests(unittest.IsolatedAsyncioTestCase):
    def test_boundary_udp_flow_checks_family_length_and_protocol(self):
        for ipv6 in (False, True):
            header = 40 if ipv6 else 20
            packet = bytearray(tun_feasibility.MTU)
            packet[0] = 0x60 if ipv6 else 0x45
            packet[6 if ipv6 else 9] = socket.IPPROTO_UDP
            struct.pack_into("!H", packet, 4 if ipv6 else 2, tun_feasibility.MTU - header if ipv6 else tun_feasibility.MTU)
            struct.pack_into("!HHH", packet, header, 41001, 9000, tun_feasibility.MTU - header)
            self.assertEqual(tun_feasibility.boundary_udp_flow(packet, ipv6), (41001, 9000))
            self.assertIsNone(tun_feasibility.boundary_udp_flow(packet[:-1], ipv6))
            self.assertIsNone(tun_feasibility.boundary_udp_flow(packet, not ipv6))
            packet[6 if ipv6 else 9] = socket.IPPROTO_TCP
            self.assertIsNone(tun_feasibility.boundary_udp_flow(packet, ipv6))
            packet[6 if ipv6 else 9] = socket.IPPROTO_UDP
            if not ipv6:
                struct.pack_into("!H", packet, 6, 0x2000)
                self.assertIsNone(tun_feasibility.boundary_udp_flow(packet, ipv6))
                struct.pack_into("!H", packet, 6, 0)
            struct.pack_into("!H", packet, header + 4, 8)
            self.assertIsNone(tun_feasibility.boundary_udp_flow(packet, ipv6))

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
