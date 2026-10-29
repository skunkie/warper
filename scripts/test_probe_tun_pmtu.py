# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Check fixture feedback lengths, addresses, quotes and wire checksums."""

import socket
import struct
import unittest

from scripts import probe_tun_pmtu


class FeedbackTests(unittest.TestCase):
    def test_feedback_quotes_packet_and_has_valid_checksums(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                if ipv6:
                    source = socket.inet_pton(socket.AF_INET6, "fd66:67::2")
                    destination = socket.inet_pton(socket.AF_INET6, "fd66:67::91")
                    packet = struct.pack("!IHBB16s16s", 6 << 28, 1408, 17, 64,
                                         source, destination) + bytes(1408)
                else:
                    source = socket.inet_pton(socket.AF_INET, "10.66.67.2")
                    destination = socket.inet_pton(socket.AF_INET, "10.66.67.91")
                    packet = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 1428, 0, 0, 64,
                                         17, 0, source, destination) + bytes(1408)
                response = probe_tun_pmtu.feedback(packet, ipv6)
                header = 40 if ipv6 else 20
                icmp = response[header:]
                self.assertEqual(len(response), 1280 if ipv6 else 576)
                self.assertEqual(icmp[:2], bytes((2, 0) if ipv6 else (3, 4)))
                self.assertEqual(icmp[8:], packet[:1232 if ipv6 else 548])
                self.assertEqual(struct.unpack_from("!I" if ipv6 else "!H", icmp, 4 if ipv6 else 6)[0], 1280)
                if ipv6:
                    self.assertEqual(response[8:24], destination)
                    self.assertEqual(response[24:40], source)
                    pseudo = destination + source + struct.pack("!I3xB", len(icmp), 58)
                    self.assertEqual(probe_tun_pmtu.checksum(pseudo + icmp), 0)
                else:
                    self.assertEqual(response[12:16], destination)
                    self.assertEqual(response[16:20], source)
                    self.assertEqual(probe_tun_pmtu.checksum(response[:20]), 0)
                    self.assertEqual(probe_tun_pmtu.checksum(icmp), 0)


if __name__ == "__main__":
    unittest.main()
