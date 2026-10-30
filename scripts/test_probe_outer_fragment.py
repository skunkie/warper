# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Test the bounded outer-fragment fixture without changing host networking."""

import contextlib
import io
import socket
import struct
import unittest
from unittest.mock import MagicMock, call, patch

from scripts import probe_outer_fragment as probe


class FragmentTests(unittest.TestCase):
    def test_extracts_fragment_identity_offsets_and_first_ports(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                header = 48 if ipv6 else 20
                frame = bytearray(14 + header + 8)
                packet = memoryview(frame)[14:]
                packet[0] = 0x60 if ipv6 else 0x45
                packet[6 if ipv6 else 9] = 44 if ipv6 else socket.IPPROTO_UDP
                if ipv6:
                    packet[40] = socket.IPPROTO_UDP
                    struct.pack_into("!HI", packet, 42, 1, 42)
                else:
                    struct.pack_into("!H", packet, 4, 42)
                    struct.pack_into("!H", packet, 6, 0x2000)
                struct.pack_into("!HH", packet, header, 41001, 9000)
                self.assertEqual(probe.fragment(frame, ipv6), (42, 0, True, (41001, 9000), header + 8))
                if ipv6:
                    struct.pack_into("!H", packet, 42, 8)
                else:
                    struct.pack_into("!H", packet, 6, 1)
                self.assertEqual(probe.fragment(frame, ipv6), (42, 8, False, None, header + 8))
                self.assertIsNone(probe.fragment(frame[:15], ipv6))
                self.assertIsNone(probe.fragment(frame, not ipv6))

    def test_non_linux_is_rejected_before_namespace_inspection(self):
        with patch.object(probe.sys, "platform", "darwin"), patch.object(probe, "isolated_namespace") as isolated:
            with self.assertRaisesRegex(RuntimeError, "requires Linux"):
                probe.run()
            isolated.assert_not_called()

    def test_wrong_fragmentation_mode_fails_before_send(self):
        receiver, sender = MagicMock(), MagicMock()
        receiver.__enter__.return_value = receiver
        sender.__enter__.return_value = sender
        sender.getsockopt.return_value = 2
        with patch.object(probe.socket, "socket", side_effect=[receiver, sender]):
            with self.assertRaisesRegex(RuntimeError, "fragmentation mode"):
                probe.exercise(MagicMock(), False)
        sender.sendto.assert_not_called()
        receiver.__exit__.assert_called_once()
        sender.__exit__.assert_called_once()

    def test_changed_payload_is_rejected_before_empty_datagram(self):
        receiver, sender = MagicMock(), MagicMock()
        receiver.__enter__.return_value = receiver
        sender.__enter__.return_value = sender
        receiver.getsockname.return_value = ("127.0.0.1", 9000)
        sender.getsockname.return_value = ("127.0.0.1", 41001)
        sender.getsockopt.return_value = 0
        sender.sendto.return_value = len(probe.PAYLOAD)
        receiver.recvfrom.return_value = (b"synthetic-wrong", ("127.0.0.1", 41001))
        with patch.object(probe.socket, "socket", side_effect=[receiver, sender]):
            with self.assertRaisesRegex(RuntimeError, "payload or source changed"):
                probe.exercise(MagicMock(), False)
        self.assertEqual(sender.sendto.call_count, 1)
        receiver.__exit__.assert_called_once()
        sender.__exit__.assert_called_once()

    def test_fragment_observation_capacity_fails_closed(self):
        receiver, sender, capture = MagicMock(), MagicMock(), MagicMock()
        receiver.__enter__.return_value = receiver
        sender.__enter__.return_value = sender
        receiver.getsockname.return_value = ("127.0.0.1", 9000)
        sender.getsockname.return_value = ("127.0.0.1", 41001)
        sender.getsockopt.return_value = 0
        sender.sendto.side_effect = [len(probe.PAYLOAD), 0]
        receiver.recvfrom.side_effect = [(probe.PAYLOAD, ("127.0.0.1", 41001)),
                                        (b"", ("127.0.0.1", 41001))]
        fragments = [(identity, 0, True, (1, 2), 100) for identity in range(9)]
        with (patch.object(probe.socket, "socket", side_effect=[receiver, sender]),
              patch.object(probe.select, "select", return_value=([capture], [], [])),
              patch.object(probe.time, "monotonic", return_value=0),
              patch.object(probe, "fragment", side_effect=fragments)):
            with self.assertRaisesRegex(RuntimeError, "observation capacity"):
                probe.exercise(capture, False)
        self.assertEqual(capture.recv.call_count, 9)
        receiver.__exit__.assert_called_once()
        sender.__exit__.assert_called_once()

    def test_namespace_guard_precedes_network_inspection(self):
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe, "isolated_namespace", return_value=False),
              patch.object(probe, "link_state") as state):
            with self.assertRaisesRegex(RuntimeError, "fresh single-UID"):
                probe.run()
            state.assert_not_called()

    def test_fixture_failure_restores_original_loopback_state(self):
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe.socket, "AF_PACKET", 17, create=True),
              patch.object(probe, "isolated_namespace", return_value=True),
              patch.object(probe, "link_state", side_effect=[(1500, False), (1500, False)]),
              patch.object(probe, "configure_loopback") as configure,
              patch.object(probe.socket, "socket"),
              patch.object(probe, "exercise", side_effect=RuntimeError("fixture failed")),
              contextlib.redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(RuntimeError, "fixture failed"):
                probe.run()
            self.assertEqual(configure.call_args_list, [call(1280, True), call(1500, False)])

    def test_cleanup_failure_preserves_primary_error(self):
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe.socket, "AF_PACKET", 17, create=True),
              patch.object(probe, "isolated_namespace", return_value=True),
              patch.object(probe, "link_state", return_value=(1500, False)),
              patch.object(probe, "configure_loopback", side_effect=[None, OSError("cleanup failed")]),
              patch.object(probe.socket, "socket"),
              patch.object(probe, "exercise", side_effect=RuntimeError("fixture failed")),
              contextlib.redirect_stderr(io.StringIO()) as errors):
            with self.assertRaisesRegex(RuntimeError, "fixture failed"):
                probe.run()
            self.assertIn("cleanup failed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
