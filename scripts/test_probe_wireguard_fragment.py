# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Test bounded encrypted-fragment observation and fixture safeguards."""

import contextlib
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from scripts import probe_wireguard_fragment as probe


class EncryptedFragmentTests(unittest.TestCase):
    def test_observes_only_wireguard_data_fragment_sets(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                header = 48 if ipv6 else 20
                frame = bytearray(14 + header + 12)
                frame[14 + header + 8:14 + header + 12] = b"\x04\x00\x00\x00"
                observations, completed = {}, set()
                items = [(42, 0, True, (41001, 9000), 100), None,
                         (42, 8, False, None, 100), None]
                if ipv6:
                    items = [None, items[0], None, items[2]]
                with patch.object(probe, "fragment", side_effect=items):
                    probe.observe(frame, observations, completed)
                    probe.observe(frame, observations, completed)
                self.assertEqual(completed, {ipv6})

    def test_final_fragment_can_precede_wireguard_first_fragment(self):
        frame = bytearray(14 + 20 + 12)
        frame[14 + 20 + 8:14 + 20 + 12] = b"\x04\x00\x00\x00"
        observations, completed = {}, set()
        with patch.object(probe, "fragment", side_effect=[(1, 8, False, None, 100), None,
                                                          (1, 0, True, (1, 2), 100), None]):
            probe.observe(frame, observations, completed)
            probe.observe(frame, observations, completed)
        self.assertEqual(completed, {False})

    def test_unrelated_fragment_does_not_count_as_wireguard(self):
        frame = bytearray(14 + 20 + 12)
        observations, completed = {}, set()
        with patch.object(probe, "fragment", side_effect=[(1, 0, True, (1, 2), 100), None,
                                                          (1, 8, False, None, 100), None]):
            probe.observe(frame, observations, completed)
            probe.observe(frame, observations, completed)
        self.assertFalse(completed)

    def test_observation_capacity_and_fragment_size_fail_closed(self):
        frame = bytearray(14 + 20 + 12)
        with patch.object(probe, "fragment", return_value=(1, 0, True, (1, 2), probe.MTU + 1)):
            with self.assertRaisesRegex(RuntimeError, "exceeds link MTU"):
                probe.observe(frame, {}, set())
        observations = {(False, b"test", index): (False, False) for index in range(probe.MAX_OBSERVATIONS)}
        with patch.object(probe, "fragment", return_value=(100, 0, True, (1, 2), 100)):
            with self.assertRaisesRegex(RuntimeError, "observation capacity"):
                probe.observe(frame, observations, set())

    def test_cli_rejects_missing_or_extra_arguments(self):
        for arguments in ([], ["/synthetic", "extra"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, "-m", "scripts.probe_wireguard_fragment", *arguments],
                                        capture_output=True, text=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("usage:", result.stderr)

    def test_non_linux_and_unmapped_namespace_are_rejected(self):
        with (patch.object(probe.sys, "platform", "darwin"),
              patch.object(probe, "isolated_namespace") as isolated):
            with self.assertRaisesRegex(RuntimeError, "requires Linux"):
                probe.run("/synthetic-binary")
            isolated.assert_not_called()
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe, "isolated_namespace", return_value=False),
              patch.object(probe, "link_state") as state):
            with self.assertRaisesRegex(RuntimeError, "single-UID"):
                probe.run("/synthetic-binary")
            state.assert_not_called()

    def test_child_failure_is_reported_and_process_is_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text("#!/usr/bin/env python3\nimport sys\nprint('synthetic failure')\nsys.exit(7)\n")
            os.chmod(binary, 0o700)
            capture, peer = socket.socketpair()
            with capture, peer:
                capture.setblocking(False)
                with self.assertRaisesRegex(RuntimeError, "exit 7"):
                    probe.run_child(str(binary), capture)
                self.assertGreaterEqual(peer.fileno(), 0)

    def test_child_output_capacity_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text("#!/usr/bin/env python3\nprint('x' * 20000)\n")
            os.chmod(binary, 0o700)
            capture, peer = socket.socketpair()
            with capture, peer:
                capture.setblocking(False)
                with self.assertRaisesRegex(RuntimeError, "output capacity"):
                    probe.run_child(str(binary), capture)

    def test_child_deadline_terminates_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n")
            os.chmod(binary, 0o700)
            capture, peer = socket.socketpair()
            with capture, peer, patch.object(probe.time, "monotonic", side_effect=[0, 31]):
                capture.setblocking(False)
                with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
                    probe.run_child(str(binary), capture)

    def test_successful_child_without_fragments_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text("#!/usr/bin/env python3\n")
            os.chmod(binary, 0o700)
            capture, peer = socket.socketpair()
            with capture, peer:
                capture.setblocking(False)
                with self.assertRaisesRegex(RuntimeError, "observations are incomplete"):
                    probe.run_child(str(binary), capture)
                self.assertGreaterEqual(peer.fileno(), 0)

    def test_invalid_binary_is_rejected_before_network_mutation(self):
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe, "isolated_namespace", return_value=True),
              patch.object(probe, "link_state") as state):
            with self.assertRaisesRegex(ValueError, "absolute path"):
                probe.run("relative-binary")
            state.assert_not_called()

    def test_cleanup_error_does_not_replace_child_error(self):
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe.socket, "AF_PACKET", 17, create=True),
              patch.object(probe, "isolated_namespace", return_value=True),
              patch.object(probe.Path, "is_file", return_value=True),
              patch.object(probe.os, "access", return_value=True),
              patch.object(probe, "link_state", return_value=(1500, False)),
              patch.object(probe, "configure_loopback", side_effect=[None, OSError("cleanup failed")]),
              patch.object(probe.socket, "socket", return_value=MagicMock()),
              patch.object(probe, "run_child", side_effect=RuntimeError("child failed")),
              contextlib.redirect_stderr(io.StringIO()) as errors):
            with self.assertRaisesRegex(RuntimeError, "child failed"):
                probe.run("/synthetic-binary")
            self.assertIn("cleanup failed", errors.getvalue())

    def test_child_failure_restores_loopback_and_preserves_error(self):
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe.socket, "AF_PACKET", 17, create=True),
              patch.object(probe, "isolated_namespace", return_value=True),
              patch.object(probe.Path, "is_file", return_value=True),
              patch.object(probe.os, "access", return_value=True),
              patch.object(probe, "link_state", side_effect=[(1500, False), (1500, False)]),
              patch.object(probe, "configure_loopback") as configure,
              patch.object(probe.socket, "socket", return_value=MagicMock()),
              patch.object(probe, "run_child", side_effect=RuntimeError("child failed")),
              contextlib.redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(RuntimeError, "child failed"):
                probe.run("/synthetic-binary")
            self.assertEqual(configure.call_count, 2)
            configure.assert_called_with(1500, False)


if __name__ == "__main__":
    unittest.main()
