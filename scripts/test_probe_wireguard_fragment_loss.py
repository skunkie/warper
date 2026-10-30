# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Safeguards for the isolated fragment loss fixture."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import probe_wireguard_fragment_loss as probe


class FragmentLossTests(unittest.TestCase):
    def test_unmapped_namespace_is_rejected_before_mutation(self):
        with (patch.object(probe.sys, "platform", "linux"),
              patch.object(probe, "isolated_namespace", return_value=False),
              patch.object(probe, "qdiscs") as qdiscs):
            with self.assertRaisesRegex(RuntimeError, "mapped Linux namespace"):
                probe.run("/synthetic")
            qdiscs.assert_not_called()

    def test_existing_qdisc_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.touch(mode=0o700)
            with (patch.object(probe.sys, "platform", "linux"),
                  patch.object(probe, "isolated_namespace", return_value=True),
                  patch.object(probe, "qdiscs", return_value=[{"kind": "clsact"}]),
                  patch.object(probe, "configure_loopback") as configure):
                with self.assertRaisesRegex(RuntimeError, "already has"):
                    probe.run(str(binary))
                configure.assert_not_called()

    def test_drop_counter_only_counts_owned_action(self):
        entries = [{"pref": 10, "protocol": "ip", "options": {"actions": [
            {"kind": "gact", "control_action": {"type": "drop"}, "stats": {"drops": 3}}]}},
            {"pref": 20, "protocol": "ipv6", "options": {"actions": [
                {"kind": "gact", "control_action": {"type": "pass"}, "stats": {"drops": 9}}]}}]
        with patch.object(probe, "filters", return_value=entries):
            self.assertEqual(probe.dropped(False), 3)
            self.assertEqual(probe.dropped(True), 0)

    def test_child_failure_is_reported_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(7)\n")
            os.chmod(binary, 0o700)
            with self.assertRaisesRegex(RuntimeError, "fragment loss fixture"):
                probe.run_child(str(binary))

    def test_incomplete_child_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_text("#!/usr/bin/env python3\n")
            os.chmod(binary, 0o700)
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                probe.run_child(str(binary))
