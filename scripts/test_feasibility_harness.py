# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Check evidence and failure propagation without privileges or networking."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class FeasibilityHarnessTests(unittest.TestCase):
    def run_harness(self, *, probe_exit=0, scope="--packet-only", build_exit=0):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "scripts").mkdir()
        harness = root / "scripts/verify-feasibility.sh"
        shutil.copyfile(Path(__file__).with_name("verify-feasibility.sh"), harness)
        (root / "Cargo.lock").write_text("# synthetic lockfile\n")
        tools = root / "tools"
        tools.mkdir()
        commands = {
            "cargo": f'if [[ "$1" == build ]]; then exit {build_exit}; fi\necho fixture-cargo\n',
            "rustc": "echo fixture-rustc\n",
            "git": 'if [[ "$1" == rev-parse ]]; then echo fixture-revision; fi\n',
            # Only the namespace launcher is replaced. The real timeout still
            # supervises a real child; these tests do not claim network isolation.
            "unshare": 'exec "${@: -1}"\n',
            "ip": "exit 0\n",
        }
        for name, source in commands.items():
            path = tools / name
            path.write_text("#!/usr/bin/env bash\nset -eu\n" + source)
            path.chmod(0o700)
        executable = root / "target/debug/wireguard-stack"
        executable.parent.mkdir(parents=True)
        executable.write_text(f"#!/bin/sh\necho fixture-probe\nexit {probe_exit}\n")
        executable.chmod(0o700)
        environment = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}")
        arguments = ["bash", str(harness), "wireguard-stack"]
        if scope:
            arguments.append(scope)
        result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=10)
        evidence = list((root / "target/evidence/phase-0").glob("wireguard-stack.*"))
        self.assertEqual(len(evidence), 1, result.stderr)
        return result, evidence[0]

    def test_packet_success_records_scope_and_unrun_gates(self):
        result, evidence = self.run_harness()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-probe", (evidence / "probe.log").read_text())
        outcome = (evidence / "result.txt").read_text()
        self.assertIn("PASS packet-only", outcome)
        self.assertIn("NOT RUN kernel TUN/utun", outcome)
        self.assertTrue((evidence / "Cargo.lock").is_file())

    def test_packet_success_cannot_pass_full_gate(self):
        result, evidence = self.run_harness(scope="")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("INCOMPLETE full feasibility gate", (evidence / "result.txt").read_text())

    def test_probe_failure_is_preserved_with_evidence(self):
        result, evidence = self.run_harness(probe_exit=7)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("probe_exit=7", (evidence / "result.txt").read_text())

    def test_build_failure_does_not_run_probe(self):
        result, evidence = self.run_harness(build_exit=9)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((evidence / "result.txt").read_text(), "FAIL build\n")
        self.assertFalse((evidence / "probe.log").exists())


if __name__ == "__main__":
    unittest.main()
