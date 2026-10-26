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
    def run_harness(self, *, probe="wireguard-stack", probe_exit=0, scope="--packet-only", build_exit=0, rekey=False, mapping="0 1000 1", cleanup_exit=0):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "scripts").mkdir()
        harness = root / "scripts/verify-feasibility.sh"
        shutil.copyfile(Path(__file__).with_name("verify-feasibility.sh"), harness)
        shutil.copyfile(Path(__file__).with_name("run-feasibility-isolated.sh"), root / "scripts/run-feasibility-isolated.sh")
        (root / "Cargo.lock").write_text("# synthetic lockfile\n")
        tools = root / "tools"
        tools.mkdir()
        commands = {
            "cargo": f'if [[ "$1" == build ]]; then exit {build_exit}; fi\necho fixture-cargo\n',
            "rustc": "echo fixture-rustc\n",
            "git": 'if [[ "$1" == rev-parse ]]; then echo fixture-revision; fi\n',
            # Only the namespace launcher is replaced. The real timeout still
            # supervises a real child; these tests do not claim network isolation.
            "unshare": 'while [[ "$1" != bash ]]; do shift; done\nexec "$@"\n',
            "ip": f'echo "$*" >> "{root}/ip-commands.log"\nif [[ "$1" == -j ]]; then echo "[]"; fi\nif [[ "$1 $2" == "link del" ]]; then exit {cleanup_exit}; fi\n',
            "cat": f'if [[ "$1" == /proc/self/uid_map ]]; then echo "{mapping}"; else exec /bin/cat "$@"; fi\n',
        }
        for name, source in commands.items():
            path = tools / name
            path.write_text("#!/usr/bin/env bash\nset -eu\n" + source)
            path.chmod(0o700)
        executable = root / f"target/debug/{probe}"
        executable.parent.mkdir(parents=True)
        executable.write_text(f'#!/bin/sh\necho fixture-probe "$@"\nexit {probe_exit}\n')
        executable.chmod(0o700)
        environment = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}")
        arguments = ["bash", str(harness), probe]
        if scope:
            arguments.append(scope)
        if rekey:
            arguments.append("--rekey")
        result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=10)
        evidence = list((root / "target/evidence/phase-0").glob(f"{probe}.*"))
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

    def test_mtu_scope_reaches_host_probe_and_preserves_unsupported_exit(self):
        result, evidence = self.run_harness(probe="host-stack", scope="--mtu-check", probe_exit=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("fixture-probe --mtu-check", (evidence / "probe.log").read_text())
        self.assertIn("mtu_probe_exit=1", (evidence / "result.txt").read_text())
        self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_mtu_scope_rejects_wireguard_before_build_or_network_setup(self):
        result = subprocess.run(["bash", str(Path(__file__).with_name("verify-feasibility.sh")), "wireguard-stack", "--mtu-check"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--mtu-check requires host-stack", result.stderr)

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

    def test_rekey_argument_reaches_probe_and_result_records_its_status(self):
        result, evidence = self.run_harness(rekey=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-probe --rekey", (evidence / "probe.log").read_text())
        outcome = (evidence / "result.txt").read_text()
        self.assertIn("rekey_probe_exit=0", outcome)
        self.assertNotIn("NOT RUN long-lived rekey", outcome)

    def test_kernel_peer_is_removed_and_verified_after_success(self):
        result, evidence = self.run_harness(scope="--kernel-peer")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-probe --kernel-peer", (evidence / "probe.log").read_text())
        self.assertIn("CLEANUP independent kernel WireGuard interface removed and verified", result.stdout)
        self.assertIn("kernel_peer_probe_exit=0", (evidence / "result.txt").read_text())

    def test_failed_kernel_probe_still_removes_interface(self):
        result, _ = self.run_harness(scope="--kernel-peer", probe_exit=7)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("CLEANUP independent kernel WireGuard interface removed and verified", result.stdout)

    def test_kernel_cleanup_failure_cannot_report_success(self):
        result, evidence = self.run_harness(scope="--kernel-peer", cleanup_exit=9)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("FAIL independent kernel interface cleanup", (evidence / "probe.log").read_text())

    def test_probe_failure_is_preserved_when_kernel_cleanup_also_fails(self):
        result, evidence = self.run_harness(scope="--kernel-peer", probe_exit=7, cleanup_exit=9)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("FAIL independent kernel interface cleanup", (evidence / "probe.log").read_text())

    def test_initial_user_namespace_is_rejected_before_network_mutation(self):
        result, evidence = self.run_harness(scope="--kernel-peer", mapping="0 0 4294967295")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("requires a fresh single-UID", (evidence / "probe.log").read_text())
        self.assertFalse((evidence.parents[3] / "ip-commands.log").exists())


if __name__ == "__main__":
    unittest.main()
