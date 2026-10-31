#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Unprivileged failure/cleanup checks for the real privileged CI fixture."""

import contextlib
import json
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
import sys
import tempfile
import unittest
import types
from unittest import mock

import control_acceptance as fixture


class ControlAcceptanceTests(unittest.TestCase):
    def test_private_device_nodes_stay_under_the_mounted_fixture_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(fixture.os, "mknod") as mknod, \
                    mock.patch.object(fixture.Path, "chmod") as chmod:
                fixture.create_device_nodes(root)
            expected = [("null", 1, 3, 0o666), ("zero", 1, 5, 0o666),
                        ("random", 1, 8, 0o666), ("urandom", 1, 9, 0o666),
                        ("net/tun", 10, 200, 0o600)]
            self.assertEqual(mknod.call_args_list, [
                mock.call(root / name, stat.S_IFCHR | mode, os.makedev(major, minor))
                for name, major, minor, mode in expected])
            self.assertEqual(chmod.call_args_list, [mock.call(mode) for *_, mode in expected])
            self.assertTrue((root / "net").is_dir())

    def test_existing_device_parent_is_preserved_instead_of_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "net").symlink_to("invented-foreign-location")
            with mock.patch.object(fixture.os, "mknod") as mknod:
                with self.assertRaises(FileExistsError):
                    fixture.create_device_nodes(root)
            mknod.assert_not_called()
            self.assertEqual(os.readlink(root / "net"), "invented-foreign-location")

    def test_resolver_fixture_bounds_questions_and_returns_only_local_nxdomain(self):
        response = fixture.dns_response(fixture.QUERY)
        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(response[2:12], b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00")
        self.assertEqual(response[12:], fixture.QUERY[12:])
        for sample in (b"", b"x" * 513, fixture.QUERY[:-1],
                       fixture.QUERY[:2] + b"\x81" + fixture.QUERY[3:],
                       fixture.QUERY[:12] + b"\xc0\x0c\x00\x01\x00\x01"):
            self.assertIsNone(fixture.dns_response(sample))

    def test_real_private_resolver_serves_udp_tcp_and_joins_its_thread(self):
        with fixture.Resolver(port=0) as resolver:
            fixture.resolver_health(resolver.port)
        self.assertFalse(resolver.thread.is_alive())
        self.assertEqual(resolver.failures, [])

    def test_artifacts_never_follow_a_preexisting_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "foreign").write_text("invented foreign data")
            (path / "probe.log").symlink_to(path / "foreign")
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError):
                    with fixture.artifact(fd, "probe.log"):
                        self.fail("existing artifact must not be opened")
            finally:
                os.close(fd)
            self.assertEqual((path / "foreign").read_text(), "invented foreign data")

    def test_failed_cleanup_diagnostics_preserve_the_initial_probe_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            probe = path / "probe"
            probe.write_text("synthetic artifact")
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            def run(args, **_kwargs):
                if args[0] == "git":
                    return types.SimpleNamespace(stdout="sample-revision\n")
                raise ValueError("synthetic primary failure")
            try:
                with mock.patch.object(fixture, "snapshot", side_effect=[{}, OSError("synthetic cleanup failure")]), \
                        mock.patch.object(fixture, "command", side_effect=run):
                    with self.assertRaises(RuntimeError) as failure:
                        fixture.run_outer(types.SimpleNamespace(probe=probe), fd)
                self.assertIsInstance(failure.exception.__cause__, ValueError)
            finally:
                os.close(fd)
            result = json.loads((path / "result.json").read_text())
            self.assertEqual(result["primary_error"], "ValueError")
            self.assertEqual(result["cleanup_error"], "OSError")
            self.assertFalse(result["host_state_preserved"])

    def test_private_bus_policy_allows_actual_method_replies(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as log:
            path = Path(directory)
            bus_path = path / "bus"
            config = path / "bus.conf"
            config.write_text(fixture.BUS_CONFIG.replace("/run/dbus/system_bus_socket", str(bus_path)))
            bus = subprocess.Popen([fixture.tool("dbus-daemon"), "--nofork", "--nopidfile",
                                    f"--config-file={config}"], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 3
                while not bus_path.exists():
                    self.assertIsNone(bus.poll(), "private fixture bus exited before readiness")
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                result = fixture.bus_health(f"unix:path={bus_path}")
                self.assertIn(b"org.freedesktop.DBus", result.stdout)
            finally:
                if bus.poll() is None:
                    bus.terminate()
                try:
                    status = bus.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    bus.kill()
                    status = bus.wait(timeout=2)
                self.assertIn(status, (0, -signal.SIGTERM))

    def test_namespace_guard_rejects_an_ordinary_descriptor_before_mutation(self):
        with tempfile.TemporaryFile() as file:
            with self.assertRaisesRegex(RuntimeError, "namespace descriptors"):
                fixture.require_private_namespace("mnt", file.fileno())

    def test_namespace_guard_rejects_the_actual_parent_namespace(self):
        with open("/proc/thread-self/ns/mnt", "rb") as file:
            with self.assertRaisesRegex(RuntimeError, "distinct mount"):
                fixture.require_private_namespace("mnt", file.fileno())

    def test_timeout_kills_and_reaps_the_owned_process(self):
        with tempfile.TemporaryFile() as log:
            result = fixture.supervise([sys.executable, "-c", "import time; time.sleep(60)"], log, timeout=0.05)
        self.assertEqual(result, {"code": -signal.SIGKILL, "timed_out": True})

    def test_child_failure_is_not_reported_as_success_or_timeout(self):
        with tempfile.TemporaryFile() as log:
            result = fixture.supervise([sys.executable, "-c", "raise SystemExit(7)"], log, timeout=2)
        self.assertEqual(result, {"code": 7, "timed_out": False})

    def test_unprivileged_invocation_rejects_before_creating_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            with mock.patch.object(os, "geteuid", return_value=1000), \
                    mock.patch.object(sys, "argv", ["control_acceptance.py", "--probe", "unused", "--evidence", str(evidence)]), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as failure:
                    fixture.main()
            self.assertEqual(failure.exception.code, 2)
            self.assertFalse(evidence.exists())

    def test_writable_tool_is_not_executed_as_root(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tool"
            path.write_text("fixture")
            path.chmod(0o777)
            with mock.patch.object(fixture.shutil, "which", return_value=str(path)):
                with self.assertRaisesRegex(RuntimeError, "not protected"):
                    fixture.tool("fixture")


class PrivilegedWorkflowPolicyTests(unittest.TestCase):
    def test_only_an_owner_dispatch_in_this_repository_can_enable_the_root_job(self):
        import re
        workflow = (Path(__file__).parent.parent / ".github/workflows/ci.yml").read_text()
        job = workflow.split("  privileged-control:\n", 1)[1]
        folded = re.search(r"    if: >-\n((?:      [^\n]+\n)+)", job)
        self.assertIsNotNone(folded)
        expression = " ".join(line.strip() for line in folded[1].splitlines())
        predicates = []
        for predicate in expression.split("&&"):
            parsed = re.fullmatch(r"\s*([\w.]+)\s*==\s*('[^']*'|[\w.]+)\s*", predicate)
            self.assertIsNotNone(parsed, "root policy admits only explicit equality conjunctions")
            predicates.append(parsed.groups())

        def permits(event="workflow_dispatch", actor="skunkie", repository="skunkie/warper", rust="true"):
            values = {"needs.stage.outputs.rust": rust, "github.event_name": event,
                      "github.repository": repository, "github.actor": actor,
                      "github.repository_owner": "skunkie"}
            return all(values[left] == (right[1:-1] if right.startswith("'") else values[right])
                       for left, right in predicates)

        self.assertTrue(permits())
        for event in ("pull_request", "push", "workflow_run", "workflow_call"):
            self.assertFalse(permits(event=event), event)
        self.assertFalse(permits(actor="fixture-contributor"))
        self.assertFalse(permits(repository="fixture-fork/warper"))
        self.assertFalse(permits(rust="false"))


if __name__ == "__main__":
    unittest.main()
