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
    def run_harness(self, *, probe="wireguard-stack", probe_exit=0, scope="--packet-only", build_exit=0, rekey=False, mapping="0 1000 1", cleanup_exit=0, peer_exit=0, probe_killed=False, tc_exit=0, interrupt_exit=0, route_exit=0, rule_exit=0, address_exit=0, route_mismatch=False, mismatch_after=0):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "scripts").mkdir()
        harness = root / "scripts/verify-feasibility.sh"
        shutil.copyfile(Path(__file__).with_name("verify-feasibility.sh"), harness)
        shutil.copyfile(Path(__file__).with_name("run-feasibility-isolated.sh"), root / "scripts/run-feasibility-isolated.sh")
        shutil.copyfile(Path(__file__).with_name("run-router-mtu-isolated.sh"), root / "scripts/run-router-mtu-isolated.sh")
        shutil.copyfile(Path(__file__).with_name("verify_router_paths.py"), root / "scripts/verify_router_paths.py")
        (root / "scripts/tun_feasibility.py").write_text(
            f'import sys\nprint("fixture-tun", *sys.argv[1:])\nsys.exit({probe_exit})\n'
        )
        (root / "Cargo.lock").write_text("# synthetic lockfile\n")
        tools = root / "tools"
        tools.mkdir()
        commands = {
            "cargo": f'if [[ "$1" == build ]]; then exit {build_exit}; fi\necho fixture-cargo\n',
            "rustc": "echo fixture-rustc\n",
            "git": 'if [[ "$1" == rev-parse ]]; then echo fixture-revision; fi\n',
            # Network operations are replaced. Real timeout/child processes
            # exercise supervision; these tests do not claim network isolation.
            "unshare": 'if [[ "$1" == --net ]]; then shift; exec "$@"; fi\nwhile [[ "$1" != bash ]]; do shift; done\nexec "$@"\n',
            "readlink": 'echo "$1"\n',
            "sysctl": f'echo "$*" >> "{root}/sysctl-commands.log"\n',
            "tc": f'echo "$*" >> "{root}/tc-commands.log"\nexit {tc_exit}\n',
            "mount": f'echo "$*" >> "{root}/mount-commands.log"\n',
            "umount": f'echo "$*" >> "{root}/umount-commands.log"\n',
            "nsenter": f'echo "$*" >> "{root}/nsenter-commands.log"\nshift\nif [[ "$1" == bash && "$2" == -eu ]]; then exit 0; fi\nexec "$@"\n',
            "ip": f'echo "$*" >> "{root}/ip-commands.log"\nif [[ "$1 $2 $3" == "-j route get" ]]; then\ncase "$6" in\n198.18.0.2) gateway=198.18.0.1; dev=client0;;\n198.20.0.2) gateway=198.20.0.1; dev=client1;;\nfd77:1::2) gateway=fd77:1::1; dev=client0;;\nfd77:3::2) gateway=fd77:3::1; dev=client1;;\nesac\ncount=$(grep -c -- "-j route get" "{root}/ip-commands.log" || :)\nif [[ "{route_mismatch}" == True || ( {mismatch_after} -gt 0 && "$count" -gt {mismatch_after} ) ]]; then dev=wrong; fi\nprintf \'[{{"dst":"%s","from":"%s","gateway":"%s","dev":"%s"}}]\\n\' "$4" "$6" "$gateway" "$dev"\nexit 0\nfi\nif [[ "$1" == -j ]]; then echo "[]"; fi\nif [[ "$1 $2" == "link del" ]]; then exit {cleanup_exit}; fi\nif [[ "$*" == "link set dev routerc1 down" ]]; then exit {interrupt_exit}; fi\nif [[ "$*" == "route del default via 198.20.0.1 dev client1 table 100" ]]; then exit {route_exit}; fi\nif [[ "$*" == "rule del from 198.20.0.2/32 table 100" ]]; then exit {rule_exit}; fi\nif [[ "$*" == "addr del 198.20.0.2/24 dev client1" ]]; then exit {address_exit}; fi\n',
            "cat": f'if [[ "$1" == /proc/self/uid_map ]]; then echo "{mapping}"; else exec /bin/cat "$@"; fi\n',
        }
        for name, source in commands.items():
            path = tools / name
            path.write_text("#!/usr/bin/env bash\nset -eu\n" + source)
            path.chmod(0o700)
        executable = root / f"target/debug/{probe}"
        executable.parent.mkdir(parents=True)
        executable.write_text(f'''#!/usr/bin/env bash
set -eu
echo fixture-probe "$@"
if [[ "${{1:-}}" == --router-mtu-peer ]]; then
    touch "$2/ready"
    while [[ ! -f "$2/stop" ]]; do sleep 0.01; done
    exit {peer_exit}
fi
if [[ "{probe_killed}" == True ]]; then kill -KILL $$; fi
if [[ "${{1:-}}" == --router-mtu-check && {probe_exit} == 0 ]]; then
    for suffix in 00 01 10 11; do
        touch "$2/down.$suffix.request"
        for _ in {{1..500}}; do
            if [[ -f "$2/down.$suffix.ready" ]]; then break; fi
            sleep 0.002
        done
        [[ -f "$2/down.$suffix.ready" ]] || exit 1
        touch "$2/up.$suffix.request"
        for _ in {{1..500}}; do
            if [[ -f "$2/up.$suffix.ready" ]]; then break; fi
            sleep 0.002
        done
        [[ -f "$2/up.$suffix.ready" ]] || exit 1
        touch "$2/route.down.$suffix.request"
        for _ in {{1..500}}; do
            if [[ -f "$2/route.down.$suffix.ready" ]]; then break; fi
            sleep 0.002
        done
        [[ -f "$2/route.down.$suffix.ready" ]] || exit 1
        touch "$2/route.up.$suffix.request"
        for _ in {{1..500}}; do
            if [[ -f "$2/route.up.$suffix.ready" ]]; then break; fi
            sleep 0.002
        done
        [[ -f "$2/route.up.$suffix.ready" ]] || exit 1
        for change in rule address; do
        for direction in down up; do
            touch "$2/$change.$direction.$suffix.request"
            for _ in {{1..500}}; do
                if [[ -f "$2/$change.$direction.$suffix.ready" ]]; then break; fi
                sleep 0.002
            done
            [[ -f "$2/$change.$direction.$suffix.ready" ]] || exit 1
        done
        done
    done
fi
exit {probe_exit}
''')
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

    def test_tun_scope_records_success_and_failure_without_claiming_other_gates(self):
        for probe_exit in (0, 7):
            result, evidence = self.run_harness(probe="host-stack", scope="--tun", probe_exit=probe_exit)
            self.assertEqual(result.returncode, probe_exit, result.stderr)
            self.assertIn("fixture-tun", (evidence / "probe.log").read_text())
            outcome = (evidence / "result.txt").read_text()
            self.assertIn(f"kernel_tun_probe_exit={probe_exit}", outcome)
            self.assertIn("NOT RUN native macOS utun", outcome)
            self.assertEqual("PASS tun" in outcome, probe_exit == 0)

    def test_tun_scope_rejects_wrong_probe_and_initial_namespace(self):
        harness = str(Path(__file__).with_name("verify-feasibility.sh"))
        result = subprocess.run(["bash", harness, "wireguard-stack", "--tun"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        result, evidence = self.run_harness(probe="host-stack", scope="--tun", mapping="0 0 4294967295")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((evidence.parents[3] / "ip-commands.log").exists())

    def test_tun_crash_scope_passes_argument_and_preserves_failure(self):
        for probe_exit in (0, 7):
            result, evidence = self.run_harness(probe="host-stack", scope="--tun-crash-check", probe_exit=probe_exit)
            self.assertEqual(result.returncode, probe_exit, result.stderr)
            self.assertIn("--crash-after-udp", (evidence / "probe.log").read_text())
            outcome = (evidence / "result.txt").read_text()
            self.assertIn(f"tun_crash_probe_exit={probe_exit}", outcome)
            self.assertEqual("PASS tun-crash-check" in outcome, probe_exit == 0)

    def test_tun_crash_scope_rejects_wrong_probe_and_initial_namespace(self):
        harness = str(Path(__file__).with_name("verify-feasibility.sh"))
        result = subprocess.run(["bash", harness, "wireguard-stack", "--tun-crash-check"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        result, evidence = self.run_harness(probe="host-stack", scope="--tun-crash-check", mapping="0 0 4294967295")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((evidence.parents[3] / "ip-commands.log").exists())

    def test_tun_fragment_scope_passes_argument_and_preserves_failure(self):
        for probe_exit in (0, 7):
            result, evidence = self.run_harness(probe="host-stack", scope="--tun-fragment-check", probe_exit=probe_exit)
            self.assertEqual(result.returncode, probe_exit, result.stderr)
            self.assertIn("--fragmented-ipv4", (evidence / "probe.log").read_text())
            outcome = (evidence / "result.txt").read_text()
            self.assertIn(f"tun_fragment_probe_exit={probe_exit}", outcome)
            self.assertEqual("PASS tun-fragment-check" in outcome, probe_exit == 0)

    def test_tun_fragment_scope_rejects_wrong_probe_and_initial_namespace(self):
        harness = str(Path(__file__).with_name("verify-feasibility.sh"))
        result = subprocess.run(["bash", harness, "wireguard-stack", "--tun-fragment-check"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        result, evidence = self.run_harness(probe="host-stack", scope="--tun-fragment-check", mapping="0 0 4294967295")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((evidence.parents[3] / "ip-commands.log").exists())

    def test_mtu_scope_rejects_wireguard_before_build_or_network_setup(self):
        result = subprocess.run(["bash", str(Path(__file__).with_name("verify-feasibility.sh")), "wireguard-stack", "--mtu-check"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--mtu-check requires host-stack", result.stderr)

    def test_outer_mtu_scope_configures_only_private_loopback(self):
        result, evidence = self.run_harness(scope="--outer-mtu-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-probe --outer-mtu-check", (evidence / "probe.log").read_text())
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("link set lo mtu 1400", commands)
        self.assertNotIn("link add", commands)
        outcome = (evidence / "result.txt").read_text()
        self.assertIn("outer_local_mtu_probe_exit=0", outcome)
        self.assertIn("NOT RUN remote router MTU discovery", outcome)

    def test_outer_mtu_scope_rejects_wrong_probe_and_rekey(self):
        harness = str(Path(__file__).with_name("verify-feasibility.sh"))
        for arguments in [("host-stack", "--outer-mtu-check"), ("wireguard-stack", "--outer-mtu-check", "--rekey")]:
            result = subprocess.run(["bash", harness, *arguments], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_outer_mtu_scope_rejects_initial_namespace_before_mutation(self):
        result, evidence = self.run_harness(scope="--outer-mtu-check", mapping="0 0 4294967295")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((evidence.parents[3] / "ip-commands.log").exists())

    def test_kernel_mtu_scope_sets_private_limits_and_verifies_cleanup(self):
        result, evidence = self.run_harness(scope="--kernel-mtu-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-probe --kernel-mtu-check", (evidence / "probe.log").read_text())
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("link set lo mtu 1400", commands)
        self.assertIn("link set dev wg-feasibility mtu 1500 up", commands)
        self.assertIn("link del dev wg-feasibility", commands)
        self.assertIn("-j link show", commands)
        self.assertIn("CLEANUP independent kernel WireGuard interface removed and verified", result.stdout)
        outcome = (evidence / "result.txt").read_text()
        self.assertIn("kernel_mtu_probe_exit=0", outcome)
        self.assertIn("kernel_peer_probe_exit=0", outcome)
        self.assertNotIn("NOT RUN independent WireGuard implementation", outcome)
        self.assertIn("NOT RUN remote router MTU discovery", outcome)

    def test_kernel_mtu_probe_and_cleanup_failures_preserve_primary_exit(self):
        for probe_exit, cleanup_exit, expected in [(7, 0, 7), (0, 9, 1), (7, 9, 7)]:
            result, evidence = self.run_harness(scope="--kernel-mtu-check", probe_exit=probe_exit, cleanup_exit=cleanup_exit)
            self.assertEqual(result.returncode, expected, result.stderr)
            commands = (evidence.parents[3] / "ip-commands.log").read_text()
            self.assertIn("link del dev wg-feasibility", commands)
            self.assertIn(f"kernel_mtu_probe_exit={expected}", (evidence / "result.txt").read_text())
            self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_kernel_mtu_scope_rejects_wrong_probe_and_rekey_before_build(self):
        harness = str(Path(__file__).with_name("verify-feasibility.sh"))
        for arguments in [("host-stack", "--kernel-mtu-check"), ("wireguard-stack", "--kernel-mtu-check", "--rekey")]:
            result = subprocess.run(["bash", harness, *arguments], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_kernel_mtu_scope_rejects_initial_namespace_before_mutation(self):
        result, evidence = self.run_harness(scope="--kernel-mtu-check", mapping="0 0 4294967295")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((evidence.parents[3] / "ip-commands.log").exists())

    def test_router_scope_configures_private_forwarding_and_reaps_children(self):
        result, evidence = self.run_harness(scope="--router-mtu-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("link set routerc0 mtu 1600 up", commands)
        self.assertIn("link set routerc1 mtu 1600 up", commands)
        self.assertEqual(commands.count("-j route get"), 68)
        self.assertEqual(commands.count("link set dev routerc1 down"), 4)
        self.assertEqual(commands.count("link set dev routerc1 up"), 4)
        self.assertEqual(commands.count("route del default via 198.20.0.1 dev client1 table 100"), 2)
        self.assertEqual(commands.count("-6 route del default via fd77:3::1 dev client1 table 100"), 2)
        self.assertEqual(commands.count("rule del from 198.20.0.2/32 table 100"), 2)
        self.assertEqual(commands.count("-6 rule del from fd77:3::2/128 table 100"), 2)
        self.assertEqual(commands.count("addr del 198.20.0.2/24 dev client1"), 2)
        self.assertEqual(commands.count("-6 addr del fd77:3::2/64 dev client1"), 2)
        self.assertIn("link set routers0 mtu 1400 up", commands)
        traffic_control = (evidence.parents[3] / "tc-commands.log").read_text()
        self.assertIn("netem delay 100ms", traffic_control)
        self.assertIn("match ip protocol 1 0xff", traffic_control)
        self.assertIn("match ip6 protocol 58 0xff", traffic_control)
        self.assertIn("link set dev wg-feasibility mtu 1500 up", commands)
        self.assertIn("link del dev routerc0", commands)
        self.assertIn("link del dev routerc1", commands)
        self.assertIn("link del dev routers0", commands)
        forwarding = (evidence.parents[3] / "sysctl-commands.log").read_text()
        self.assertIn("net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1", forwarding)
        log = (evidence / "probe.log").read_text()
        self.assertIn("--router-mtu-check", log)
        self.assertIn("--router-mtu-peer", log)
        self.assertIn("CLEANUP independent kernel WireGuard interface removed and verified", log)
        self.assertIn("namespace processes reaped", log)
        self.assertTrue((evidence.parents[3] / "umount-commands.log").exists())
        outcome = (evidence / "result.txt").read_text()
        self.assertIn("router_mtu_probe_exit=0", outcome)
        self.assertIn("NOT RUN short-quote support", outcome)

    def test_router_failures_preserve_primary_exit_and_still_retire_links(self):
        for probe_exit, peer_exit, cleanup_exit, expected in [(7, 0, 0, 7), (0, 9, 0, 9), (7, 9, 0, 7), (0, 0, 9, 1)]:
            result, evidence = self.run_harness(scope="--router-mtu-check", probe_exit=probe_exit, peer_exit=peer_exit, cleanup_exit=cleanup_exit)
            self.assertEqual(result.returncode, expected, result.stderr)
            commands = (evidence.parents[3] / "ip-commands.log").read_text()
            self.assertIn("link del dev routerc0", commands)
            self.assertIn("link del dev routerc1", commands)
            self.assertIn("link del dev routers0", commands)
            self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_router_traffic_control_failure_retires_links(self):
        result, evidence = self.run_harness(scope="--router-mtu-check", tc_exit=7)
        self.assertEqual(result.returncode, 7, result.stderr)
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("link del dev routerc0", commands)
        self.assertIn("link del dev routerc1", commands)
        self.assertIn("link del dev routers0", commands)
        self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_router_interruption_failure_retires_links_and_control_mount(self):
        result, evidence = self.run_harness(scope="--router-mtu-check", interrupt_exit=7)
        self.assertEqual(result.returncode, 1, result.stderr)
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("link set dev routerc1 down", commands)
        self.assertIn("link del dev routerc1", commands)
        self.assertTrue((evidence.parents[3] / "umount-commands.log").exists())
        self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_router_lookup_mismatch_retires_links_and_control_mount(self):
        result, evidence = self.run_harness(scope="--router-mtu-check", route_mismatch=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("link del dev routerc1", commands)
        self.assertTrue((evidence.parents[3] / "umount-commands.log").exists())
        self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_router_restoration_lookup_mismatch_does_not_acknowledge_recovery(self):
        for completed in (4, 8, 12, 16):
            with self.subTest(completed=completed):
                result, evidence = self.run_harness(scope="--router-mtu-check", mismatch_after=completed)
                self.assertEqual(result.returncode, 1, result.stderr)
                commands = (evidence.parents[3] / "ip-commands.log").read_text()
                self.assertEqual(commands.count("-j route get"), completed + 1)
                self.assertIn("link del dev routerc1", commands)
                self.assertTrue((evidence.parents[3] / "umount-commands.log").exists())
                self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_router_address_change_failure_retires_links_and_control_mount(self):
        result, evidence = self.run_harness(scope="--router-mtu-check", address_exit=7)
        self.assertEqual(result.returncode, 1, result.stderr)
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("addr del 198.20.0.2/24 dev client1", commands)
        self.assertIn("link del dev routerc1", commands)
        self.assertTrue((evidence.parents[3] / "umount-commands.log").exists())
        self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_router_rule_change_failure_retires_links_and_control_mount(self):
        result, evidence = self.run_harness(scope="--router-mtu-check", rule_exit=7)
        self.assertEqual(result.returncode, 1, result.stderr)
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("rule del from 198.20.0.2/32 table 100", commands)
        self.assertIn("link del dev routerc1", commands)
        self.assertTrue((evidence.parents[3] / "umount-commands.log").exists())
        self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_router_route_change_failure_retires_links_and_control_mount(self):
        result, evidence = self.run_harness(scope="--router-mtu-check", route_exit=7)
        self.assertEqual(result.returncode, 1, result.stderr)
        commands = (evidence.parents[3] / "ip-commands.log").read_text()
        self.assertIn("route del default via 198.20.0.1 dev client1 table 100", commands)
        self.assertIn("link del dev routerc1", commands)
        self.assertTrue((evidence.parents[3] / "umount-commands.log").exists())
        self.assertNotIn("PASS", (evidence / "result.txt").read_text())

    def test_killed_router_client_still_stops_peer_and_reaps_namespaces(self):
        result, evidence = self.run_harness(scope="--router-mtu-check", probe_killed=True)
        self.assertEqual(result.returncode,137,result.stderr)
        log=(evidence / "probe.log").read_text()
        self.assertIn("CLEANUP independent kernel WireGuard interface removed and verified",log)
        self.assertIn("namespace processes reaped",log)
        self.assertNotIn("PASS",(evidence / "result.txt").read_text())

    def test_router_scope_rejects_invalid_scope_and_initial_namespace(self):
        harness = str(Path(__file__).with_name("verify-feasibility.sh"))
        for arguments in [("host-stack", "--router-mtu-check"), ("wireguard-stack", "--router-mtu-check", "--rekey")]:
            result = subprocess.run(["bash", harness, *arguments], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
        result, evidence = self.run_harness(scope="--router-mtu-check", mapping="0 0 4294967295")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((evidence.parents[3] / "ip-commands.log").exists())
        self.assertFalse((evidence.parents[3] / "sysctl-commands.log").exists())

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
