# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Exercise physical-path coordination and cleanup with synthetic commands."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class PhysicalPathHarnessTests(unittest.TestCase):
    def run_harness(
        self, *, mapping="0 1000 1", client_exit=0, peer_exit=0,
        fail_down=False, fail_cleanup=False, early_client=False, early_peer=False,
        kill_client=False, fail_group_signal=False, track_peer_shutdown=False,
        signal_timeout_124=False, signal_peer_timeout_124=False, stuck_peer=False,
        peer_timeout_after_ready=False, delay_early_client=False, families=("4",),
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        scripts = root / "scripts"
        scripts.mkdir()
        for name in ("run-physical-path-isolated.sh", "run-feasibility-isolated.sh"):
            shutil.copyfile(Path(__file__).with_name(name), scripts / name)
        tools = root / "tools"
        tools.mkdir()
        ip_log = root / "ip.log"
        state = root / "link-state"
        commands = {
            "unshare": 'if [[ "$1" == --net ]]; then shift; fi\nexec "$@"\n',
            "nsenter": 'shift\nif [[ "${1:-}" == bash && "${2:-}" == -eu ]]; then exit 0; fi\nexec "$@"\n',
            "readlink": 'echo "$1"\n',
            "sysctl": 'exit 0\n',
            "mount": f'echo mounted > "{root}/mount.log"\n',
            "umount": 'rm -f -- "$1"/*\n',
            "cat": f'if [[ "$1" == /proc/self/uid_map ]]; then echo "{mapping}"; else exec /bin/cat "$@"; fi\n',
            "ip": f'''echo "$*" >> "{ip_log}"
if [[ "$*" == "link set dev routers0 down" ]]; then
    if [[ "{fail_down}" == True ]]; then exit 9; fi
    echo down > "{state}"
fi
if [[ "$*" == "link set dev routers0 up" ]]; then echo up > "{state}"; fi
if [[ "$*" == "link del dev routers0" && "{fail_cleanup}" == True ]]; then exit 9; fi
if [[ "$*" == "-j link show dev routers0" ]]; then
    if [[ -f "{state}" && $(cat "{state}") == down ]]; then echo '[{{"flags":[]}}]'; else echo '[{{"flags":["UP"]}}]'; fi
elif [[ "$*" == "-j -6 addr show dev routers0" ]]; then
    echo '[{{"addr_info":[{{"local":"fd77:2::1"}}]}}]'
elif [[ "$1" == -j ]]; then echo '[]'; fi
''',
        }
        if signal_timeout_124 or signal_peer_timeout_124:
            timeout_command = shutil.which("timeout")
            if timeout_command is None:
                self.fail("timeout is required for the synthetic supervisor")
            commands["timeout"] = f'''role=
if [[ "$*" == *--physical-path-client* && "{signal_timeout_124}" == True ]]; then role=client; fi
if [[ "$*" == *--physical-path-peer* && "{signal_peer_timeout_124}" == True ]]; then role=peer; fi
if [[ -z "$role" ]]; then exec "{timeout_command}" "$@"; fi
"{timeout_command}" "$@" &
child=$!
trap 'kill "$child" 2>/dev/null || :; wait "$child" || :; touch "{root}/timeout-$role-signalled"; exit 124' TERM
wait "$child"
'''
        for name, source in commands.items():
            path = tools / name
            path.write_text("#!/usr/bin/env bash\nset -eu\n" + source)
            path.chmod(0o700)
        probe = root / "probe"
        probe.write_text(f'''#!/usr/bin/env bash
set -eu
if [[ "$1" == --physical-path-peer ]]; then
    echo "$3 $4" > "{root}/peer-families"
    if [[ "{early_peer}" == True ]]; then exit {peer_exit}; fi
    touch "$2/peer.ready"
    if [[ "{peer_timeout_after_ready}" == True ]]; then exit 124; fi
    if [[ "{stuck_peer}" == True ]]; then while true; do sleep 0.01; done; fi
    while [[ ! -f "$2/peer.stop" ]]; do sleep 0.01; done
    if [[ "{track_peer_shutdown}" == True ]]; then
        sleep 0.1
        touch "{root}/peer-finished"
    fi
    exit {peer_exit}
fi
if [[ "$1" == --physical-path-client ]]; then
    echo "$3 $4" > "{root}/client-families"
    if [[ "{early_client}" == True ]]; then
        if [[ "{delay_early_client}" == True ]]; then sleep 0.2; fi
        exit {client_exit}
    fi
    if [[ "{kill_client}" == True ]]; then kill -KILL $$; fi
    touch "$2/down.request"
    while [[ ! -f "$2/down.ready" ]]; do sleep 0.01; done
    touch "$2/up.request"
    while [[ ! -f "$2/up.ready" ]]; do sleep 0.01; done
    exit {client_exit}
fi
exit 2
''')
        probe.chmod(0o700)
        environment = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}")
        if fail_group_signal:
            environment["BASH_FUNC_kill%%"] = '() { if [[ "$1" == -- && "$2" == -* ]]; then return 1; fi; builtin kill "$@"; }'
        result = subprocess.run(
            ["bash", str(scripts / "run-physical-path-isolated.sh"), str(probe), *families],
            env=environment, capture_output=True, text=True, timeout=12,
        )
        return result, root

    def test_success_changes_owned_link_and_verifies_cleanup(self):
        result, root = self.run_harness()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = (root / "ip.log").read_text()
        self.assertIn("link set dev routers0 down", commands)
        self.assertIn("link set dev routers0 up", commands)
        self.assertIn("link del dev routers0", commands)
        self.assertIn("CLEANUP physical-path links removed and verified", result.stdout)
        self.assertEqual((root / "client-families").read_text().strip(), "4 4")

    def test_cross_family_arguments_reach_both_peers(self):
        for families in [("4", "6"), ("6", "4")]:
            result, root = self.run_harness(families=families)
            self.assertEqual(result.returncode, 0, result.stderr)
            for role in ("client", "peer"):
                self.assertEqual((root / f"{role}-families").read_text().strip(), " ".join(families))

    def test_invalid_family_is_rejected_before_mutation(self):
        for families in [("5",), ("4", "5")]:
            result, root = self.run_harness(families=families)
            self.assertEqual(result.returncode, 2)
            self.assertFalse((root / "ip.log").exists())
            self.assertFalse((root / "mount.log").exists())

    def test_child_failures_preserve_status_and_cleanup(self):
        for client_exit, peer_exit, expected in [(7, 0, 7), (0, 8, 8)]:
            result, root = self.run_harness(client_exit=client_exit, peer_exit=peer_exit)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertIn("link del dev routers0", (root / "ip.log").read_text())
            self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)

    def test_early_child_failures_preserve_status_and_cleanup(self):
        for arguments, expected in [
            ({"early_client": True, "client_exit": 7}, 7),
            ({"early_peer": True, "peer_exit": 8}, 8),
        ]:
            result, root = self.run_harness(**arguments)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertIn("link del dev routers0", (root / "ip.log").read_text())
            self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)

    def test_abrupt_client_termination_cleans_up(self):
        result, root = self.run_harness(kill_client=True)
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertIn("link del dev routers0", (root / "ip.log").read_text())
        self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)

    def test_link_and_cleanup_failures_are_reported(self):
        result, root = self.run_harness(fail_down=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("link del dev routers0", (root / "ip.log").read_text())
        result, _ = self.run_harness(fail_cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL independent physical-path cleanup", result.stderr)
        result, _ = self.run_harness(fail_down=True, fail_cleanup=True)
        self.assertEqual(result.returncode, 9)
        self.assertIn("FAIL independent physical-path cleanup", result.stderr)

    def test_group_signal_failure_still_reaps_children_and_preserves_primary_error(self):
        result, root = self.run_harness(fail_down=True, fail_group_signal=True)
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertIn("link del dev routers0", (root / "ip.log").read_text())
        self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)
        self.assertNotIn("FAIL independent physical-path cleanup", result.stderr)

    def test_peer_has_time_to_finish_before_forced_termination(self):
        result, root = self.run_harness(fail_down=True, track_peer_shutdown=True)
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertTrue((root / "peer-finished").exists(), result.stderr)
        self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)

    def test_signalled_timeout_status_124_is_accepted_after_reaping(self):
        result, root = self.run_harness(
            fail_down=True, fail_group_signal=True, signal_timeout_124=True,
        )
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertTrue((root / "timeout-client-signalled").exists(), result.stderr)
        self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)
        self.assertNotIn("FAIL independent physical-path cleanup", result.stderr)

    def test_signalled_peer_timeout_status_124_is_accepted_after_reaping(self):
        result, root = self.run_harness(
            fail_down=True, fail_group_signal=True,
            signal_peer_timeout_124=True, stuck_peer=True,
        )
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertTrue((root / "timeout-peer-signalled").exists(), result.stderr)
        self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)
        self.assertNotIn("FAIL independent physical-path cleanup", result.stderr)

    def test_unexpected_timeout_remains_a_failure(self):
        result, root = self.run_harness(early_client=True, client_exit=124)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("FAIL physical-path coordination", result.stderr)
        self.assertIn("link del dev routers0", (root / "ip.log").read_text())
        self.assertIn("CLEANUP physical-path links removed and verified", result.stdout, result.stderr)

    def test_unsignalled_peer_timeout_is_reported_during_cleanup(self):
        result, _ = self.run_harness(
            early_client=True, client_exit=7, delay_early_client=True,
            peer_timeout_after_ready=True,
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("FAIL physical-path cleanup: peer exited 124", result.stderr)
        self.assertIn("FAIL independent physical-path cleanup", result.stderr)

    def test_broad_namespace_is_rejected_before_mutation(self):
        result, root = self.run_harness(mapping="0 0 4294967295")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "ip.log").exists())
        self.assertFalse((root / "mount.log").exists())


if __name__ == "__main__":
    unittest.main()
