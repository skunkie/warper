# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Verify the destructive VM fixture cannot select ordinary developer hosts."""

import unittest
from unittest.mock import patch

import systemd_acceptance as fixture


class DisposableVmTests(unittest.TestCase):
    def test_refuses_missing_consent_nonroot_and_nonhosted_environments(self):
        hosted = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}
        for environment, uid, acknowledged in (
                ({}, 0, True), (hosted, 1000, True), (hosted, 0, False),
                ({**hosted, 'RUNNER_ENVIRONMENT': 'self-hosted'}, 0, True)):
            with self.assertRaises(ValueError):
                fixture.require_disposable(environment, uid, acknowledged)

    def test_developer_invocation_refuses_before_filesystem_or_process_operations(self):
        with patch.object(fixture.subprocess, 'run') as processes, \
                patch.object(fixture.Path, 'exists') as paths:
            with self.assertRaises(ValueError):
                fixture.exercise(type('Arguments', (), {'disposable_github_vm': True})(), {})
            processes.assert_not_called()
            paths.assert_not_called()


if __name__ == '__main__':
    unittest.main()
