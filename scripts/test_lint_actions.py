# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

from lint_actions import LayoutError, escape_property, lint, to_workflow

SCRIPT = Path(__file__).with_name("lint_actions.py")

COMPOSITE = textwrap.dedent(
    """\
    # SPDX header comment
    name: Sample action
    description: Synthetic composite action.
    inputs:
      target:
        description: Target name.
        required: true
    outputs:
      result:
        value: ${{ steps.build.outputs.result }}
    runs:
      using: composite
      steps:
        - id: build
          shell: bash
          env:
            TARGET: ${{ inputs.target }}
          run: |
            echo "Building $TARGET"
    """
)


def find_actionlint() -> str | None:
    """Return the actionlint to test with; ACTIONLINT makes it mandatory."""
    return os.environ.get("ACTIONLINT") or shutil.which("actionlint")


class RewriteTests(unittest.TestCase):
    def test_composite_action_becomes_workflow_with_inputs_and_steps(self):
        workflow = to_workflow(COMPOSITE, Path("action.yml"))
        self.assertIsNotNone(workflow)
        self.assertEqual(
            workflow.text,
            textwrap.dedent(
                """\
                name: Sample action
                on:
                  workflow_dispatch:
                    inputs:
                      target:
                        description: Target name.
                        required: true
                jobs:
                  composite:
                    runs-on: ubuntu-latest
                    steps:
                      - id: build
                        shell: bash
                        env:
                          TARGET: ${{ inputs.target }}
                        run: |
                          echo "Building $TARGET"
                """
            ),
        )

    def test_workflow_positions_map_to_action_lines_and_columns(self):
        workflow = to_workflow(COMPOSITE, Path("action.yml"))
        lines = workflow.text.splitlines()
        target = next(index for index, line in enumerate(lines) if "TARGET:" in line) + 1
        # The expression starts after the two spaces the rewrite adds to steps.
        column = lines[target - 1].index("${{") + 1
        self.assertEqual(workflow.locate(target, column), (17, column - 2))
        description = lines.index("        description: Target name.") + 1
        self.assertEqual(workflow.locate(description, 9), (6, 5))

    def test_added_lines_map_to_preceding_action_line(self):
        workflow = to_workflow(COMPOSITE, Path("action.yml"))
        jobs = workflow.text.splitlines().index("jobs:") + 1
        self.assertEqual(workflow.locate(jobs, 1), (7, 1), "jobs: follows the last input line")
        self.assertEqual(workflow.locate(2, 1), (2, 1), "on: follows the name line")

    def test_comments_between_steps_keep_later_steps(self):
        action = COMPOSITE.replace("    - id: build\n", "  # Shallow comment between steps.\n    - id: build\n")
        workflow = to_workflow(action, Path("action.yml"))
        self.assertIn('echo "Building $TARGET"', workflow.text, "steps after a shallow comment are linted")

    def test_script_comments_are_kept(self):
        directive = "      # shellcheck disable=SC2086"
        action = COMPOSITE.replace('      echo "Building $TARGET"', f"{directive}\n      echo $TARGET")
        workflow = to_workflow(action, Path("action.yml"))
        self.assertIn(f"  {directive}\n", workflow.text, "shellcheck directives in run scripts still apply")

    def test_action_without_inputs_uses_bare_workflow_dispatch(self):
        action = "name: No inputs\nruns:\n  using: composite\n  steps:\n    - run: true\n      shell: bash\n"
        workflow = to_workflow(action, Path("action.yml"))
        self.assertIn("on:\n  workflow_dispatch:\njobs:\n", workflow.text)

    def test_non_composite_action_is_skipped(self):
        for using in ("node20", "docker", "'node24'"):
            with self.subTest(using=using):
                action = f"name: Other\nruns:\n  using: {using}\n  main: index.js\n"
                self.assertIsNone(to_workflow(action, Path("action.yml")))

    def test_unsupported_layout_is_rejected(self):
        for case, action in (
            ("missing runs", "name: Missing runs\n"),
            ("flow runs", "name: Flow\nruns: {using: composite, steps: []}\n"),
            ("flow inputs", "inputs: {}\nruns:\n  using: composite\n  steps:\n    - run: true\n"),
            ("flow steps", "runs:\n  using: composite\n  steps: []\n"),
        ):
            with self.subTest(case=case):
                with self.assertRaises(LayoutError, msg=case):
                    to_workflow(action, Path("action.yml"))

    def test_annotation_properties_escape_separators(self):
        self.assertEqual(escape_property("a,b:c%d\ne"), "a%2Cb%3Ac%25d%0Ae")


@unittest.skipUnless(find_actionlint(), "actionlint is not installed; set ACTIONLINT to require it")
class ActionlintTests(unittest.TestCase):
    def setUp(self):
        self.actionlint = find_actionlint()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def write_action(self, text: str) -> Path:
        path = self.directory / "sample" / "action.yml"
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_clean_composite_action_has_no_findings(self):
        self.assertEqual(lint([self.write_action(COMPOSITE)], self.actionlint, None), [])

    def test_findings_are_reported_at_action_positions(self):
        if not shutil.which("shellcheck"):
            if os.environ.get("ACTIONLINT"):
                self.fail("ACTIONLINT requires shellcheck on PATH for script checks")
            self.skipTest("shellcheck is not installed")
        action = COMPOSITE.replace("inputs.target", "inputs.targets").replace(
            'echo "Building $TARGET"', "echo $TARGET"
        )
        path = self.write_action(action)
        findings = lint([path], self.actionlint, None)
        positions = {(finding.kind, finding.line, finding.column) for finding in findings}
        self.assertEqual(
            positions,
            {("expression", 17, 21), ("shellcheck", 18, 7)},
            "the unquoted variable and the undefined input are both located in action.yml",
        )
        self.assertTrue(all(finding.path == str(path) for finding in findings))

    def test_cli_lints_default_action_yml_and_action_yaml_files(self):
        actions = self.directory / ".github" / "actions"
        broken = COMPOSITE.replace("inputs.target", "inputs.missing")
        for relative, text in (("good/action.yml", COMPOSITE), ("bad/action.yaml", broken)):
            path = actions / relative
            path.parent.mkdir(parents=True)
            path.write_text(text, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--actionlint", self.actionlint],
            capture_output=True,
            cwd=self.directory,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(".github/actions/bad/action.yaml:17:", result.stdout, "action.yaml files are linted too")

    def test_cli_exit_status_reflects_findings_and_failures(self):
        clean = self.write_action(COMPOSITE)
        command = [sys.executable, "-B", str(SCRIPT), "--actionlint", self.actionlint]
        result = subprocess.run([*command, str(clean)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

        broken = self.write_action(COMPOSITE.replace("inputs.target", "inputs.missing"))
        env = {**os.environ, "GITHUB_ACTIONS": "true"}
        result = subprocess.run([*command, str(broken)], capture_output=True, env=env, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, "findings fail the check")
        self.assertIn(f"{broken}:17:", result.stdout)
        self.assertIn("::error file=", result.stdout, "GitHub Actions runs get annotations")

        missing = self.directory / "missing-actionlint"
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--actionlint", str(missing), str(clean)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 2, "a missing actionlint is an error, not a pass")


if __name__ == "__main__":
    unittest.main()
