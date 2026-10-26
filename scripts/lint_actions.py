#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Lint the steps of local composite actions with actionlint.

actionlint checks workflow steps but not the steps inside composite actions.
This script rewrites each composite action as a temporary workflow: action
inputs become workflow_dispatch inputs and the action steps become the steps
of one job. actionlint then checks run: scripts with shellcheck and checks
expressions such as ${{ inputs.name }}, and each finding is reported at its
line and column in the original action file.

Because the steps run in a workflow context, actionlint does not flag
contexts that composite actions cannot use, such as secrets. The action's
outputs: block is not checked.

The rewrite is line-based and expects the block layout used in this
repository: top-level keys at column 0, `inputs:` as a block mapping, and
`steps:` as a block sequence indented under `  steps:`. Other layouts are
rejected rather than skipped.

The script exits with status 1 when actionlint reports findings and 2 when
it cannot lint.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATTERNS = (".github/actions/*/action.yml", ".github/actions/*/action.yaml")

TOP_LEVEL_KEY = re.compile(r"^([A-Za-z][\w-]*):(.*)$")
RUNS_USING = re.compile(r"^  using:\s*[\"']?([\w-]+)[\"']?\s*(#.*)?$")
RUNS_STEPS = re.compile(r"^  steps:\s*(#.*)?$")
BLANK_OR_COMMENT = re.compile(r"^\s*(#.*)?$")


class LayoutError(ValueError):
    """The action does not use the layout this script can rewrite."""


@dataclass(frozen=True)
class Origin:
    """Where a generated workflow line came from in the action file."""

    line: int
    indent: int


@dataclass(frozen=True)
class Workflow:
    text: str
    # Origin of each generated line; None for lines the rewrite adds.
    origins: list[Origin | None]

    def locate(self, line: int, column: int) -> tuple[int, int]:
        """Map a 1-based workflow position back to the action file."""
        for index in range(min(line, len(self.origins)) - 1, -1, -1):
            origin = self.origins[index]
            if origin is None:
                continue
            if index == line - 1:
                return origin.line, max(column - origin.indent, 1)
            return origin.line, 1
        return 1, 1


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    kind: str
    message: str


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "actions",
        nargs="*",
        type=Path,
        help=f"action files to lint (default: {' and '.join(DEFAULT_PATTERNS)})",
    )
    parser.add_argument(
        "--actionlint",
        default="actionlint",
        help="actionlint executable (default: actionlint on PATH)",
    )
    parser.add_argument(
        "--shellcheck",
        help="shellcheck executable passed to actionlint (default: its own lookup)",
    )
    args = parser.parse_args()

    actions = args.actions or sorted(
        path for pattern in DEFAULT_PATTERNS for path in Path().glob(pattern)
    )
    if not actions:
        print(f"No actions match {' or '.join(DEFAULT_PATTERNS)}", file=sys.stderr)
        return 2
    try:
        findings = lint(actions, args.actionlint, args.shellcheck)
    except (LayoutError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        return 2

    annotate = os.environ.get("GITHUB_ACTIONS") == "true"
    for finding in findings:
        print(f"{finding.path}:{finding.line}:{finding.column}: {finding.message} [{finding.kind}]")
        if annotate:
            properties = {
                "file": finding.path,
                "line": finding.line,
                "col": finding.column,
                "title": f"actionlint ({finding.kind})",
            }
            fields = ",".join(f"{key}={escape_property(str(value))}" for key, value in properties.items())
            print(f"::error {fields}::{escape_annotation(finding.message)}")
    return 1 if findings else 0


def lint(actions: list[Path], actionlint: str, shellcheck: str | None) -> list[Finding]:
    """Lint composite actions and return findings located in their sources."""
    with tempfile.TemporaryDirectory() as temporary:
        workflows: dict[Path, tuple[Path, Workflow]] = {}
        for index, action in enumerate(actions):
            workflow = to_workflow(action.read_text(encoding="utf-8"), action)
            if workflow is None:
                continue
            generated = Path(temporary) / f"{index}-{action.parent.name}.yml"
            generated.write_text(workflow.text, encoding="utf-8")
            workflows[generated.resolve()] = (action, workflow)
        if not workflows:
            return []

        command = [actionlint, "-no-color", "-format", "{{json .}}"]
        if shellcheck:
            command += ["-shellcheck", shellcheck]
        result = subprocess.run(
            [*command, *map(str, workflows)],
            capture_output=True,
            check=False,
            text=True,
            timeout=120,
        )
        # actionlint exits 0 without findings, 1 with findings, and 2 or 3
        # when it cannot lint.
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"actionlint failed with exit status {result.returncode}:\n{result.stderr.strip()}"
            )
        try:
            errors = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as error:
            raise RuntimeError(f"actionlint printed invalid JSON: {error}") from error

        findings = []
        for error in errors:
            # actionlint prints paths relative to the working directory.
            action, workflow = workflows[Path(error["filepath"]).resolve()]
            line, column = workflow.locate(error["line"], error["column"])
            findings.append(Finding(str(action), line, column, error["kind"], error["message"]))
    if result.returncode == 1 and not findings:
        raise RuntimeError(f"actionlint reported failure without findings:\n{result.stderr.strip()}")
    return findings


def to_workflow(text: str, source: Path) -> Workflow | None:
    """Rewrite a composite action as a workflow, or return None for other actions."""
    lines = text.splitlines()
    blocks = top_level_blocks(lines)

    runs = blocks.get("runs")
    if runs is None:
        raise LayoutError(f"{source}: no top-level runs: block")
    using = next(
        (match.group(1) for index in runs if (match := RUNS_USING.match(lines[index]))),
        None,
    )
    if using is None:
        raise LayoutError(f"{source}: runs: has no block-style using: key")
    if using != "composite":
        return None

    output: list[str] = []
    origins: list[Origin | None] = []

    def emit(line: str, origin: Origin | None) -> None:
        output.append(line)
        origins.append(origin)

    if "name" in blocks:
        first = blocks["name"][0]
        emit(lines[first], Origin(first + 1, 0))

    emit("on:", None)
    inputs = blocks.get("inputs")
    if inputs is None:
        emit("  workflow_dispatch:", None)
    else:
        header, *body = inputs
        if not BLANK_OR_COMMENT.match(TOP_LEVEL_KEY.match(lines[header]).group(2)):
            raise LayoutError(f"{source}:{header + 1}: inputs: must be a block mapping")
        emit("  workflow_dispatch:", None)
        emit("    inputs:", Origin(header + 1, 4))
        for index in body:
            emit(indent(lines[index], 4), Origin(index + 1, 4))

    steps = next((index for index in runs if RUNS_STEPS.match(lines[index])), None)
    if steps is None:
        raise LayoutError(f"{source}: runs: has no block-style steps: key")
    emit("jobs:", None)
    emit("  composite:", None)
    emit("    runs-on: ubuntu-latest", None)
    emit("    steps:", Origin(steps + 1, 2))
    for index in runs[runs.index(steps) + 1 :]:
        line = lines[index]
        if not line.startswith("   "):
            # Blank lines and comments shallower than the steps do not end
            # them; deeper lines, including script comments, are kept.
            if BLANK_OR_COMMENT.match(line):
                emit("", Origin(index + 1, 2))
                continue
            break
        emit(indent(line, 2), Origin(index + 1, 2))

    return Workflow("\n".join(output) + "\n", origins)


def top_level_blocks(lines: list[str]) -> dict[str, list[int]]:
    """Group line indexes under the top-level key that owns them."""
    blocks: dict[str, list[int]] = {}
    current: list[int] | None = None
    for index, line in enumerate(lines):
        if line.startswith("#"):
            continue
        match = TOP_LEVEL_KEY.match(line)
        if match:
            current = blocks.setdefault(match.group(1), [])
        if current is not None:
            current.append(index)
    return blocks


def indent(line: str, width: int) -> str:
    return " " * width + line if line.strip() else ""


def escape_annotation(message: str) -> str:
    """Escape a message for a GitHub Actions workflow command."""
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value: str) -> str:
    """Escape a property value for a GitHub Actions workflow command."""
    return escape_annotation(value).replace(":", "%3A").replace(",", "%2C")


if __name__ == "__main__":
    sys.exit(main())
