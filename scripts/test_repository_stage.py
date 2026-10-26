# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Exercise stage detection without creating a real Rust workspace."""

import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-repository-stage.sh").resolve()
TOOLCHAIN = '[toolchain]\nchannel = "1.99.1"\ncomponents = ["clippy", "rustfmt"]\n'


class RepositoryStageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        subprocess.run(["git", "init", "--quiet", str(self.directory)], check=True)

    def write(self, name, content):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def detect(self):
        return subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.directory, capture_output=True,
            text=True, timeout=10,
        )

    def workspace(self):
        self.write("Cargo.toml", '[workspace]\nresolver = "3"\n')
        self.write("Cargo.lock", "version = 4\n")
        self.write("rust-toolchain.toml", TOOLCHAIN)

    def test_documentation_stage_explicitly_disables_rust_jobs(self):
        self.write("README.md", "Design documents.\n")
        result = self.detect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "rust=false\n")
        self.assertIn("Planning stage", result.stderr)

    def test_untracked_rust_sources_cannot_hide_in_the_planning_stage(self):
        self.write("src/lib.rs", "// Synthetic stage-detection fixture.\n")
        result = self.detect()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("rust=false", result.stdout)

    def test_tracked_nested_manifest_requires_a_root_workspace(self):
        self.write("experiments/probe/Cargo.toml", '[package]\nname = "sample"\n')
        subprocess.run(["git", "add", "."], cwd=self.directory, check=True)
        self.assertNotEqual(self.detect().returncode, 0)

    def test_ignored_generated_rust_does_not_enable_workspace_jobs(self):
        self.write(".gitignore", "/target/\n")
        self.write("target/generated.rs", "// Generated fixture.\n")
        result = self.detect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "rust=false\n")

    def test_workspace_requires_lockfile_and_toolchain(self):
        for missing in ("Cargo.lock", "rust-toolchain.toml"):
            with self.subTest(missing=missing):
                self.workspace()
                (self.directory / missing).unlink()
                self.assertNotEqual(self.detect().returncode, 0)

    def test_complete_workspace_enables_real_rust_jobs(self):
        self.workspace()
        result = self.detect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "rust=true\n")

    def test_floating_toolchain_and_missing_components_are_rejected(self):
        for toolchain in (
            TOOLCHAIN.replace("1.99.1", "stable"),
            TOOLCHAIN.replace('["clippy", "rustfmt"]', '["rustfmt"]'),
            "invalid TOML [\n",
        ):
            with self.subTest(toolchain=toolchain):
                self.workspace()
                self.write("rust-toolchain.toml", toolchain)
                self.assertNotEqual(self.detect().returncode, 0)

    def test_empty_lockfile_and_symlinked_toolchain_are_rejected(self):
        self.workspace()
        self.write("Cargo.lock", "")
        self.assertNotEqual(self.detect().returncode, 0)
        self.write("Cargo.lock", "version = 4\n")
        (self.directory / "rust-toolchain.toml").unlink()
        self.write("other.toml", TOOLCHAIN)
        (self.directory / "rust-toolchain.toml").symlink_to("other.toml")
        self.assertNotEqual(self.detect().returncode, 0)

    def test_directory_and_broken_symlink_cannot_be_root_manifests(self):
        manifest = self.directory / "Cargo.toml"
        manifest.mkdir()
        self.assertNotEqual(self.detect().returncode, 0)
        manifest.rmdir()
        manifest.symlink_to("missing.toml")
        self.assertNotEqual(self.detect().returncode, 0)


if __name__ == "__main__":
    unittest.main()
