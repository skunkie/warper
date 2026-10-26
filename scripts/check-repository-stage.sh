#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Emit one machine-readable value on stdout; send diagnostics to stderr.
set -euo pipefail

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

if [[ -e Cargo.toml || -L Cargo.toml ]]; then
    for required in Cargo.toml Cargo.lock rust-toolchain.toml; do
        if [[ ! -f "$required" || ! -s "$required" || -L "$required" ]]; then
            echo "A Cargo workspace requires a nonempty regular $required" >&2
            exit 1
        fi
    done
    python3 - <<'PY'
import re
import sys
import tomllib
from pathlib import Path

try:
    toolchain = tomllib.loads(Path("rust-toolchain.toml").read_text())["toolchain"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain.get("channel", "")):
        raise ValueError("channel must pin an exact released Rust version")
    if not {"clippy", "rustfmt"}.issubset(toolchain.get("components", [])):
        raise ValueError("components must include clippy and rustfmt")
except (KeyError, TypeError, ValueError, OSError) as error:
    print(f"Invalid rust-toolchain.toml: {error}", file=sys.stderr)
    sys.exit(1)
PY
    echo "rust=true"
else
    rust_sources=$(git ls-files --cached --others --exclude-standard -- '*.rs' '**/Cargo.toml')
    if [[ -n "$rust_sources" ]]; then
        echo "Rust sources and nested manifests require a root Cargo.toml" >&2
        exit 1
    fi
    echo "rust=false"
    echo "Planning stage: Cargo checks start with the root manifest." >&2
fi
