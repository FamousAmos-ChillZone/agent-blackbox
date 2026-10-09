"""The installer's Python-environment fallback works on a uv-built venv (KI-042).

On every fresh Ubuntu 24.04 bench the one-line installer stopped once with
"No module named pip": setup-hermes.sh installs uv into ~/.local/bin and builds
the venv with it (uv venvs ship no pip), and when it then fails, the outer
installer's fallback looked for uv on ITS OWN PATH — which does not include
~/.local/bin yet — and fell back to `python -m pip`. These tests run the real
shell functions from scripts/blackbox-install.sh.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"


def _function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?\n\}}", INSTALL_SH.read_text(encoding="utf-8"), re.DOTALL | re.MULTILINE)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def _run(body: str, env: dict) -> subprocess.CompletedProcess:
    script = "set -euo pipefail\nstep() { :; }\n" + _function("find_uv") + "\n" + _function("ensure_venv_pip") + "\n" + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def test_find_uv_finds_the_copy_setup_hermes_installed_off_path(tmp_path: Path) -> None:
    uv = tmp_path / ".local" / "bin" / "uv"
    uv.parent.mkdir(parents=True)
    uv.write_text("#!/bin/sh\nexit 0\n")
    uv.chmod(0o755)

    found = _run("find_uv", {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"})

    assert found.returncode == 0 and found.stdout.strip() == str(uv)


def test_find_uv_reports_absence(tmp_path: Path) -> None:
    missing = _run("find_uv", {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"})

    assert missing.returncode != 0 and missing.stdout == ""


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build a pip-less venv")
def test_ensure_venv_pip_bootstraps_pip_into_a_uv_built_venv(tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    subprocess.run(["uv", "venv", "-q", str(venv)], check=True, capture_output=True)
    assert subprocess.run([str(venv / "bin" / "python"), "-m", "pip", "--version"],
                          capture_output=True).returncode != 0   # the KI-042 starting point

    result = _run(f"ensure_venv_pip {shlex.quote(str(venv))}", {**os.environ, "HOME": str(tmp_path)})

    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(venv / "bin" / "python"), "-m", "pip", "--version"],
                          capture_output=True).returncode == 0
