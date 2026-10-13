"""The installer finds Hermes 0.21.7's environment, and registers no boot service for a missing node.

Hermes 0.21.7's setup-hermes.sh builds the environment with pm OUTSIDE the checkout
($HERMES_HOME/installs/<install>/environments/<generation>/venv), so the installer's
fixed $REPO_DIR/venv no longer existed on a fresh install: the plugin copy, config,
mode, attach and dashboard steps all failed with "venv/bin/python: No such file".
And with --skip-dkg the installer still registered a launchd/systemd service for a
DKG node that was never installed (launchd exit 78 at every login). These tests run
the real shell functions from scripts/blackbox-install.sh.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="runs bash functions of the POSIX installer")


def _function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?\n\}}", INSTALL_SH.read_text(encoding="utf-8"), re.DOTALL | re.MULTILINE)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def _run(body: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    stubs = "step() { echo \"STEP $*\"; }\nwarn() { echo \"WARN $*\"; }\nheading() { :; }\n"
    script = "set -uo pipefail\n" + stubs + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, check=False)


def _repo_with_runner(tmp_path: Path, prints: str) -> Path:
    """A checkout whose scripts/run-in-hermes-env prints a progress line, then *prints*."""
    repo = tmp_path / "repo"
    runner = repo / "scripts" / "run-in-hermes-env"
    runner.parent.mkdir(parents=True)
    runner.write_text(f"#!/bin/sh\necho 'Preparing the isolated Hermes runtime...'\necho '{prints}'\n", encoding="utf-8")
    runner.chmod(0o755)
    return repo


def _venv(tmp_path: Path) -> Path:
    python = tmp_path / "home" / "installs" / "abc" / "environments" / "gen" / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    python.chmod(0o755)
    return python.parent.parent


def test_uses_the_environment_hermes_reports_as_selected(tmp_path: Path) -> None:
    venv = _venv(tmp_path)
    repo = _repo_with_runner(tmp_path, str(venv))

    result = _run(_function("use_hermes_selected_venv") + f'\nREPO_DIR="{repo}"; VENV_DIR="{repo}/venv"\n'
                  'use_hermes_selected_venv; echo "VENV=$VENV_DIR"', {"PATH": "/usr/bin:/bin"})

    assert f"VENV={venv}" in result.stdout, result.stdout + result.stderr


def test_a_checkout_without_the_runner_keeps_the_classic_venv(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    result = _run(_function("use_hermes_selected_venv") + f'\nREPO_DIR="{repo}"; VENV_DIR="{repo}/venv"\n'
                  'use_hermes_selected_venv; echo "VENV=$VENV_DIR"', {"PATH": "/usr/bin:/bin"})

    assert f"VENV={repo}/venv" in result.stdout and "WARN" not in result.stdout


def test_an_answer_that_is_not_an_environment_is_not_used(tmp_path: Path) -> None:
    repo = _repo_with_runner(tmp_path, str(tmp_path / "nowhere"))

    result = _run(_function("use_hermes_selected_venv") + f'\nREPO_DIR="{repo}"; VENV_DIR="{repo}/venv"\n'
                  'use_hermes_selected_venv; echo "VENV=$VENV_DIR"', {"PATH": "/usr/bin:/bin"})

    assert f"VENV={repo}/venv" in result.stdout and "WARN Could not ask Hermes" in result.stdout


def test_setup_hermes_success_asks_hermes_for_the_environment() -> None:
    body = _function("install_python_env")

    assert re.search(r'Base environment ready via setup-hermes\.sh"\n\s*use_hermes_selected_venv', body)


def test_no_boot_service_is_registered_without_a_dkg_node(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    result = _run(_function("register_boot_service") + f'\nBLACKBOX_DKG_BIN="{tmp_path}/missing/dkg"\n'
                  'register_boot_service; echo "RC=$?"', {"PATH": "/usr/bin:/bin", "HOME": str(home)})

    assert "RC=0" in result.stdout and "not registering a boot service" in result.stdout
    assert not (home / "Library").exists()
