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


# --- an upgrade keeps the operator's protection mode (2026-10-13) ------------
# configure_blackbox_mode wrote "audit" on every run, so re-running the installer
# (an upgrade) quietly switched a block-mode install to audit.

REPO_ROOT = INSTALL_SH.parents[1]


def _saved_mode(tmp_path: Path, saved: str | None, requested_env: str | None) -> str:
    """Run the real configure_blackbox_mode on a config holding *saved*; the mode it leaves."""
    from plugins.blackbox.kernel import yaml_files

    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    wrapper = venv_bin / "python"   # a wrapper, not a symlink: a symlinked venv python loses its packages
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    home = tmp_path / "hermes"
    home.mkdir()
    if saved is not None:
        (home / "config.yaml").write_text(f"plugins:\n  entries:\n    blackbox:\n      mode: {saved}\n", encoding="utf-8")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    if requested_env is not None:
        env["BLACKBOX_MODE"] = requested_env
    body = (_function("write_blackbox_mode") + "\n" + _function("configure_blackbox_mode") + "\n"
            + f'VENV_DIR="{tmp_path / "venv"}"; HERMES_HOME="{home}"\nconfigure_blackbox_mode')
    result = subprocess.run(["bash", "-c", "set -uo pipefail\nok() { echo \"OK $*\"; }\nwarn() { echo \"WARN $*\"; }\nheading() { :; }\n" + body],
                            capture_output=True, text=True, env=env, cwd=REPO_ROOT, check=False)
    assert "WARN" not in result.stdout, result.stdout + result.stderr
    return yaml_files.load_yaml(home / "config.yaml")["plugins"]["entries"]["blackbox"]["mode"]


def test_a_rerun_keeps_block_mode(tmp_path: Path) -> None:
    assert _saved_mode(tmp_path, saved="block", requested_env=None) == "block"


def test_a_first_install_starts_in_audit(tmp_path: Path) -> None:
    assert _saved_mode(tmp_path, saved=None, requested_env=None) == "audit"


def test_an_explicit_mode_still_wins(tmp_path: Path) -> None:
    assert _saved_mode(tmp_path, saved="block", requested_env="audit") == "audit"


def test_a_pm_checkout_never_reuses_a_kept_venv() -> None:
    body = _function("install_python_env")
    assert '[ ! -x "$REPO_DIR/scripts/run-in-hermes-env" ]' in body.split("ensure_web_extra")[0]


# --- a failed Hermes setup never leaves a half-built install (2026-10-13) ----
# On an upgraded bench setup-hermes.sh failed once (launcher publication) and the
# installer fell back to the old minimal venv/, built for the previous Hermes; attach,
# the reviewer check and the sync then all failed. A pm checkout retries, then stops.

def _run_install_python_env(tmp_path: Path, setup_exit_codes: list[int]) -> subprocess.CompletedProcess[str]:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    runner = repo / "scripts" / "run-in-hermes-env"
    runner.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    runner.chmod(0o755)
    calls = tmp_path / "calls"
    codes = " ".join(str(code) for code in setup_exit_codes)
    (repo / "setup-hermes.sh").write_text(
        f'n=$(wc -l < "{calls}" 2>/dev/null || echo 0); echo x >> "{calls}"\n'
        f'set -- {codes}\nshift "$n"\nexit "${{1:-0}}"\n', encoding="utf-8")
    body = (_function("install_python_env") + "\n" + _function("use_hermes_selected_venv") + "\n"
            + 'ok() { echo "OK $*"; }; err() { echo "ERR $*"; }; ensure_web_extra() { :; }\n'
            + 'minimal_python_env() { echo "FELL BACK TO MINIMAL VENV"; }\n'
            + f'REPO_DIR="{repo}"\ninstall_python_env; echo "RETURNED"')
    return subprocess.run(["bash", "-c", "set -uo pipefail\nstep() { :; }\nwarn() { echo \"WARN $*\"; }\nheading() { :; }\n" + body],
                          capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}, check=False)


def test_a_transient_setup_failure_is_retried(tmp_path: Path) -> None:
    result = _run_install_python_env(tmp_path, [1, 0])

    assert "second try" in result.stdout and "RETURNED" in result.stdout
    assert "FELL BACK" not in result.stdout


def test_a_setup_that_fails_twice_stops_the_install(tmp_path: Path) -> None:
    result = _run_install_python_env(tmp_path, [1, 1])

    assert result.returncode == 1 and "failed twice" in result.stdout
    assert "FELL BACK" not in result.stdout and "RETURNED" not in result.stdout
