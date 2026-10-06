"""Regression coverage for Agent Blackbox installer checkout resolution."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO_ROOT / "scripts" / "blackbox-install.ps1"


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"{name}\(\) \{{.*?\n\}}", text, re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def test_shell_installer_defaults_to_invocation_directory() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")

    assert 'BLACKBOX_INSTALL_ROOT="$PWD/agent-blackbox"' in text
    assert 'BLACKBOX_INSTALL_ROOT="$HOME/agent-blackbox"' not in text


def test_shell_installer_rejects_incomplete_existing_checkout() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    validity = re.search(
        r"blackbox_repo_is_valid\(\) \{.*?\n\}", text, re.DOTALL
    )

    assert validity is not None
    block = validity.group(0)
    assert "rev-parse --verify HEAD" in block
    assert 'pyproject.toml' in block
    assert 'plugins/blackbox' in block
    assert "move_broken_blackbox_repo_aside" in text
    assert '|| true' not in re.search(
        r"resolve_repo\(\) \{.*?\n\}", text, re.DOTALL
    ).group(0)


def test_powershell_installer_matches_checkout_contract() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert 'Join-Path ([string](Get-Location)) "agent-blackbox"' in text
    assert '$env:USERPROFILE\\agent-blackbox' not in text
    assert "function Test-BlackboxRepoCheckout" in text
    assert "rev-parse --verify HEAD" in text
    assert 'Test-Path "$Path\\pyproject.toml"' in text
    assert 'Test-Path "$Path\\plugins\\blackbox"' in text
    assert "Move-BrokenBlackboxRepoAside" in text
    assert "Move-Item -LiteralPath $Path" in text


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
def test_shell_installer_replaces_incomplete_checkout_with_real_clone(
    tmp_path: Path,
) -> None:
    """Exercise the reported state: Git exists, project markers do not."""
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True)
    (source / "pyproject.toml").write_text("[project]\nname='agent-blackbox'\n")
    (source / "plugins" / "blackbox").mkdir(parents=True)
    (source / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n")
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "fixture",
        ],
        cwd=source,
        check=True,
        capture_output=True,
    )

    install_dir = tmp_path / "agent-blackbox"
    install_dir.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=install_dir, check=True)
    (install_dir / "partial.txt").write_text("interrupted checkout\n")
    subprocess.run(["git", "add", "."], cwd=install_dir, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "partial",
        ],
        cwd=install_dir,
        check=True,
        capture_output=True,
    )

    text = INSTALL_SH.read_text(encoding="utf-8")
    functions = "\n".join(
        _shell_function(text, name)
        for name in (
            "blackbox_repo_is_valid",
            "move_broken_blackbox_repo_aside",
            "resolve_repo",
        )
    )
    script = f"""
set -euo pipefail
step() {{ :; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ printf '%s\\n' "$*" >&2; }}
BLACKBOX_INSTALL_ROOT={shlex.quote(str(install_dir))}
REPO_URL={shlex.quote(str(source))}
REPO_BRANCH=main
{functions}
resolve_repo
"""
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    assert (install_dir / "pyproject.toml").is_file()
    assert (install_dir / "plugins" / "blackbox").is_dir()
    backups = list(tmp_path.glob("agent-blackbox.broken-*"))
    assert len(backups) == 1
    assert (backups[0] / "partial.txt").read_text() == "interrupted checkout\n"


def _commit_all(repo: Path, message: str) -> None:
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-m", message], cwd=repo, check=True, capture_output=True)


def _resolve_repo(install_dir: Path, source: Path, branch: str) -> subprocess.CompletedProcess:
    text = INSTALL_SH.read_text(encoding="utf-8")
    functions = "\n".join(_shell_function(text, name)
                          for name in ("blackbox_repo_is_valid", "move_broken_blackbox_repo_aside", "resolve_repo"))
    script = f"""
set -euo pipefail
step() {{ :; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ printf '%s\\n' "$*" >&2; }}
BLACKBOX_INSTALL_ROOT={shlex.quote(str(install_dir))}
REPO_URL={shlex.quote(source.as_uri())}
REPO_BRANCH={shlex.quote(branch)}
{functions}
resolve_repo
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
def test_shell_installer_moves_an_existing_install_to_another_branch(tmp_path: Path) -> None:
    """KI-287: the installer clones one branch, shallow. Re-running it with
    BLACKBOX_REPO_BRANCH set to another branch fetched that branch only into
    FETCH_HEAD, so `git checkout <branch>` failed ("resolve local changes") on
    every existing install — found upgrading two benches to the DKG 10.0.21
    branch on 2026-10-06. A file:// URL keeps --depth honoured, as on a real
    network clone (git ignores --depth for plain local paths)."""
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True, capture_output=True)
    (source / "pyproject.toml").write_text("[project]\nname='agent-blackbox'\n")
    (source / "plugins" / "blackbox").mkdir(parents=True)
    (source / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n")
    _commit_all(source, "main")
    subprocess.run(["git", "checkout", "-q", "-b", "feat/next"], cwd=source, check=True)
    (source / "NEXT").write_text("the next release\n")
    _commit_all(source, "next")
    subprocess.run(["git", "checkout", "-q", "main"], cwd=source, check=True)
    install_dir = tmp_path / "agent-blackbox"

    first = _resolve_repo(install_dir, source, "main")
    assert first.returncode == 0, first.stderr
    assert not (install_dir / "NEXT").exists()

    switched = _resolve_repo(install_dir, source, "feat/next")

    assert switched.returncode == 0, switched.stderr
    head = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=install_dir,
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == "feat/next"
    assert (install_dir / "NEXT").read_text() == "the next release\n"

    again = _resolve_repo(install_dir, source, "feat/next")   # a later same-branch re-run still works
    assert again.returncode == 0, again.stderr


def test_powershell_installer_fetches_a_branch_with_an_explicit_refspec() -> None:
    """KI-287 mirror: the Windows installer must record origin/<branch> too."""
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert '"+refs/heads/${RepoBranch}:refs/remotes/origin/${RepoBranch}"' in text
    assert "remote set-branches --add origin $RepoBranch" in text
