"""scripts/move_proof.py on a throwaway git repo: a move is clean, an edit is not, a stale lazy import is caught.

Each case builds a tiny plugin package, commits it, changes the working tree and
runs the tool as a child process, exactly as a builder would.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "move_proof.py"
PLUGIN = "plugins/demo"
ADD_MODULE = "def add(a, b):\n    return a + b\n"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A committed plugin with one module holding one function."""
    plugin = tmp_path / PLUGIN
    plugin.mkdir(parents=True)
    (plugin / "__init__.py").write_text("", encoding="utf-8")
    (plugin / "math_ops.py").write_text(ADD_MODULE, encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def _move_proof(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "HEAD", "--plugin", PLUGIN],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=60,
        check=False,
    )


def test_pure_rename_is_clean_with_one_moved_body(repo: Path) -> None:
    _git(repo, "mv", f"{PLUGIN}/math_ops.py", f"{PLUGIN}/arithmetic.py")

    result = _move_proof(repo)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "moved (1):\n  math_ops::add -> arithmetic::add\n" in result.stdout
    for empty in ("added (0):", "removed (0):", "changed (0):", "broken imports (0):"):
        assert empty in result.stdout


def test_one_token_body_change_is_reported_with_exit_1(repo: Path) -> None:
    (repo / PLUGIN / "math_ops.py").write_text(ADD_MODULE.replace("a + b", "a - b"), encoding="utf-8")

    result = _move_proof(repo)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "changed (1):\n  math_ops::add\n" in result.stdout


def test_broken_lazy_import_inside_a_function_is_reported(repo: Path) -> None:
    # The function body is untouched, but the module it imports lazily has moved away.
    (repo / PLUGIN / "caller.py").write_text(
        "def total(values):\n    from .math_ops import add\n    return add(*values)\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "caller")
    _git(repo, "mv", f"{PLUGIN}/math_ops.py", f"{PLUGIN}/arithmetic.py")

    result = _move_proof(repo)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "changed (0):" in result.stdout
    assert "broken imports (1):\n  caller:2: from .math_ops import add -> ModuleNotFoundError" in result.stdout


def test_a_changed_property_getter_is_not_hidden_by_its_setter(repo: Path) -> None:
    # Getter and setter share one qualified name; neither may overwrite the other.
    holder = "class Box:\n    @property\n    def size(self):\n        return {}\n\n    @size.setter\n    def size(self, value):\n        self._size = value\n"
    (repo / PLUGIN / "box.py").write_text(holder.format("self._size"), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "box")
    (repo / PLUGIN / "box.py").write_text(holder.format("0"), encoding="utf-8")

    result = _move_proof(repo)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "changed (1):\n  box::Box.size\n" in result.stdout


def test_a_function_defined_under_a_module_level_if_or_try_is_compared(repo: Path) -> None:
    guarded = "import sys\n\nif sys.platform:\n    def pick():\n        return {}\n\ntry:\n    import json\nexcept ImportError:\n    def load():\n        return None\n"
    (repo / PLUGIN / "guarded.py").write_text(guarded.format("1"), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "guarded")
    (repo / PLUGIN / "guarded.py").write_text(guarded.format("2"), encoding="utf-8")

    result = _move_proof(repo)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "changed (1):\n  guarded::pick\n" in result.stdout


def test_a_docstring_edit_is_clean_but_a_change_below_the_docstring_is_not(repo: Path) -> None:
    documented = 'def scale(x):\n    """{}"""\n    return x * {}\n'
    (repo / PLUGIN / "scale.py").write_text(documented.format("Double it.", "2"), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "scale")

    (repo / PLUGIN / "scale.py").write_text(documented.format("Twice the value.", "2"), encoding="utf-8")
    reworded = _move_proof(repo)
    (repo / PLUGIN / "scale.py").write_text(documented.format("Double it.", "3"), encoding="utf-8")
    changed = _move_proof(repo)

    assert reworded.returncode == 0, reworded.stdout + reworded.stderr
    assert changed.returncode == 1, changed.stdout + changed.stderr
    assert "changed (1):\n  scale::scale\n" in changed.stdout
