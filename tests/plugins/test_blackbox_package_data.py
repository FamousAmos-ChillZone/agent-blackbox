"""Every data file the Blackbox plugin reads ships in a wheel (F-038, F-057, R20).

A wheel or sealed install carries only the Python files plus what
``[tool.setuptools.package-data]`` names. A data file a module opens next to itself
(``Path(__file__).with_name(...)``, ``Path(__file__).parent / "static"``) and that
no glob covers is simply absent there: ``known_contracts.json`` was, so a wheel
install exempted no exchange router.

The guard is a static scan, not a list: it walks the plugin's sources for path
expressions rooted at ``Path(__file__)`` that end in a literal name, resolves each
one on disk, and asserts every non-Python file it names (or that lives in a folder
it names) is matched by a ``plugins`` package-data glob. A new data file opened
that way fails here until its glob is added.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS_DIR = REPO_ROOT / "plugins"
BLACKBOX_DIR = PLUGINS_DIR / "blackbox"

#: Read by Hermes plugin discovery, not through ``__file__``, so the scan cannot see it.
READ_BY_THE_HOST = [BLACKBOX_DIR / "plugin.yaml"]


class _Located:
    """Where a path expression points, and whether its last step named a literal file or folder."""

    def __init__(self, path: Path, ends_in_literal: bool):
        self.path = path
        self.ends_in_literal = ends_in_literal


def _locate(node: ast.AST, source: Path) -> Optional[_Located]:
    """Resolve *node* when it is ``Path(__file__)`` followed by ``.resolve()``, ``.parent``,
    ``.parents[n]``, ``.with_name("x")`` or ``/ "x"`` steps; None for anything else."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path":
        if len(node.args) == 1 and isinstance(node.args[0], ast.Name) and node.args[0].id == "__file__":
            return _Located(source, False)
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        inner = _locate(node.func.value, source)
        if inner is None:
            return None
        if node.func.attr == "resolve" and not node.args:
            return inner
        if node.func.attr == "with_name" and len(node.args) == 1 and _literal(node.args[0]):
            return _Located(inner.path.with_name(node.args[0].value), True)
        return None
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        inner = _locate(node.value, source)
        return _Located(inner.path.parent, False) if inner else None
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
        inner = _locate(node.value.value, source)
        if inner is None or not isinstance(node.slice, ast.Constant) or type(node.slice.value) is not int:
            return None
        return _Located(inner.path.parents[node.slice.value], False)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and _literal(node.right):
        inner = _locate(node.left, source)
        return _Located(inner.path / node.right.value, True) if inner else None
    return None


def _literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _opened_paths(source: Path) -> list[Path]:
    """The outermost ``Path(__file__)`` expressions in *source* that end in a literal name."""
    found: list[Path] = []

    def visit(node: ast.AST) -> None:
        located = _locate(node, source)
        if located is not None:
            if located.ends_in_literal:
                found.append(located.path)
            return
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(ast.parse(source.read_text(encoding="utf-8"), filename=str(source)))
    return found


def _data_files_read_by_the_plugin() -> dict[Path, str]:
    """``{data file: who opens it}`` for every non-Python file the plugin reads (folders expanded)."""
    wanted: dict[Path, str] = {path: "Hermes plugin discovery" for path in READ_BY_THE_HOST}
    for source in sorted(BLACKBOX_DIR.rglob("*.py")):
        if "__pycache__" in source.parts:
            continue
        for path in _opened_paths(source):
            opener = str(source.relative_to(REPO_ROOT))
            assert path.exists(), f"{opener} opens {path.relative_to(REPO_ROOT)}, which is not in the tree"
            files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
            for file in files:
                if file.suffix not in {".py", ".pyc"} and "__pycache__" not in file.parts:
                    wanted.setdefault(file, opener)
    return wanted


def _shipped_plugin_files() -> set[Path]:
    """Every file the ``plugins`` package-data globs match (they are relative to plugins/)."""
    package_data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]["package-data"]
    return {path.resolve() for pattern in package_data.get("plugins", []) for path in PLUGINS_DIR.glob(pattern) if path.is_file()}


def test_the_scan_finds_the_files_the_plugin_is_known_to_read():
    wanted = {path.relative_to(BLACKBOX_DIR).as_posix() for path in _data_files_read_by_the_plugin()}
    assert {
        "plugin.yaml",
        "kernel/public_suffix/public_suffix_list.dat",
        "ruleset/legacy_assets.txt",
        "curate/service/never_promote_ranges.json",
        "kernel/crypto_secrets/known_contracts.json",
        "kernel/crypto_secrets/bip39_english.txt",
        "dashboard/static/index.html",
        "docs/REPORTER_TERMS.md",
    } <= wanted


def test_every_plugin_data_file_ships():
    shipped = _shipped_plugin_files()
    missing = sorted(f"{path.relative_to(REPO_ROOT)} (opened by {opener})"
                     for path, opener in _data_files_read_by_the_plugin().items() if path.resolve() not in shipped)
    assert missing == [], "no [tool.setuptools.package-data] plugins glob covers:\n" + "\n".join(missing)
