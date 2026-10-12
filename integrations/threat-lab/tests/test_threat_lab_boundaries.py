"""The runner's boundaries: no plugin import other than the by-path schema load,
in-sandbox modules independent of the schema, no Evidence built here (only the
curator's extractor builds it), and the fixture output equal to what the
builder makes now (LES-029)."""

from __future__ import annotations

import ast
from pathlib import Path

from threat_lab import fixtures, schema

RUNNER_ROOT = Path(__file__).resolve().parents[1]
#: Modules copied into the sandbox image: they run where the schema file is absent.
SANDBOX_MODULES = {"__init__", "identifiers", "probe", "rules"}
#: Modules copied into the level-4 guest root filesystem (microvm/Dockerfile.guest).
GUEST_MODULES = {"__init__", "identifiers", "bait", "guest"}


def _python_files():
    return sorted(RUNNER_ROOT.rglob("*.py"))


def _imports(path: Path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            yield ("." * node.level) + (node.module or "")


def test_nothing_imports_the_plugin():
    offenders = [(path.name, name) for path in _python_files() for name in _imports(path)
                 if name.split(".")[0] in ("plugins", "blackbox", "hermes_cli", "agent")]
    assert offenders == []


def test_exactly_one_file_loads_the_evidence_schema_by_path():
    package = sorted((RUNNER_ROOT / "threat_lab").glob("*.py"))
    loaders = [path for path in package if "spec_from_file_location" in path.read_text(encoding="utf-8")]
    assert loaders == [RUNNER_ROOT / "threat_lab" / "schema.py"]
    assert schema.schema_path().name == "evidence_schema.py"


def test_the_sandbox_modules_never_need_the_schema():
    for name in SANDBOX_MODULES | GUEST_MODULES:
        imported = set(_imports(RUNNER_ROOT / "threat_lab" / f"{name}.py"))
        assert not imported & {".schema", ".output", ".api", ".runner", ".fixtures", ".cli"}, name


def test_the_dockerfile_copies_only_the_sandbox_modules():
    copy = next(line for line in (RUNNER_ROOT / "Dockerfile").read_text().splitlines() if line.startswith("COPY "))
    copied = {Path(part).stem for part in copy.split()[1:-1]}
    assert copied == SANDBOX_MODULES


def test_the_guest_image_copies_only_the_guest_modules():
    dockerfile = (RUNNER_ROOT / "microvm" / "Dockerfile.guest").read_text()
    copy = next(line for line in dockerfile.splitlines() if line.startswith("COPY threat_lab/"))
    assert {Path(part).stem for part in copy.split()[1:-1]} == GUEST_MODULES
    for name in GUEST_MODULES - {"__init__"}:
        imported = {entry for entry in _imports(RUNNER_ROOT / "threat_lab" / f"{name}.py") if entry.startswith(".")}
        assert imported <= {"." , ".bait", ".identifiers"}, (name, imported)


def test_the_lab_never_builds_evidence():
    """Evidence is built by the curator's extractor alone (L3): no runner module
    calls the schema's builders or names an Evidence."""
    for path in sorted((RUNNER_ROOT / "threat_lab").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for forbidden in ("validate_evidence", "evidence_schema.to_json", "evidence_schema.to_mapping",
                          "evidence_schema.Evidence", "Evidence("):
            assert forbidden not in source, f"{path.name} uses {forbidden}"


def test_the_committed_fixture_output_is_what_the_builder_makes_now():
    built = fixtures.build_fixtures()
    for name, text in built.items():
        assert (fixtures.FIXTURES_DIR / name).read_text(encoding="utf-8") == text, (
            f"{name} is stale: run `python -m threat_lab fixtures --write` in this commit")
