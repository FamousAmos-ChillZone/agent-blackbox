"""Blackbox stays admissible to the Hermes plugin catalog.

The catalog's CI gate is ``hermes plugins validate``: the manifest must declare
every hook ``register()`` installs, ``requires_hermes`` must be a SemVer floor,
and the install-time security scan must not call the plugin ``dangerous``.
These tests run Hermes's OWN validator over ``plugins/blackbox`` so a change that
would fail admission (an undeclared hook, a demo text the scanner reads as an
attack, a bundled binary) fails here first — not in a reviewer's CI log.
"""

from pathlib import Path

from hermes_cli.plugin_validate import validate_plugin_dir
from tools.plugin_guard import scan_plugin

PLUGIN_DIR = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"


def _checks(report) -> dict[str, tuple[bool, str]]:
    return {name: (ok, detail) for name, ok, detail in report.checks}


def test_catalog_validator_admits_blackbox():
    report = validate_plugin_dir(PLUGIN_DIR)

    failed = {name: detail for name, (ok, detail) in _checks(report).items() if not ok}
    assert failed == {}


def test_manifest_declares_every_registered_hook_and_a_semver_floor():
    checks = _checks(validate_plugin_dir(PLUGIN_DIR))

    assert checks["declared hooks"][0], checks["declared hooks"][1]
    assert checks["requires_hermes"] == (True, "spec '>=0.21.7' parses")


def test_security_scan_finds_nothing_critical():
    critical = [
        f"{finding.pattern_id} {finding.file}:{finding.line}"
        for finding in scan_plugin(PLUGIN_DIR).findings
        if finding.severity == "critical"
    ]

    assert critical == []
