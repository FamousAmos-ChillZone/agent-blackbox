"""Cross-language parity: the shared fixture must match the Python builders.

``tests/parity/identifier_fixtures.json`` is the ground truth that the OpenClaw
TypeScript plugin also asserts against (``integrations/openclaw/test/parity.mjs``).
This test guards the Python side: if ``plugins/blackbox/kernel/threat_ids.py`` or the ``detection/`` parsers ever change
an identifier, URI, arg-shape, dependency parse, or report-quad shape, this test
fails until the fixture is regenerated — forcing the TS mirror to be updated too.
"""

import json
import pytest
from pathlib import Path

from _blackbox_loader import load_blackbox

_FIXTURE = (
    Path(__file__).resolve().parents[1] / "parity" / "identifier_fixtures.json"
)


def _fixture():
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def test_fixture_exists():
    assert _FIXTURE.exists(), "parity fixture missing — run tests/parity/generate.py"


def test_identifier_parity():
    action_parsing = load_blackbox("detection.action_parsing")
    report_builder = load_blackbox("community.report_builder")
    shell_shapes = load_blackbox("detection.shell_shapes")
    threat_ids = load_blackbox("kernel.threat_ids")
    for case in _fixture()["identifiers"]:
        kind, args = case["kind"], case["in"]
        if kind == "dependency":
            ident = threat_ids.dependency_identifier(**args)
        elif kind == "injection":
            ident = threat_ids.injection_identifier(**args)
        elif kind == "fileaccess":
            ident = threat_ids.fileaccess_identifier(**args)
        elif kind == "skill_version":
            ident = threat_ids.skill_version_identifier(**args)
        elif kind == "skill_shape":
            ident = threat_ids.skill_shape_identifier(**args)
        else:
            ident = threat_ids.escalation_identifier(**args)
        assert ident == case["identifier"], f"{kind} {args}"
        assert threat_ids.threat_uri(ident) == case["threatUri"], f"threat_uri {ident}"


def test_report_uri_parity():
    action_parsing = load_blackbox("detection.action_parsing")
    report_builder = load_blackbox("community.report_builder")
    shell_shapes = load_blackbox("detection.shell_shapes")
    threat_ids = load_blackbox("kernel.threat_ids")
    for case in _fixture()["reportUris"]:
        if not case["reporter"].strip():
            # LES-003 (Refine R0): Python refuses a blank reporter; the OpenClaw
            # bridge still substitutes "anonymous" until it is ported (KI-182).
            with pytest.raises(ValueError):
                threat_ids.report_uri(case["identifier"], case["reporter"])
            continue
        assert (
            threat_ids.report_uri(case["identifier"], case["reporter"]) == case["reportUri"]
        ), case["identifier"]


def test_arg_shape_parity():
    action_parsing = load_blackbox("detection.action_parsing")
    report_builder = load_blackbox("community.report_builder")
    shell_shapes = load_blackbox("detection.shell_shapes")
    threat_ids = load_blackbox("kernel.threat_ids")
    for case in _fixture()["argShapes"]:
        assert (
            shell_shapes.normalize_arg_shape(case["tool"], case["args"]) == case["shape"]
        ), case["args"]


def test_dependency_parse_parity():
    action_parsing = load_blackbox("detection.action_parsing")
    report_builder = load_blackbox("community.report_builder")
    shell_shapes = load_blackbox("detection.shell_shapes")
    threat_ids = load_blackbox("kernel.threat_ids")
    for case in _fixture()["dependencyParses"]:
        assert (
            action_parsing.parse_dependency_installs(case["command"]) == case["packages"]
        ), case["command"]


def test_report_quads_parity():
    action_parsing = load_blackbox("detection.action_parsing")
    report_builder = load_blackbox("community.report_builder")
    shell_shapes = load_blackbox("detection.shell_shapes")
    threat_ids = load_blackbox("kernel.threat_ids")
    report_schema = load_blackbox("community.report_schema")
    compared, refused = 0, set()
    for case in _fixture()["reportQuads"]:
        try:
            quads = report_builder.build_report_quads(**case["in"])
        except report_schema.ReportValidationError:
            # Refine R1: Python now refuses a dependency report without kind=malware
            # and a skill report that names a local skill; the OpenClaw bridge still
            # builds them until it is ported (KI-182).
            refused.add(case["in"]["category"])
            continue
        compared += 1
        rows = sorted(
            (
                {"subject": x["subject"], "predicate": x["predicate"], "object": x["object"]}
                for x in quads
                if not x["predicate"].endswith("dateModified")
            ),
            key=lambda r: (r["predicate"], r["object"]),
        )
        assert rows == case["quadsNoDate"], case["in"]
    assert compared >= 1
    assert refused <= {"dependency", "skill"}


def test_ioc_value_parity():
    """KI-193: IOC canonicalisation (incl. IPv6) is ground truth for both runtimes."""
    threat_ids = load_blackbox("kernel.threat_ids")
    for case in _fixture()["iocValues"]:
        assert threat_ids.normalize_ioc_value(case["type"], case["in"]) == case["canonical"], case
