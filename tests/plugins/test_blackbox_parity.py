"""Cross-language parity: the shared fixture must match the Python builders.

``tests/parity/identifier_fixtures.json`` is the ground truth that the OpenClaw
TypeScript plugin also asserts against (``integrations/openclaw/test/parity.mjs``).
This test guards the Python side: if ``plugins/blackbox/quads.py`` ever changes
an identifier, URI, arg-shape, dependency parse, or report-quad shape, this test
fails until the fixture is regenerated — forcing the TS mirror to be updated too.
"""

import json
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
    for case in _fixture()["reportQuads"]:
        quads = report_builder.build_report_quads(**case["in"])
        rows = sorted(
            (
                {"subject": x["subject"], "predicate": x["predicate"], "object": x["object"]}
                for x in quads
                if not x["predicate"].endswith("dateModified")
            ),
            key=lambda r: (r["predicate"], r["object"]),
        )
        assert rows == case["quadsNoDate"], case["in"]
