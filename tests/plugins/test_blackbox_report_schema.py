"""Refine R1 — an unvalidated report cannot be built (community/report_schema.py).

Every field is checked against a closed vocabulary that already exists in the
code, the identifier must equal the one its fields derive, and free text is
refused. Rejects never leave the machine.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from plugins.blackbox.community import report_builder
from plugins.blackbox.community.report_schema import ReportValidationError, validate_report
from plugins.blackbox.kernel import constants, threat_ids

SHA = "a" * 64


def _ok(category, identifier, **evidence):
    return validate_report(identifier=identifier, category=category, severity="high", framework="hermes", evidence=evidence)


def _bad(category, identifier, **evidence):
    with pytest.raises(ReportValidationError):
        _ok(category, identifier, **evidence)


# ------------------------------------------------------------ accepted shapes


def test_each_category_accepts_its_valid_shape():
    inj = threat_ids.injection_identifier("ignore previous instructions")
    assert _ok("injection", inj, context="in-fetched-page", owasp_category="llm01").evidence == (
        ("context", "in-fetched-page"), ("owasp_category", "LLM01"))
    _ok("escalation", "escalation:terminal:rm-rf-system-paths", tool_name="terminal", arg_shape="rm-rf-system-paths")
    _ok("dependency", "dep:pypi:evil-pkg@1.0", ecosystem="pypi", package_name="Evil_Pkg", package_version="1.0",
        kind="malware", advisory_id="MAL-2026-1")
    _ok("fileaccess", "fileaccess:read_file:ssh-private-key", tool_name="read_file", file_category="ssh-private-key")
    _ok("skill", f"skill:artifact:{SHA}:credential-exfil", artifact_hash=SHA, danger_shape="credential-exfil")
    _ok("ioc", threat_ids.ioc_identifier("domain", "evil.example"), ioc_type="domain")


# ------------------------------------------------------------- refused shapes


def test_a_vulnerability_report_cannot_be_built():
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x", package_version="1", kind="vulnerability")
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x", package_version="1")   # kind is mandatory


def test_an_injection_report_without_a_valid_context_is_refused():
    inj = threat_ids.injection_identifier("p")
    _bad("injection", inj)
    _bad("injection", inj, context="https://example.com/page")       # never a source domain (decision 24)


def test_free_text_is_refused():
    inj = threat_ids.injection_identifier("p")
    _bad("injection", inj, context="in-user-prompt", pattern="ignore all previous instructions")
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x", package_version="1", kind="malware",
         description="free text")


def test_a_local_skill_is_never_named():
    _bad("skill", f"skill:artifact:{SHA}:obfuscation", artifact_hash=SHA, danger_shape="obfuscation", skill_name="acme-internal")
    _bad("skill", f"skill:artifact:{'z' * 64}:obfuscation", artifact_hash="z" * 64, danger_shape="obfuscation")


def test_values_outside_the_closed_vocabularies_are_refused():
    _bad("escalation", "escalation:terminal:made-up", tool_name="terminal", arg_shape="made-up")
    _bad("fileaccess", "fileaccess:read_file:my-diary", tool_name="read_file", file_category="my-diary")
    _bad("ioc", "ioc:planet:mars", ioc_type="planet")
    _bad("dependency", "dep:go:x@1", ecosystem="go", package_name="x", package_version="1", kind="malware")


def test_the_identifier_must_match_its_fields():
    _bad("escalation", "escalation:terminal:chmod-world-writable", tool_name="terminal", arg_shape="rm-rf-system-paths")
    _bad("dependency", "dep:npm:other@1", ecosystem="npm", package_name="x", package_version="1", kind="malware")
    _bad("injection", "injection:not-a-hash", context="in-user-prompt")


def test_ioc_identifiers_must_be_canonical_so_lookalikes_cannot_split():
    _bad("ioc", "ioc:domain:EVIL.example", ioc_type="domain")                  # not canonical (case)
    canonical = threat_ids.ioc_identifier("domain", "bücher.example")          # IDN -> punycode
    _ok("ioc", canonical, ioc_type="domain")
    _bad("ioc", "ioc:domain:bücher.example", ioc_type="domain")


def test_control_characters_and_oversized_values_are_refused():
    _bad("fileaccess", "fileaccess:read\x1b_file:ssh-private-key", tool_name="read\x1b_file", file_category="ssh-private-key")
    _bad("dependency", "dep:npm:x@1", ecosystem="npm", package_name="x" * 500, package_version="1", kind="malware")
    _bad("ioc", "ioc:domain:" + "a" * 600 + ".example", ioc_type="domain")


def test_severity_and_framework_are_closed():
    with pytest.raises(ReportValidationError):
        validate_report(identifier="ioc:domain:x.example", category="ioc", severity="apocalyptic",
                        framework="hermes", evidence={"ioc_type": "domain"})
    with pytest.raises(ReportValidationError):
        validate_report(identifier="ioc:domain:x.example", category="ioc", severity="high",
                        framework="some-bot", evidence={"ioc_type": "domain"})


def test_a_report_dated_in_the_future_is_refused():
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    with pytest.raises(ReportValidationError):
        report_builder.build_report_quads(identifier="ioc:domain:x.example", category="ioc", severity="high",
                                          reporter_address="0xabc", ioc_type="domain", ts=future)


def test_the_builder_emits_only_validated_fields():
    quads = report_builder.build_report_quads(identifier="dep:pypi:evil-pkg@1.0", category="dependency",
                                              severity="critical", reporter_address="0xabc", ecosystem="PyPI",
                                              package_name="Evil_Pkg", package_version="1.0", kind="malware")
    names = {q["object"] for q in quads if q["predicate"] == constants.PACKAGE_NAME_PRED}
    assert names == {'"evil-pkg"'}                                              # canonical, as in the identifier
