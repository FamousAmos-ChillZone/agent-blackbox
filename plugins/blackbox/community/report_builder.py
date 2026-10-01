"""Report quads: a finding -> the privacy-safe statements shared to the community graph.

One subject per (reporter, threat) — ``urn:guardian:report:{reporter}:{hash}``
— which makes distinct-reporter counting honest by construction. Never carries
prompt or command text; literals are capped by :mod:`..kernel.rdf_terms`.

Usage: ``community.build_report_quads(identifier, severity=..., reporter_address=...)``
· ``community.build_false_positive_quads(identifier, reporter_address=...)``.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from ..kernel import constants
from ..kernel import rdf_terms
from ..kernel import threat_ids

# ---------------------------------------------------------------------------
# Threat / report quad builders
# ---------------------------------------------------------------------------


def build_report_quads(
    *,
    identifier: str,
    category: str,
    severity: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    # optional full threat fields for NEW candidate threats
    pattern: Optional[str] = None,
    owasp_category: Optional[str] = None,
    tool_name: Optional[str] = None,
    arg_shape: Optional[str] = None,
    ecosystem: Optional[str] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    advisory_id: Optional[str] = None,
    file_category: Optional[str] = None,
    skill_name: Optional[str] = None,
    skill_version: Optional[str] = None,
    danger_shape: Optional[str] = None,
    kind: Optional[str] = None,
    ioc_type: Optional[str] = None,
) -> List[rdf_terms.Quad]:
    """Build a sighting/report for SWM.

    The subject is per-submitter namespaced (:func:`report_uri`). A report
    NEVER carries observed prompt/command text (privacy split — that stays in
    the private WM audit). For a NEW candidate threat, the caller may pass the
    threat fields needed for independent review.
    """
    subj = threat_ids.report_uri(identifier, reporter_address)
    threat = threat_ids.threat_uri(identifier)
    out: List[rdf_terms.Quad] = [
        rdf_terms.make_quad(subj, constants.RDF_TYPE, rdf_terms.iri(constants.REPORT_TYPE_IRI)),
        rdf_terms.make_quad(subj, constants.REPORTS_THREAT_PRED, rdf_terms.iri(threat)),
        rdf_terms.make_quad(subj, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subj, constants.REPORTER_PRED, rdf_terms.literal((reporter_address or "anonymous").lower())),
        rdf_terms.make_quad(subj, constants.FRAMEWORK_PRED, rdf_terms.literal(framework)),
        rdf_terms.make_quad(subj, constants.SEVERITY_PRED, rdf_terms.literal(constants.normalize_severity(severity))),
        rdf_terms.make_quad(subj, constants.SCHEMA_DATE_MODIFIED_PRED, rdf_terms.datetime_literal(ts)),
    ]
    if category == "injection" and pattern:
        out.append(rdf_terms.make_quad(subj, constants.PATTERN_PRED, rdf_terms.literal(pattern)))
        if owasp_category:
            out.append(rdf_terms.make_quad(subj, constants.OWASP_CATEGORY_PRED, rdf_terms.literal(owasp_category)))
    elif category == "escalation":
        if tool_name:
            out.append(rdf_terms.make_quad(subj, constants.TOOL_NAME_PRED, rdf_terms.literal(tool_name)))
        if arg_shape:
            out.append(rdf_terms.make_quad(subj, constants.ARG_SHAPE_PRED, rdf_terms.literal(arg_shape)))
    elif category == "dependency":
        if package_name:
            out.append(rdf_terms.make_quad(subj, constants.PACKAGE_NAME_PRED, rdf_terms.literal(package_name)))
        if package_version:
            out.append(rdf_terms.make_quad(subj, constants.PACKAGE_VERSION_PRED, rdf_terms.literal(package_version)))
        if ecosystem:
            out.append(rdf_terms.make_quad(subj, constants.PACKAGE_ECOSYSTEM_PRED, rdf_terms.literal(ecosystem)))
        if advisory_id:
            out.append(rdf_terms.make_quad(subj, constants.SCHEMA_IDENTIFIER_PRED, rdf_terms.literal(advisory_id)))
        # Keep the dependency kind intact in the community report.
        if kind:
            out.append(rdf_terms.make_quad(subj, constants.KIND_PRED, rdf_terms.literal(kind)))
    elif category == "fileaccess":
        if tool_name:
            out.append(rdf_terms.make_quad(subj, constants.TOOL_NAME_PRED, rdf_terms.literal(tool_name)))
        if file_category:
            out.append(rdf_terms.make_quad(subj, constants.CATEGORY_PRED, rdf_terms.literal(file_category)))
    elif category == "skill":
        if skill_name:
            out.append(rdf_terms.make_quad(subj, constants.SKILL_NAME_PRED, rdf_terms.literal(skill_name)))
        if skill_version:
            out.append(rdf_terms.make_quad(subj, constants.SKILL_VERSION_PRED, rdf_terms.literal(skill_version)))
        if danger_shape:
            out.append(rdf_terms.make_quad(subj, constants.DANGER_SHAPE_PRED, rdf_terms.literal(danger_shape)))
    elif category == "ioc":
        # KI-024: without this branch an IOC report carried only the common
        # core and curators' evidence queries bound nothing for it. The value
        # itself already lives IN the identifier (ioc:{type}:{value}); the type
        # travels as its own field so reviewers can filter without parsing.
        if ioc_type:
            out.append(rdf_terms.make_quad(subj, constants.IOC_TYPE_PRED, rdf_terms.literal(ioc_type)))
    return out


def build_false_positive_quads(
    *,
    identifier: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
) -> List[rdf_terms.Quad]:
    """A dispute signal: "this community threat is wrong" (KI-011, Q8's writer).

    Same per-(reporter, threat) subject discipline as reports — one dispute
    voice per reporter per threat, first write wins — under a ``:fp`` suffix
    so a reporter can hold both a report and a dispute without collision.
    Carries only the identifier, reporter, framework and timestamp: a veto
    needs no evidence payload (curators re-check the original reports).
    """
    subj = threat_ids.report_uri(identifier, reporter_address) + ":fp"
    return [
        rdf_terms.make_quad(subj, constants.RDF_TYPE, rdf_terms.iri(constants.FALSE_POSITIVE_TYPE_IRI)),
        rdf_terms.make_quad(subj, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subj, constants.REPORTER_PRED, rdf_terms.literal((reporter_address or "").lower())),
        rdf_terms.make_quad(subj, constants.FRAMEWORK_PRED, rdf_terms.literal(framework)),
        rdf_terms.make_quad(subj, constants.SCHEMA_DATE_MODIFIED_PRED, rdf_terms.datetime_literal(ts)),
    ]
