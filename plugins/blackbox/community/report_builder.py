"""Report quads: a finding -> the privacy-safe statements shared to the community graph.

One subject per (reporter, threat) — ``urn:guardian:report:{reporter}:{hash}``
— which makes distinct-reporter counting honest by construction. Never carries
prompt or command text; literals are capped by :mod:`..kernel.rdf_terms`.

Usage: ``community.build_report_quads(identifier, severity=..., reporter_address=...)``
· ``community.build_false_positive_quads(identifier, reporter_address=...)``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Mapping, Optional, Tuple
from ..kernel import constants
from ..kernel import rdf_terms
from ..kernel import threat_ids

# ---------------------------------------------------------------------------
# Threat / report quad builders
# ---------------------------------------------------------------------------

#: The evidence a report may carry, per category: (keyword argument, predicate),
#: in emission order. ONE table, so the builder and anything that reads or signs
#: a report's fields agree on what a report holds.
_EVIDENCE_FIELDS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "injection": (("pattern", constants.PATTERN_PRED), ("owasp_category", constants.OWASP_CATEGORY_PRED)),
    "escalation": (("tool_name", constants.TOOL_NAME_PRED), ("arg_shape", constants.ARG_SHAPE_PRED)),
    "dependency": (
        ("package_name", constants.PACKAGE_NAME_PRED),
        ("package_version", constants.PACKAGE_VERSION_PRED),
        ("ecosystem", constants.PACKAGE_ECOSYSTEM_PRED),
        ("advisory_id", constants.SCHEMA_IDENTIFIER_PRED),
        # Keep the dependency kind intact in the community report.
        ("kind", constants.KIND_PRED),
    ),
    "fileaccess": (("tool_name", constants.TOOL_NAME_PRED), ("file_category", constants.CATEGORY_PRED)),
    "skill": (
        ("skill_name", constants.SKILL_NAME_PRED),
        ("skill_version", constants.SKILL_VERSION_PRED),
        ("danger_shape", constants.DANGER_SHAPE_PRED),
    ),
    # KI-024: without this entry an IOC report carried only the common core and
    # curators' evidence queries bound nothing for it. The value itself already
    # lives IN the identifier (ioc:{type}:{value}); the type travels as its own
    # field so reviewers can filter without parsing.
    "ioc": (("ioc_type", constants.IOC_TYPE_PRED),),
}


def _evidence(category: str, values: Mapping[str, Optional[str]]) -> List[Tuple[str, str]]:
    """(predicate, value) for each evidence field of *category* that is set.

    An injection report without a pattern carries no evidence at all (the
    OWASP category only means something next to the pattern it classifies).
    """
    if category == "injection" and not values.get("pattern"):
        return []
    return [(predicate, str(values[name])) for name, predicate in _EVIDENCE_FIELDS.get(category, ()) if values.get(name)]


def build_report_quads(
    *,
    identifier: str,
    category: str,
    severity: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    **evidence: Optional[str],
) -> List[rdf_terms.Quad]:
    """Build a sighting/report for SWM.

    The subject is per-submitter namespaced (:func:`report_uri`). A report
    NEVER carries observed prompt/command text (privacy split — that stays in
    the private WM audit). For a NEW candidate threat, the caller may pass the
    threat fields needed for independent review — the keyword arguments named
    in ``_EVIDENCE_FIELDS`` (``pattern``, ``owasp_category``, ``tool_name``,
    ``arg_shape``, ``ecosystem``, ``package_name``, ``package_version``,
    ``advisory_id``, ``file_category``, ``skill_name``, ``skill_version``,
    ``danger_shape``, ``kind``, ``ioc_type``); fields that do not belong to
    *category* are ignored. Any other keyword is a ``TypeError``.
    """
    unknown = set(evidence) - _EVIDENCE_NAMES
    if unknown:
        raise TypeError(f"build_report_quads() got unexpected keyword argument(s): {sorted(unknown)}")
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
    out.extend(rdf_terms.make_quad(subj, predicate, rdf_terms.literal(value)) for predicate, value in _evidence(category, evidence))
    return out


_EVIDENCE_NAMES = frozenset(name for fields in _EVIDENCE_FIELDS.values() for name, _ in fields)


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
