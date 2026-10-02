"""Report quads: a finding -> the privacy-safe statements shared to the community graph.

One subject per (reporter, threat) — ``urn:guardian:report:{reporter}:{hash}``
— which makes distinct-reporter counting honest by construction. Never carries
prompt or command text; literals are capped by :mod:`..kernel.rdf_terms`.

Usage: ``community.build_report_quads(identifier, severity=..., reporter_address=...)``
· ``community.build_false_positive_quads(identifier, reporter_address=...)``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Mapping, Optional, Tuple
from ..kernel import constants
from ..kernel import rdf_terms
from ..kernel import threat_ids
from .report_signer import DISPUTE_STATEMENT, REPORT_STATEMENT, ReportSigner

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


def _day(ts: Optional[datetime]) -> datetime:
    """*ts* (default: now) rounded down to midnight UTC — decision 25: a report
    says WHICH DAY, never the minute, so the timestamp is no activity clock."""
    when = ts or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _evidence(category: str, values: Mapping[str, Optional[str]]) -> List[Tuple[str, str, str]]:
    """(name, predicate, value) for each evidence field of *category* that is set.

    An injection report without a pattern carries no evidence at all (the
    OWASP category only means something next to the pattern it classifies).
    Raises ``TypeError`` for a name that is no evidence field at all.
    """
    unknown = set(values) - _EVIDENCE_NAMES
    if unknown:
        raise TypeError(f"build_report_quads() got unexpected keyword argument(s): {sorted(unknown)}")
    if category == "injection" and not values.get("pattern"):
        return []
    return [(name, predicate, str(values[name])) for name, predicate in _EVIDENCE_FIELDS.get(category, ()) if values.get(name)]


def _signature_quad(subject: str, signer: ReportSigner, statement_type: str, payload: Dict[str, str]) -> rdf_terms.Quad:
    """The quad carrying *subject*'s signed envelope."""
    return rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED,
                               rdf_terms.literal(signer.sign(statement_type, payload)))


def build_report_quads(
    *,
    identifier: str,
    category: str,
    severity: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    signer: Optional[ReportSigner] = None,
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

    The timestamp is rounded to the day (decision 25). With a *signer*, the
    report also carries a signed envelope (``SIGNED_STATEMENT_PRED``) over its
    subject, identifier, category, severity, reporter, framework, day and
    evidence — the statement a reader verifies before counting it (R0b).
    """
    subj = threat_ids.report_uri(identifier, reporter_address)
    threat = threat_ids.threat_uri(identifier)
    day = _day(ts)
    reporter = reporter_address.strip().lower()   # report_uri above refused a blank one
    severity = constants.normalize_severity(severity)
    fields = _evidence(category, evidence)
    out: List[rdf_terms.Quad] = [
        rdf_terms.make_quad(subj, constants.RDF_TYPE, rdf_terms.iri(constants.REPORT_TYPE_IRI)),
        rdf_terms.make_quad(subj, constants.REPORTS_THREAT_PRED, rdf_terms.iri(threat)),
        rdf_terms.make_quad(subj, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subj, constants.REPORTER_PRED, rdf_terms.literal(reporter)),
        rdf_terms.make_quad(subj, constants.FRAMEWORK_PRED, rdf_terms.literal(framework)),
        rdf_terms.make_quad(subj, constants.SEVERITY_PRED, rdf_terms.literal(severity)),
        rdf_terms.make_quad(subj, constants.SCHEMA_DATE_MODIFIED_PRED, rdf_terms.datetime_literal(day)),
    ]
    out.extend(rdf_terms.make_quad(subj, predicate, rdf_terms.literal(value)) for _, predicate, value in fields)
    if signer is not None:
        payload = {"subject": subj, "identifier": identifier, "category": category, "severity": severity,
                   "reporter": reporter, "framework": framework, "day": day.date().isoformat()}
        payload.update({name: value for name, _, value in fields})
        out.append(_signature_quad(subj, signer, REPORT_STATEMENT, payload))
    return out


_EVIDENCE_NAMES = frozenset(name for fields in _EVIDENCE_FIELDS.values() for name, _ in fields)


def build_false_positive_quads(
    *,
    identifier: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    signer: Optional[ReportSigner] = None,
) -> List[rdf_terms.Quad]:
    """A dispute signal: "this community threat is wrong" (KI-011, Q8's writer).

    Same per-(reporter, threat) subject discipline as reports — one dispute
    voice per reporter per threat, first write wins — under a ``:fp`` suffix
    so a reporter can hold both a report and a dispute without collision.
    Carries only the identifier, reporter, framework and timestamp: a veto
    needs no evidence payload (curators re-check the original reports).
    Day-rounded and, with a *signer*, signed like a report (``blackbox.dispute``).
    """
    subj = threat_ids.report_uri(identifier, reporter_address) + ":fp"
    day = _day(ts)
    reporter = reporter_address.strip().lower()   # report_uri above refused a blank one
    out = [
        rdf_terms.make_quad(subj, constants.RDF_TYPE, rdf_terms.iri(constants.FALSE_POSITIVE_TYPE_IRI)),
        rdf_terms.make_quad(subj, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subj, constants.REPORTER_PRED, rdf_terms.literal(reporter)),
        rdf_terms.make_quad(subj, constants.FRAMEWORK_PRED, rdf_terms.literal(framework)),
        rdf_terms.make_quad(subj, constants.SCHEMA_DATE_MODIFIED_PRED, rdf_terms.datetime_literal(day)),
    ]
    if signer is not None:
        payload = {"subject": subj, "identifier": identifier, "reporter": reporter,
                   "framework": framework, "day": day.date().isoformat()}
        out.append(_signature_quad(subj, signer, DISPUTE_STATEMENT, payload))
    return out
