"""Validated community report records — an unvalidated report cannot be built (Refine R1).

Every report and dispute leaves the machine through the report builder, and
the builder builds only from a :class:`ReportRecord` produced here. Validation
is closed-world: each field is checked against a vocabulary that ALREADY exists
in the code (detection's shapes and categories, the IOC types, the OWASP LLM
list, the injection contexts), the identifier must equal the one the fields
derive, and free text is refused. Rejects never leave the machine.

What a report may carry, per category (the evidence keys are the builder's
keyword names):

* ``injection`` — ``context`` (required, decision 24) + optional
  ``owasp_category``. Never the pattern text: the identifier is already its
  hash (KI-115/161).
* ``escalation`` — ``tool_name`` (a shell tool) + ``arg_shape`` (a known shape).
* ``dependency`` — ``ecosystem``, canonical ``package_name``,
  ``package_version``, ``kind`` = ``malware`` (a vulnerability report cannot
  be built — decision 22), ``reason`` (``DEPENDENCY_REASONS`` or
  ``advisory:<id>``; a whole-package ``*`` version only with a
  ``WHOLE_PACKAGE_REASONS`` reason), optional ``advisory_id``.
* ``fileaccess`` — ``tool_name`` + ``file_category`` (a known category).
* ``skill`` — either a known-bad named version from a public registry
  (``registry`` + ``skill_name`` + ``skill_version``), or a local/unknown
  skill as ``artifact_hash`` (sha256 of its code) + ``danger_shape`` — never
  its name or version (KI-159).
* ``ioc`` — ``ioc_type`` (a known type) + ``ioc_context`` (where it was met);
  the canonical value is the identifier.

The vocabularies are plan §04's, kept in ``kernel.constants``.

Pattern: Factory (:func:`validate_report`) + a Strategy table of per-category
validators; the record is an immutable Value Object.

Usage::

    record = report_schema.validate_report(identifier=..., category="ioc",
        severity="high", framework="hermes", evidence={"ioc_type": "domain"})
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Mapping, Optional, Tuple

from .. import detection
from ..kernel import constants, threat_ids

#: Longest identifier / evidence value a report may carry.
MAX_IDENTIFIER_CHARS = 512
MAX_VALUE_CHARS = 128
#: A report dated further ahead than this is refused (sender clocks drift a little).
MAX_CLOCK_SKEW = timedelta(minutes=10)

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._@:/+~-]+")       # package names/versions, tool names, advisory ids
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
#: A heuristic's id is its pattern hash; a verified-corpus id is the threat's
#: slug (``injection:seed-000``) — either way a lowercase slug, never free text.
_INJECTION_ID = re.compile(r"injection:[a-z0-9][a-z0-9._-]{0,63}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ReportValidationError(ValueError):
    """A report that must not be built or shared; the message says why."""


@dataclass(frozen=True)
class ReportRecord:
    """One validated report: what the builder emits and the signer signs.

    ``evidence`` holds (builder keyword, value) pairs, sorted — only keys the
    category allows, every value checked.
    """

    identifier: str
    category: str
    severity: str
    framework: str
    evidence: Tuple[Tuple[str, str], ...]


def _fail(message: str) -> None:
    raise ReportValidationError(message)


def _token(name: str, value: Optional[str], *, required: bool = True) -> str:
    """A short safe token (no spaces, no control characters)."""
    text = str(value or "").strip()
    if not text:
        if required:
            _fail(f"{name} is required")
        return ""
    if len(text) > MAX_VALUE_CHARS or not _SAFE_TOKEN.fullmatch(text):
        _fail(f"{name} must be a short token without spaces or control characters")
    return text


def _one_of(name: str, value: Optional[str], allowed) -> str:
    text = str(value or "").strip().lower()
    if text not in allowed:
        _fail(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return text


# -- per-category validators (Strategy table): evidence in -> (derived id, evidence out)


def _injection(ev: Mapping[str, str]) -> Tuple[Optional[str], Dict[str, str]]:
    out = {"context": _one_of("context", ev.get("context"), constants.INJECTION_CONTEXTS)}
    if ev.get("owasp_category"):
        out["owasp_category"] = _one_of("owasp_category", ev["owasp_category"],
                                        {c.lower() for c in constants.OWASP_LLM_CATEGORIES}).upper()
    return None, out   # the identifier is the pattern's hash, checked by shape


def _escalation(ev: Mapping[str, str]) -> Tuple[Optional[str], Dict[str, str]]:
    tool = _one_of("tool_name", ev.get("tool_name"), detection.SHELL_TOOLS)
    shape = _one_of("arg_shape", ev.get("arg_shape"), detection.ESCALATION_SHAPES)
    return threat_ids.escalation_identifier(tool, shape), {"tool_name": tool, "arg_shape": shape}


def _dependency(ev: Mapping[str, str]) -> Tuple[Optional[str], Dict[str, str]]:
    eco = _one_of("ecosystem", ev.get("ecosystem"), detection.DEPENDENCY_ECOSYSTEMS)
    raw_name = _token("package_name", ev.get("package_name"))
    name = threat_ids.canonical_package_name(eco, raw_name)
    if str(ev.get("kind") or "").lower() != constants.KIND_MALWARE:
        _fail("a dependency report must be kind=malware (vulnerabilities stay local — decision 22)")
    reason, advisory = _dependency_reason(ev)
    version = str(ev.get("package_version") or "").strip()
    if version == "*":   # a whole-package report: every version is malware
        if reason not in constants.WHOLE_PACKAGE_REASONS:
            _fail(f"a whole-package (*) report needs reason {' or '.join(constants.WHOLE_PACKAGE_REASONS)}")
    else:
        version = _token("package_version", version)
    out = {"ecosystem": eco, "package_name": name, "package_version": version, "kind": constants.KIND_MALWARE,
           "reason": reason}
    if advisory:
        out["advisory_id"] = advisory
    return threat_ids.dependency_identifier(eco, name, version), out


def _dependency_reason(ev: Mapping[str, str]) -> Tuple[str, str]:
    """(reason, advisory id): the closed reason, or ``advisory:<id>`` — whose id
    must equal ``advisory_id`` when both are given."""
    reason = str(ev.get("reason") or "").strip()
    advisory = _token("advisory_id", ev.get("advisory_id"), required=False)
    if reason.lower().startswith(constants.ADVISORY_REASON_PREFIX):
        cited = _token("advisory id in reason", reason[len(constants.ADVISORY_REASON_PREFIX):])
        if advisory and advisory != cited:
            _fail("the reason's advisory and advisory_id differ")
        return constants.ADVISORY_REASON_PREFIX + cited, cited
    allowed = (*constants.DEPENDENCY_REASONS, constants.ADVISORY_REASON_PREFIX + "<id>")
    return _one_of("reason", reason, allowed), advisory


def _fileaccess(ev: Mapping[str, str]) -> Tuple[Optional[str], Dict[str, str]]:
    tool = _token("tool_name", ev.get("tool_name")).lower()
    category = _one_of("file_category", ev.get("file_category"), detection.SENSITIVE_PATH_CATEGORIES)
    return threat_ids.fileaccess_identifier(tool, category), {"tool_name": tool, "file_category": category}


def _skill(ev: Mapping[str, str]) -> Tuple[Optional[str], Dict[str, str]]:
    if ev.get("artifact_hash") or ev.get("danger_shape"):
        if ev.get("skill_name") or ev.get("skill_version") or ev.get("registry"):
            _fail("a local skill is reported by artifact hash + danger shape, never by name or version (KI-159)")
        digest = str(ev.get("artifact_hash") or "").strip().lower()
        if not _SHA256_HEX.fullmatch(digest):
            _fail("artifact_hash must be the sha256 hex of the skill's code")
        shape = _one_of("danger_shape", ev.get("danger_shape"), detection.SKILL_DANGER_SHAPES)
        return threat_ids.skill_artifact_identifier(digest, shape), {"artifact_hash": digest, "danger_shape": shape}
    registry = _one_of("registry", ev.get("registry"), constants.SKILL_REGISTRIES)   # never local (KI-159)
    name = _token("skill_name", ev.get("skill_name"))
    version = _token("skill_version", ev.get("skill_version"))
    return (threat_ids.skill_version_identifier(name, version),
            {"registry": registry, "skill_name": name, "skill_version": version})


def _ioc(ev: Mapping[str, str]) -> Tuple[Optional[str], Dict[str, str]]:
    return None, {"ioc_type": _one_of("ioc_type", ev.get("ioc_type"), threat_ids.IOC_TYPES),
                  "ioc_context": _one_of("ioc_context", ev.get("ioc_context"), constants.IOC_CONTEXTS)}


_VALIDATORS: Dict[str, Callable[[Mapping[str, str]], Tuple[Optional[str], Dict[str, str]]]] = {
    "injection": _injection,
    "escalation": _escalation,
    "dependency": _dependency,
    "fileaccess": _fileaccess,
    "skill": _skill,
    "ioc": _ioc,
}


def _check_identifier(category: str, identifier: str, derived: Optional[str], evidence: Mapping[str, str]) -> None:
    if not identifier or len(identifier) > MAX_IDENTIFIER_CHARS or _CONTROL.search(identifier) or " " in identifier:
        _fail("identifier must be a short single token without control characters")
    if derived is not None and identifier != derived:
        _fail(f"identifier does not match its fields (expected {derived})")
    if category == "injection" and not _INJECTION_ID.fullmatch(identifier):
        _fail("an injection identifier is a slug (injection:<pattern hash or corpus id>), never free text")
    if category == "ioc":
        prefix = f"ioc:{evidence['ioc_type']}:"
        value = identifier[len(prefix):] if identifier.startswith(prefix) else ""
        if not value or threat_ids.ioc_identifier(evidence["ioc_type"], value) != identifier:
            _fail("an ioc identifier must be the canonical ioc:<type>:<value>")


def validate_report(*, identifier: str, category: str, severity: str, framework: str,
                    evidence: Mapping[str, Optional[str]], ts: Optional[datetime] = None) -> ReportRecord:
    """The validated record for one report, or :class:`ReportValidationError`."""
    validator = _VALIDATORS.get(category)
    if validator is None:
        _fail(f"category must be one of: {', '.join(sorted(_VALIDATORS))}")
    if str(severity or "").strip().lower() not in constants.SEVERITY_ORDER:
        _fail(f"severity must be one of: {', '.join(constants.SEVERITY_ORDER)}")
    framework_name = _one_of("framework", framework, constants.REPORT_FRAMEWORKS)
    if ts is not None and _aware(ts) > datetime.now(timezone.utc) + MAX_CLOCK_SKEW:
        _fail("a report cannot be dated in the future")
    given = {k: v for k, v in evidence.items() if v not in (None, "")}
    derived, out = validator(given)
    unknown = set(given) - set(out)
    if unknown:
        _fail(f"fields not allowed in a {category} report: {', '.join(sorted(unknown))}")
    _check_identifier(category, str(identifier or "").strip(), derived, out)
    return ReportRecord(identifier=identifier.strip(), category=category,
                        severity=constants.normalize_severity(severity), framework=framework_name,
                        evidence=tuple(sorted(out.items())))


def validate_dispute(*, identifier: str, reason: str) -> Tuple[str, str]:
    """(identifier, reason) for a false-positive dispute, or
    :class:`ReportValidationError`. The reason is REQUIRED and closed
    (``constants.FALSE_POSITIVE_REASONS``, plan §04); the disputed identifier is
    a single short token, never free text."""
    return validate_statement_identifier(identifier), _one_of("reason", reason, constants.FALSE_POSITIVE_REASONS)


def validate_statement_identifier(identifier: str) -> str:
    """The threat identifier a dispute or retraction names, stripped — a single
    short token, never free text — or :class:`ReportValidationError`."""
    identifier = str(identifier or "").strip()
    if not identifier or len(identifier) > MAX_IDENTIFIER_CHARS or _CONTROL.search(identifier) or " " in identifier:
        _fail("the identifier must be a short single token without control characters")
    return identifier


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
