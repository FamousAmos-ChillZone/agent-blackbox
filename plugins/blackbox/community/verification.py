"""Verifying community reports — the only door from a raw row to a counted report (R0c).

A community row is untrusted: any node can write any ``g:reporter`` string, and
the DKG's own authorship signals are unchecked on some delivery routes
(KI-067/102/110). So a row is believed only when the signed envelope it carries
(:mod:`..kernel.signing`, written by R0b) verifies AND agrees with what the row
shows:

1. the envelope is a ``blackbox.report`` signed for THIS node's network and
   THIS community graph (no replay from a test network or another graph);
2. the row's subject, identifier, reporter and severity equal the signed ones;
3. the subject is the signed reporter's own (``report_uri(identifier, reporter)``);
4. every evidence field the row shows equals the signed value.

Anything else is dropped. A verified report's AUTHOR is the signer's public key
— counting, dedupe and caps key on it, never on the self-described reporter
string, which stays display-only (LES-014). The signer is checked before any
dedupe (KI-144).

Usage::

    verifier = ReportVerifier(environment=network_id, graph=cfg.community_graph_id)
    reports, dropped = verify_report_rows(raw_rows, verifier)
    rules = aggregate_community_reports(reports, prior_first_seen)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Tuple

from ..kernel import constants, signing, threat_ids
from ..kernel.dkg_client import extract_binding
from .report_signer import REPORT_STATEMENT

logger = logging.getLogger(__name__)

#: Reader query variable -> the key the signed payload uses for the same field
#: (the builder's keyword names, community.report_builder._EVIDENCE_FIELDS).
EVIDENCE_PAYLOAD_KEYS: Mapping[str, str] = {
    "kind": "kind",
    "iocType": "ioc_type",
    "toolName": "tool_name",
    "argShape": "arg_shape",
    "packageName": "package_name",
    "packageVersion": "package_version",
    "packageEcosystem": "ecosystem",
    "category": "file_category",
    "skillName": "skill_name",
    "dangerShape": "danger_shape",
    "pattern": "pattern",
    "injectionContext": "context",          # Refine R1
    "skillArtifactHash": "artifact_hash",   # Refine R1 (KI-159)
    "skillRegistry": "registry",            # Refine R1 (§04)
    "iocContext": "ioc_context",            # Refine R1 (§04)
    "reportReason": "reason",               # Refine R1 (§04)
}

#: The reader query variable that carries the envelope.
SIGNED_STATEMENT_VAR = "signedStatement"


@dataclass(frozen=True)
class VerifiedReport:
    """One community report whose signature checked out.

    ``author`` — the signer's Ed25519 public key (hex): THE identity for
    counting. ``reporter`` — the self-described agent address (display only).
    ``fields`` — evidence as (reader variable, signed value) pairs, sorted.
    """

    subject: str
    identifier: str
    author: str
    reporter: str
    severity: str
    fields: Tuple[Tuple[str, str], ...] = ()
    framework: str = ""      # the signed framework label (display only)


class ReportVerifier:
    """Checks rows for one network (``environment``) and one community graph.

    Stateless after construction; safe to share across threads.
    """

    def __init__(self, environment: str, graph: str) -> None:
        self._environment = environment
        self._graph = graph

    def verify(self, row: Mapping[str, Any]) -> Optional[VerifiedReport]:
        """The verified report for *row*, or None when it must be dropped."""
        envelope = signing.from_text(extract_binding(row.get(SIGNED_STATEMENT_VAR)))
        author = signing.verify(envelope, statement_type=REPORT_STATEMENT,
                                environment=self._environment, graph=self._graph)
        if author is None or envelope is None:
            return None
        payload = envelope.payload
        identifier = payload.get("identifier", "")
        reporter = payload.get("reporter", "")
        severity = payload.get("severity", "")
        if not identifier or not threat_ids.is_agent_address(reporter):
            return None                                             # KI-196: free text is not a reporter
        if payload.get("subject") != threat_ids.report_uri(identifier, reporter):
            return None
        shown = (
            extract_binding(row.get("r")),
            extract_binding(row.get("identifier")).strip(),
            extract_binding(row.get("reporter")).strip().lower(),
            constants.normalize_severity(extract_binding(row.get("severity"))),
        )
        if shown != (payload["subject"], identifier, reporter, severity):
            return None
        fields = _agreed_evidence(row, payload)
        if fields is None:
            return None
        return VerifiedReport(subject=payload["subject"], identifier=identifier, author=author,
                              reporter=reporter, severity=severity, fields=fields,
                              framework=payload.get("framework", ""))


def _agreed_evidence(row: Mapping[str, Any], payload: Mapping[str, str]) -> Optional[Tuple[Tuple[str, str], ...]]:
    """Evidence taken from the SIGNED payload; None when the row shows a
    value the signature does not (a tampered or forged row). A field the row
    omits is fine — the signed value is used."""
    fields: List[Tuple[str, str]] = []
    for var, key in EVIDENCE_PAYLOAD_KEYS.items():
        signed = payload.get(key, "")
        shown = extract_binding(row.get(var))
        if shown and shown != signed:
            return None
        if signed:
            fields.append((var, signed))
    return tuple(sorted(fields))


def verify_report_rows(rows: Iterable[Mapping[str, Any]], verifier: ReportVerifier) -> Tuple[List[VerifiedReport], int]:
    """(verified reports, number of rows dropped). Logs the drop count —
    a sudden jump is the visible sign of forged or unsigned traffic."""
    reports: List[VerifiedReport] = []
    dropped = 0
    for row in rows:
        report = verifier.verify(row)
        if report is None:
            dropped += 1
        else:
            reports.append(report)
    if dropped:
        logger.info("blackbox: community read dropped %d unsigned or unverifiable report row(s)", dropped)
    return reports, dropped

