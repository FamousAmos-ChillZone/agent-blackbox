"""Disputes (``g:FalsePositive``) — the reader the plugin never had (Refine R2, KI-092).

Since R1 a reporter can dispute a community threat with a closed reason
(``blackbox report --false-positive ID --reason R``), but nothing read the
statement back: a safeguard without a caller (LES-004). This module reads and
VERIFIES disputes: signed ``blackbox.dispute`` for this network and graph, the
subject is the signer's own ``…:fp`` subject, the reason is in the closed set,
and every shown field matches what was signed.

A dispute NEVER changes enforcement by itself (plan §03): it tags a threat
DISPUTED and, in R3, counts toward decay only when its author is counted.

Usage (from the reader)::

    rows = page_community_rows(client, cfg, disputes.disputes_sparql)
    found = disputes.verified_disputes(rows, environment, graph)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional

from ...kernel import constants, signing, sparql_text, threat_ids
from ...kernel.dkg_client import extract_binding
from ..report_signer import DISPUTE_STATEMENT
from ..verification import SIGNED_STATEMENT_VAR

from ..verification import unique_by_subject

logger = logging.getLogger(__name__)

_PAGE_SIZE = 5000


@dataclass(frozen=True)
class VerifiedDispute:
    """One verified dispute: ``subject`` (the dispute's own), ``identifier``
    (the disputed threat), ``author`` (the signer key — the identity),
    ``reporter`` (the claimed address, display only), ``reason`` (closed),
    ``day`` (the signed UTC day, display only)."""

    subject: str
    identifier: str
    author: str
    reporter: str
    reason: str
    day: str


def disputes_sparql(after: str) -> str:
    """One page of FalsePositive rows after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?identifier ?reporter ?reportReason ?signedStatement WHERE {{
  ?r a g:FalsePositive ;
     g:identifier ?identifier ;
     g:reporter ?reporter .
  OPTIONAL {{ ?r g:reportReason ?reportReason }}
  OPTIONAL {{ ?r g:signedStatement ?signedStatement }}
  {cursor}
}} ORDER BY STR(?r) LIMIT {_PAGE_SIZE}
"""


def _verified(row: Mapping[str, Any], environment: str, graph: str) -> Optional[VerifiedDispute]:
    envelope = signing.from_text(extract_binding(row.get(SIGNED_STATEMENT_VAR)))
    author = signing.verify(envelope, statement_type=DISPUTE_STATEMENT, environment=environment, graph=graph)
    if author is None or envelope is None:
        return None
    payload = envelope.payload
    identifier, reporter, reason = payload.get("identifier", ""), payload.get("reporter", ""), payload.get("reason", "")
    if not identifier or not threat_ids.is_agent_address(reporter) or reason not in constants.FALSE_POSITIVE_REASONS:
        return None
    subject = threat_ids.report_uri(identifier, reporter) + ":fp"
    shown = (
        extract_binding(row.get("r")),
        extract_binding(row.get("identifier")).strip(),
        extract_binding(row.get("reporter")).strip().lower(),
        extract_binding(row.get("reportReason")).strip() or reason,   # a row may omit it; the signed one counts
    )
    if payload.get("subject") != subject or shown != (subject, identifier, reporter, reason):
        return None
    return VerifiedDispute(subject=subject, identifier=identifier, author=author, reporter=reporter,
                           reason=reason, day=payload.get("day", ""))


def verified_disputes(rows: Iterable[Mapping[str, Any]], environment: str, graph: str) -> List[VerifiedDispute]:
    """Every dispute row that verifies; the rest are dropped and counted in the log."""
    found: List[VerifiedDispute] = []
    dropped = 0
    for row in rows:
        dispute = _verified(row, environment, graph)
        if dispute is None:
            dropped += 1
        else:
            found.append(dispute)
    if dropped:
        logger.info("blackbox: community read ignored %d unsigned or unverifiable dispute row(s)", dropped)
    return unique_by_subject(found)
