"""Retractions — a reporter withdrawing its own report (Refine R1, lifecycle RETRACT).

A retraction is a ``g:Retraction`` statement signed ``blackbox.retract`` by
the SAME reporter key that signed the report (``blackbox report --retract``).
Readers honour it unconditionally, with no hold, cap or delay: a statement
that REDUCES enforcement must always get through (LES-016). Its reach is
exactly its signer's own voice. A verified retraction removes every report
that signer made about that identifier, and nobody else's, so a retraction
can never silence other reporters (LES-014: identity is the signature, never
a payload field). Unsigned or unverifiable retraction rows are ignored.

A retraction is final for that (reporter, threat) pair: the report's asset
name is fixed, so the same report cannot be re-sent afterwards.

Usage (from the reader)::

    rows = page_community_rows(client, cfg, retractions.retractions_sparql)
    found = retractions.verified_retractions(rows, environment, graph)       # List[VerifiedRetraction]
    withdrawn, _ = tombstones.applicable_withdrawals(found, reports, first_seen, now)
    reports = retractions.apply_retractions(reports, withdrawn)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from ...kernel import signing, sparql_text, threat_ids
from ...kernel.dkg_client import extract_binding
from ..report_signer import RETRACT_STATEMENT
from ..verification import SIGNED_STATEMENT_VAR, VerifiedReport

logger = logging.getLogger(__name__)

#: One withdrawn voice: (signer key, threat identifier).
Withdrawal = Tuple[str, str]


@dataclass(frozen=True)
class VerifiedRetraction:
    """One verified retraction: its ``author`` (signer key), the
    ``identifier`` it withdraws, its own ``subject``, and for display the
    claimed ``reporter`` address and signed ``day``."""

    author: str
    identifier: str
    subject: str
    reporter: str = ""
    day: str = ""

#: Rows per page (retractions are rare; the pager's row ceiling still applies).
_PAGE_SIZE = 5000


def retractions_sparql(after: str) -> str:
    """One page of Retraction rows after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?identifier ?reporter ?signedStatement WHERE {{
  ?r a g:Retraction ;
     g:identifier ?identifier ;
     g:reporter ?reporter .
  OPTIONAL {{ ?r g:signedStatement ?signedStatement }}
  {cursor}
}} ORDER BY STR(?r) LIMIT {_PAGE_SIZE}
"""


def _verified_withdrawal(row: Mapping[str, Any], environment: str, graph: str) -> Optional[VerifiedRetraction]:
    """The retraction in *row* when it is signed for this network and graph
    and its shown fields match what was signed; else None."""
    envelope = signing.from_text(extract_binding(row.get(SIGNED_STATEMENT_VAR)))
    author = signing.verify(envelope, statement_type=RETRACT_STATEMENT, environment=environment, graph=graph)
    if author is None or envelope is None:
        return None
    identifier = envelope.payload.get("identifier", "")
    reporter = envelope.payload.get("reporter", "")
    if not identifier or not threat_ids.is_agent_address(reporter):
        return None
    subject = threat_ids.report_uri(identifier, reporter) + ":retract"
    shown = (
        extract_binding(row.get("r")),
        extract_binding(row.get("identifier")).strip(),
        extract_binding(row.get("reporter")).strip().lower(),
    )
    if envelope.payload.get("subject") != subject or shown != (subject, identifier, reporter):
        return None
    return VerifiedRetraction(author=author, identifier=identifier, subject=subject, reporter=reporter,
                              day=envelope.payload.get("day", ""))


def verified_retractions(rows: Iterable[Mapping[str, Any]], environment: str, graph: str) -> List[VerifiedRetraction]:
    """Every retraction row that verifies; the rest are dropped and counted in the log."""
    found: List[VerifiedRetraction] = []
    dropped = 0
    for row in rows:
        retraction = _verified_withdrawal(row, environment, graph)
        if retraction is None:
            dropped += 1
        else:
            found.append(retraction)
    if dropped:
        logger.info("blackbox: community read ignored %d unsigned or unverifiable retraction row(s)", dropped)
    return found


def apply_retractions(reports: Iterable[VerifiedReport], withdrawn: FrozenSet[Withdrawal]) -> List[VerifiedReport]:
    """*reports* without those their own signer withdrew."""
    return [report for report in reports if (report.author, report.identifier) not in withdrawn]
