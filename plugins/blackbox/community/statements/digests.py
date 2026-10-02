"""Reading sighting digests and estimating heat (Refine R2b).

A digest (:mod:`..digest`) says which VERIFIED threats one reporter met in one
ISO week, as buckets. This module verifies digests (signed ``blackbox.digest``
for this network and graph; the subject is the signer's own (reporter, week)
subject; entries well-formed) and turns them into a per-threat HEAT estimate:
the sum of bucket midpoints over COUNTED authors (plan §05). Rules:

* counted authors only — a digest from an unlisted author is kept for display
  ("new reporter") and weighs 0;
* at most one digest per author per week — the first this node observed
  wins, later ones for the same week are ignored and logged (an author
  cannot inflate heat by publishing twice);
* a digest is one statement against the per-author budget (the reader
  applies the budget before calling :func:`heat_for_week`).

Usage (from the reader)::

    found = digests.verified_digests(rows, environment, graph)
    heat = digests.heat_for_week(found, view, first_seen, week)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from ...kernel import signing, sparql_text
from ...kernel.dkg_client import extract_binding
from ...kernel import threat_ids
from ..digest import DigestEntry, digest_subject, parse_entries
from ..report_signer import DIGEST_STATEMENT
from ..verification import SIGNED_STATEMENT_VAR
from .curator_view import CuratorView

logger = logging.getLogger(__name__)

_PAGE_SIZE = 5000


@dataclass(frozen=True)
class VerifiedDigest:
    """One verified digest: ``subject``, ``author`` (signer key — the identity),
    ``reporter`` (claimed address, display), ``week`` (ISO), ``entries``."""

    subject: str
    author: str
    reporter: str
    week: str
    entries: Tuple[DigestEntry, ...]


@dataclass(frozen=True)
class HeatEstimate:
    """How many agents met one threat in one week, estimated from counted
    digests: ``agents`` = Σ bucket midpoints, over ``digests`` digests."""

    identifier: str
    week: str
    agents: int
    digests: int


def digests_sparql(after: str) -> str:
    """One page of SightingDigest rows after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?reporter ?isoWeek ?signedStatement WHERE {{
  ?r a g:SightingDigest ;
     g:reporter ?reporter ;
     g:isoWeek ?isoWeek .
  OPTIONAL {{ ?r g:signedStatement ?signedStatement }}
  {cursor}
}} ORDER BY STR(?r) LIMIT {_PAGE_SIZE}
"""


def _verified(row: Mapping[str, Any], environment: str, graph: str) -> Optional[VerifiedDigest]:
    envelope = signing.from_text(extract_binding(row.get(SIGNED_STATEMENT_VAR)))
    author = signing.verify(envelope, statement_type=DIGEST_STATEMENT, environment=environment, graph=graph)
    if author is None or envelope is None:
        return None
    payload = envelope.payload
    reporter, week = payload.get("reporter", ""), payload.get("week", "")
    entries = parse_entries(payload.get("entries", ""))
    if not threat_ids.is_agent_address(reporter) or not week or entries is None:
        return None
    subject = digest_subject(reporter, week)
    shown = (extract_binding(row.get("r")), extract_binding(row.get("reporter")).strip().lower(),
             extract_binding(row.get("isoWeek")).strip())
    if payload.get("subject") != subject or shown != (subject, reporter, week):
        return None
    return VerifiedDigest(subject=subject, author=author, reporter=reporter, week=week, entries=entries)


def verified_digests(rows: Iterable[Mapping[str, Any]], environment: str, graph: str) -> List[VerifiedDigest]:
    """Every digest row that verifies; the rest are dropped and counted in the log."""
    found: List[VerifiedDigest] = []
    dropped = 0
    for row in rows:
        digest = _verified(row, environment, graph)
        if digest is None:
            dropped += 1
        else:
            found.append(digest)
    if dropped:
        logger.info("blackbox: community read ignored %d unsigned or unverifiable digest row(s)", dropped)
    return found


def one_per_author_week(digests: Iterable[VerifiedDigest], first_seen: Mapping[str, float]) -> List[VerifiedDigest]:
    """At most one digest per (author, week): the first this node observed."""
    chosen: Dict[Tuple[str, str], VerifiedDigest] = {}
    ignored = 0
    for digest in sorted(digests, key=lambda d: (first_seen.get(d.subject, float("inf")), d.subject)):
        if chosen.setdefault((digest.author, digest.week), digest) is not digest:
            ignored += 1
    if ignored:
        logger.warning("blackbox: %d duplicate sighting digest(s) for an author's week ignored", ignored)
    return list(chosen.values())


def latest_week(digests: Iterable[VerifiedDigest]) -> str:
    """The most recent ISO week any digest covers ("" when none)."""
    return max((d.week for d in digests), default="")


def heat_for_week(digests: Iterable[VerifiedDigest], view: CuratorView, week: str) -> Dict[str, HeatEstimate]:
    """Per threat, the heat estimate for *week* from COUNTED authors' digests
    (already reduced to one per author and week)."""
    agents: Dict[str, int] = {}
    count: Dict[str, int] = {}
    for digest in digests:
        if digest.week != week or not view.is_counted(digest.author):
            continue
        for entry in digest.entries:
            agents[entry.identifier] = agents.get(entry.identifier, 0) + entry.bucket.midpoint
            count[entry.identifier] = count.get(entry.identifier, 0) + 1
    return {identifier: HeatEstimate(identifier=identifier, week=week, agents=agents[identifier],
                                     digests=count[identifier]) for identifier in agents}
