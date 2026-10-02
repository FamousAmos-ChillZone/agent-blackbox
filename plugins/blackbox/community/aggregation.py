"""Aggregating verified community reports into community rules.

Takes the verified reports :func:`.reader.read_verified_reports` returns and
turns them into :class:`CommunityRule` values: per-signer cap first (a flood
from one key cannot crowd others out), then corroboration counted by distinct
verified signers, with the OLDEST observation winning ties (KI-100/111). The
typed seam where untrusted community strings are clamped and made display-only
(KI-004/012). Never compiles or interprets community content.

Split out of :mod:`.reader` (which fetches and verifies).

Usage (through the package): ``community.aggregate_community_reports(read.reports, prior_first_seen)``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from ..kernel import constants
from .verification import VerifiedReport

logger = logging.getLogger(__name__)

#: Bounded ingest (KI-010): a spammer can invent unlimited identifiers; we
#: keep the corroborated head (reporter count, then oldest observation), never the tail.
_COMMUNITY_MAX_RULES = 5000

#: Most threats one verified signer may contribute to a compile (KI-100/111).
#: Its OLDEST-known threats are kept, so a fresh flood from one key can neither
#: crowd out other signers nor displace that signer's own earlier reports.
MAX_REPORTS_PER_AUTHOR = 500

@dataclass(frozen=True)
class CommunityRule:
    """One aggregated community threat — the typed seam of the read path.

    Holds the corroborated view of every report for one identifier:
    ``reporter_count`` is COUNT(DISTINCT reporter) — honest by the naming
    scheme; ``severity`` is the max across reporters (community can only
    flag, so loud-side is safe); ``first_seen``/``last_seen`` are THIS
    node's ingest observations, never reporter-supplied timestamps
    (KI-012 — display metadata can't be gamed by post-dating).

    Pattern: Adapter — :meth:`as_rule` converts to the plain rule-dict shape
    the existing merge/detection machinery expects, and is the SINGLE point
    where community-authored strings are clamped and typed display-only.
    No community string is ever compiled or interpreted (KI-004): community
    rules match by identifier equality alone.
    """

    identifier: str
    category: str
    severity: str
    reporter_count: int
    first_seen: float
    last_seen: float
    fields: "tuple[tuple[str, str], ...]" = ()
    #: The verified signer keys behind it (Refine R3: stages count counted clusters among them).
    authors: "tuple[str, ...]" = ()

    _CLAMP = 256

    def as_rule(self) -> Dict[str, Any]:
        """The merge-compatible rule dict; every value clamped display-only."""
        clamp = lambda v: str(v or "")[: self._CLAMP]  # noqa: E731 - tiny local helper
        rule = {
            "identifier": clamp(self.identifier),
            "name": clamp(self.identifier),
            "severity": constants.normalize_severity(self.severity),
            "source": "community",
            "reporterCount": int(self.reporter_count),
            "firstSeen": float(self.first_seen),
            "lastSeen": float(self.last_seen),
        }
        for key, value in self.fields:
            rule[clamp(key)] = clamp(value)
        return rule


def _cap_per_author(reports: Iterable[VerifiedReport], prior_first_seen: Dict[str, float]) -> List[VerifiedReport]:
    """At most MAX_REPORTS_PER_AUTHOR threats per verified signer, keeping
    each signer's oldest-known threats (this node's first-seen history;
    threats it has never seen sort last, then by identifier)."""
    by_author: Dict[str, List[VerifiedReport]] = {}
    for report in reports:
        by_author.setdefault(report.author, []).append(report)
    kept: List[VerifiedReport] = []
    for author_reports in by_author.values():
        author_reports.sort(key=lambda r: (prior_first_seen.get(r.identifier, float("inf")), r.identifier))
        kept.extend(author_reports[:MAX_REPORTS_PER_AUTHOR])
    if len(kept) < sum(len(v) for v in by_author.values()):
        logger.warning("blackbox: community reports capped at %d per signer", MAX_REPORTS_PER_AUTHOR)
    return kept


def aggregate_community_reports(
    reports: Iterable[VerifiedReport], prior_first_seen: Dict[str, float]
) -> List[CommunityRule]:
    """Fold VERIFIED reports into per-identifier CommunityRules.

    Only :class:`~.verification.VerifiedReport` values reach here — a raw row
    cannot be counted (R0c). Aggregation keys on the exact identifier literal
    (KI-027); ``reporter_count`` is the number of distinct SIGNERS (the
    self-described reporter string never counts, KI-067/110); severity is the
    max seen; evidence comes from the signed payload; first_seen carries over
    from this node's previous cache, never a reporter-supplied date (KI-012).
    """
    now = time.time()
    grouped: Dict[str, Dict[str, Any]] = {}
    for report in _cap_per_author(reports, prior_first_seen):
        slot = grouped.setdefault(
            report.identifier,
            {"authors": set(), "severity": "info", "fields": {}},
        )
        slot["authors"].add(report.author)
        if constants.SEVERITY_RANK.get(report.severity, 0) > constants.SEVERITY_RANK.get(slot["severity"], 0):
            slot["severity"] = report.severity
        for var, value in report.fields:
            slot["fields"].setdefault(var, value)
    rules = [
        CommunityRule(
            identifier=identifier,
            category=identifier.split(":", 1)[0],
            severity=slot["severity"],
            reporter_count=len(slot["authors"]),
            first_seen=float(prior_first_seen.get(identifier, now)),
            last_seen=now,
            fields=tuple(sorted(slot["fields"].items())),
            authors=tuple(sorted(slot["authors"])),
        )
        for identifier, slot in grouped.items()
    ]
    # Bounded ingest: corroboration first, then the OLDEST observation (KI-111 —
    # newest-first let a flood of fresh singletons evict honest older ones),
    # then the identifier, so the cut is deterministic.
    rules.sort(key=lambda r: (-r.reporter_count, r.first_seen, r.identifier))
    if len(rules) > _COMMUNITY_MAX_RULES:
        logger.warning(
            "blackbox: community ingest capped at %d rules (%d dropped — corroborated head kept)",
            _COMMUNITY_MAX_RULES,
            len(rules) - _COMMUNITY_MAX_RULES,
        )
        rules = rules[:_COMMUNITY_MAX_RULES]
    return rules
