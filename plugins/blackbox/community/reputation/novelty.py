"""Hardened novelty credit (R4, plan §05 NOVELTY).

A report earns a NOVELTY credit — the only thing that graduates a reporter —
only when ALL of these hold: its cluster was the FIRST to report the threat;
the threat was absent from the verified graph, OSV, the community graph AND
the curator's public-feed snapshot at report time (front-running a feed earns
nothing); another counted cluster also saw it in the wild; the upstream
publisher or registrant has not already yielded a credit (≤ 1 per
publisher); and the artifact was published at least :data:`SELF_DEALING_HOURS`
before the report (publishing your own junk malware to farm confirmations
earns sighting credit only).

Pure: the curator's dossier supplies the facts; this module only judges them.

Usage::

    verdict = novelty_credit(NoveltyFacts(first_cluster=True, absent_everywhere=True, corroborated_in_the_wild=True,
                                          publisher="npm:evil-author", publisher_credits_used=0,
                                          artifact_age_hours=120.0))
    verdict.credit is NoveltyCredit.CREDIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

#: An artifact published less than this long before its report earns sighting credit only.
SELF_DEALING_HOURS = 72.0
#: At most one novelty credit per upstream publisher or registrant.
CREDITS_PER_PUBLISHER = 1


class NoveltyCredit(Enum):
    """``CREDIT`` counts toward graduation; ``SIGHTING_ONLY`` protects peers
    but builds no reputation; ``NONE`` earns nothing."""

    CREDIT = "credit"
    SIGHTING_ONLY = "sighting-only"
    NONE = "none"


@dataclass(frozen=True)
class NoveltyFacts:
    """What the curator established about one confirmed report: whether its
    cluster was ``first_cluster``; ``absent_everywhere`` — not in the verified
    graph, OSV, the community graph or the public-feed snapshot at report
    time; ``corroborated_in_the_wild`` — another counted cluster saw it;
    ``publisher`` — the upstream publisher / registrant (empty if unknown);
    ``publisher_credits_used`` — credits already granted for that publisher;
    ``artifact_age_hours`` — hours between the artifact's publication and the
    report (None if unknown)."""

    first_cluster: bool
    absent_everywhere: bool
    corroborated_in_the_wild: bool
    publisher: str = ""
    publisher_credits_used: int = 0
    artifact_age_hours: Optional[float] = None


@dataclass(frozen=True)
class NoveltyVerdict:
    credit: NoveltyCredit
    reason: str


def novelty_credit(facts: NoveltyFacts) -> NoveltyVerdict:
    """Judge one confirmed report (every rule is a reduction: the first
    failing rule names itself)."""
    if not facts.first_cluster:
        return NoveltyVerdict(NoveltyCredit.SIGHTING_ONLY, "another cluster reported it first")
    if not facts.absent_everywhere:
        return NoveltyVerdict(NoveltyCredit.NONE, "already known to a feed, OSV or a graph at report time (front-running earns nothing)")
    if not facts.corroborated_in_the_wild:
        return NoveltyVerdict(NoveltyCredit.NONE, "no other counted cluster saw it in the wild")
    if facts.publisher and facts.publisher_credits_used >= CREDITS_PER_PUBLISHER:
        return NoveltyVerdict(NoveltyCredit.SIGHTING_ONLY, "this upstream publisher already yielded a credit")
    if facts.artifact_age_hours is not None and facts.artifact_age_hours < SELF_DEALING_HOURS:
        return NoveltyVerdict(NoveltyCredit.SIGHTING_ONLY, "artifact published less than 72 h before the report (self-dealing window)")
    return NoveltyVerdict(NoveltyCredit.CREDIT, "first cluster, absent everywhere, corroborated in the wild")
