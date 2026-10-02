"""Reputation bands and a reporter's standing (Refine R4, plan §05 / §10).

Three bands. PROBATION weighs nothing — a fresh key counts zero however many
reports it files, which is what makes twenty fresh wallets worth exactly 0.
ESTABLISHED weighs 1 × its Beta reputation. PARTNER is an organisation: all
of its keys share one cluster and weigh 1 × the organisation's reputation.

Pattern: Value Objects — :class:`ReporterStanding` is frozen and carries every
number the pure scoring functions in :mod:`.scoring` need; nothing here reads
a file or a clock.

Usage::

    standing = ReporterStanding(key="…64 hex…", band=ReputationBand.ESTABLISHED, first_seen_day="2026-08-01",
                                confirmed=7, rejected=1, strikes=0, novel_credits=5)
    weight_for(standing, reputation=0.8)      # 0.8
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional


class ReputationBand(Enum):
    """Where a reporter stands: ``PROBATION`` (weight 0), ``ESTABLISHED``
    (weight 1 × reputation), ``PARTNER`` (an organisation, 1 × its reputation)."""

    PROBATION = "probation"
    ESTABLISHED = "established"
    PARTNER = "partner"


@dataclass(frozen=True)
class ReporterStanding:
    """One reporter as the curator's private ledger knows it.

    ``key`` — the reporter KEY hex (the identity, LES-014); ``band``;
    ``first_seen_day`` — the UTC day of its first share (graduation needs
    14 days from here); ``confirmed`` / ``rejected`` — curator outcomes
    (rejected = honest error); ``strikes`` — confirmed bad faith (feeds
    demotion); ``novel_credits`` — curator-confirmed NOVEL reports
    (:mod:`.novelty`); ``org`` — the partner organisation (partners only);
    ``sponsor`` — the organisation sponsoring a new node (weight ≤ 0.5,
    shared strikes); ``lockout_until`` — UTC day a demotion lockout ends.
    """

    key: str
    band: ReputationBand = ReputationBand.PROBATION
    first_seen_day: str = ""
    confirmed: int = 0
    rejected: int = 0
    strikes: int = 0
    novel_credits: int = 0
    org: str = ""
    sponsor: str = ""
    lockout_until: str = ""

    def locked_out(self, today: str) -> bool:
        return bool(self.lockout_until) and today < self.lockout_until

    def reset_after_lockout(self) -> "ReporterStanding":
        """Re-graduation starts from zero: every counter and credit is cleared."""
        return replace(self, band=ReputationBand.PROBATION, confirmed=0, rejected=0, strikes=0,
                       novel_credits=0, lockout_until="")


#: A sponsored new node weighs at most this much of its sponsor's weight.
SPONSOR_WEIGHT_CAP = 0.5


def weight_for(standing: ReporterStanding, reputation: float, sponsor_reputation: Optional[float] = None) -> float:
    """The corroborating weight of one reporter: 0 on probation (or locked
    out), else its band's base × reputation; a sponsored probationer weighs
    ≤ 0.5 × its sponsor's reputation. Never above 1.0."""
    if standing.lockout_until:
        return 0.0
    if standing.band is ReputationBand.PROBATION:
        if standing.sponsor and sponsor_reputation is not None:
            return min(SPONSOR_WEIGHT_CAP, max(0.0, sponsor_reputation) * SPONSOR_WEIGHT_CAP)
        return 0.0
    return min(1.0, max(0.0, reputation))
