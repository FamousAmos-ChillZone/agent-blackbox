"""Reputation (Refine R4): automated graduation, hardened novelty, partners, collusion.

Phase 1 moved reporters between stages only by a curator-listed counted-author
list. Phase 2 keeps that list as the ONLY thing readers trust and adds the
machinery that decides what goes on it: three bands (probation weighs 0),
Beta reputation with forgetting, separate rejected and strike counters with
re-graduation from zero, a novelty credit hardened against feed front-running
and self-dealing, PARTNER per organisation with grant expiry and sponsorship,
transport-peer-id and 90-day overlap collapse, the co-report graph as a
detector only, and a curator-PRIVATE ledger keyed by per-reporter salts
(erasure deletes the salt).

Pure scoring modules (:mod:`.bands`, :mod:`.scoring`, :mod:`.novelty`,
:mod:`.partners`, :mod:`.collusion`, :mod:`.graduation`) + one ledger class
(:mod:`.ledger`). Readers apply a published collapse through the counted-author
``org`` field (``community.stages.clusters_for``).
"""

from __future__ import annotations

from .bands import SPONSOR_WEIGHT_CAP, ReporterStanding, ReputationBand, weight_for
from .collusion import OVERLAP_JACCARD, OVERLAP_MIN_SHARED, OVERLAP_WINDOW_DAYS, collapse, jaccard, rings
from .graduation import LISTING_DAYS, nomination_fields, renewal_fields
from .ledger import RETENTION_DAYS, ReputationLedger, pseudonym
from .novelty import SELF_DEALING_HOURS, NoveltyCredit, NoveltyFacts, NoveltyVerdict, novelty_credit
from .partners import GRANT_MAX_DAYS, SUSPENSION_REJECTIONS, PartnerGrant, org_clusters, partner_weight
from .scoring import (GRADUATION_MIN_DAYS, GRADUATION_MIN_NOVEL, HALF_LIFE_DAYS, LOCKOUT_DAYS, REPUTATION_FLOOR,
                      STRIKES_TO_DEMOTE, Outcome, beta_reputation, demotion, graduates)

__all__ = [
    "GRADUATION_MIN_DAYS", "GRADUATION_MIN_NOVEL", "GRANT_MAX_DAYS", "HALF_LIFE_DAYS", "LISTING_DAYS", "LOCKOUT_DAYS",
    "NoveltyCredit", "NoveltyFacts", "NoveltyVerdict", "OVERLAP_JACCARD", "OVERLAP_MIN_SHARED", "OVERLAP_WINDOW_DAYS",
    "Outcome", "PartnerGrant", "REPUTATION_FLOOR", "RETENTION_DAYS", "ReporterStanding", "ReputationBand",
    "ReputationLedger", "SELF_DEALING_HOURS", "SPONSOR_WEIGHT_CAP", "STRIKES_TO_DEMOTE", "SUSPENSION_REJECTIONS",
    "beta_reputation", "collapse", "demotion", "graduates", "jaccard", "nomination_fields", "renewal_fields", "novelty_credit",
    "org_clusters", "partner_weight", "pseudonym", "rings", "weight_for",
]
