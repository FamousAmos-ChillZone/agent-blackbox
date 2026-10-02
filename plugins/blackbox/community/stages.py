"""Local stages for community threats, from the counted-author list (Refine R3).

Every node computes the SAME stage for the same community threat from the
same inputs — the verified reports' signers, the curator-published
counted-author list, the curator's verdicts, counted disputes and this node's
own first-observation time — and labels it ``local`` (plan §03: Phase 1 has
no curator stage attestations; those arrive in Phase 2). Stages below
VERIFIED never change blocking: the strongest a community threat reaches
here is FLAG. VERIFIED and BLOCK belong to the verified tier alone, which
this module never touches (verified rules never expire by time, KI-117).

The one corroboration rule: CORROBORATED when the class-count table is met,
counting distinct CLUSTERS — each PARTNER organisation is one cluster
however many keys it runs; each ESTABLISHED author is one — over a span of at
least T reader-observed days. Enforcement levels (decision 15): MONITOR for
REPORTED from unlisted authors, HELD, DEFERRED, REJECTED, REVOKED and EXPIRED;
FLAG for REPORTED from counted authors and CORROBORATED — except a
community-only CORROBORATED domain or wallet IOC flags only once a PARTNER
cluster is in the set (a false flag there harms a third party). A dispute
never changes enforcement by itself; decay needs counted dispute weight ≥ the
corroborating weight.

Pattern: pure functions + a Constant threshold table. Stages are a function
of the rows, not a stored machine.

Usage::

    result = stages.stage_for(identifier, authors, first_seen, view, dispute_weight, verdict, now)
    result.stage, result.enforcement, result.reason        # -> rule["stage"], ["enforcement"], ["stageReason"]
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Dict, Iterable, Mapping, Optional, Tuple

from ..kernel.signing.statement_order import CuratorStatement
from .statements.curator_view import CuratorView
from . import allowlist
from .statements.lifetimes import lifetime_days

_DAY_SECONDS = 86_400


class Stage(Enum):
    """Where a community threat stands (plan §03). Display labels are the values."""

    REPORTED = "reported"
    HELD = "held"
    CORROBORATED = "corroborated"
    DEFERRED = "deferred"
    REJECTED = "rejected"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Enforcement(Enum):
    """What a community stage may do. BLOCK exists only in the verified tier."""

    MONITOR = "monitor"   # audit only
    FLAG = "flag"


@dataclass(frozen=True)
class Threshold:
    """The class-count rule for one threat class: CORROBORATED with
    ``partner_only`` partner clusters, or ``mixed`` = (partners, established),
    or ``established_only`` established authors — over at least ``days``."""

    partner_only: int
    mixed: Tuple[int, int]
    established_only: int
    days: int

    def met(self, clusters: "Clusters") -> bool:
        partners, established = clusters.partner, clusters.established
        return (partners >= self.partner_only
                or (partners >= self.mixed[0] and established >= self.mixed[1])
                or established >= self.established_only)


#: Plan §03 per-type table. IOCs and injection patterns: 2 PARTNER orgs, or
#: 1 PARTNER + 2 ESTABLISHED, or 5 ESTABLISHED, over 2 days. Malware-class
#: (dependency, escalation, file access, skill): 3 / (2, 2) / 8, over 3 days.
IOC_THRESHOLD = Threshold(partner_only=2, mixed=(1, 2), established_only=5, days=2)
MALWARE_THRESHOLD = Threshold(partner_only=3, mixed=(2, 2), established_only=8, days=3)
_IOC_CLASS = ("ioc:", "injection:")

#: Community-only IOCs of these types flag only with a PARTNER cluster in the set.
_THIRD_PARTY_IOC = ("ioc:domain:", "ioc:wallet:")


def threshold_for(identifier: str) -> Threshold:
    return IOC_THRESHOLD if identifier.startswith(_IOC_CLASS) else MALWARE_THRESHOLD


@dataclass(frozen=True)
class Clusters:
    """Distinct counted clusters behind a threat: ``partner`` organisations
    and ``established`` authors. ``total`` is the corroborating weight."""

    partner: int
    established: int

    @property
    def total(self) -> int:
        return self.partner + self.established


def clusters_for(authors: Iterable[str], view: CuratorView) -> Clusters:
    """Count the counted clusters among *authors* (reporter keys): one per
    partner organisation, one per established author; unlisted authors none.
    R4: established keys the curator listed under the same non-empty ``org``
    are a published COLLAPSE (same transport peer, 90-day overlap) and count
    once, like a partner organisation's keys."""
    orgs = set()
    established_clusters = set()
    for author in set(authors):
        entry = view.counted.get(author)
        if entry is None:
            continue
        if entry.author_class == "partner":
            orgs.add(entry.org or entry.key)
        else:
            established_clusters.add(entry.org or entry.key)
    return Clusters(partner=len(orgs), established=len(established_clusters))


@dataclass(frozen=True)
class StageResult:
    """One threat's stage: ``stage``, ``enforcement``, a one-line ``reason``,
    ``source`` (always ``local`` in Phase 1), ``disputed`` (any counted
    dispute — a tag, never enforcement by itself) and ``counted`` — the
    counted clusters behind it (plan §05 queue admission: an item reaches a
    curator lane only with counted weight or a dispute, KI-194)."""

    stage: Stage
    enforcement: Enforcement
    reason: str
    disputed: bool = False
    source: str = "local"
    counted: int = 0
    #: R9: the allowlisted name this threat looks like (a homograph supports the report).
    confusable_of: str = ""

    def as_fields(self) -> Dict[str, str]:
        """The rule-dict fields the ruleset stores and the UI shows."""
        fields = {"stage": self.stage.value, "enforcement": self.enforcement.value, "stageReason": self.reason,
                  "stageSource": self.source, "disputed": "yes" if self.disputed else "no", "counted": str(self.counted)}
        if self.confusable_of:
            fields["confusableOf"] = self.confusable_of
        return fields


def is_whole_package(identifier: str) -> bool:
    """A name-level dependency report (``dep:…@*``): held, weight 0 (plan §06 warninglist)."""
    return identifier.startswith("dep:") and identifier.endswith("@*")


def stage_for(identifier: str, authors: Iterable[str], first_seen: float, view: CuratorView,
              dispute_weight: int, verdict: Optional[CuratorStatement], now: float,
              fields: Optional[Mapping[str, str]] = None) -> StageResult:
    """The local stage of one community threat.

    *authors* — verified signer keys of its reports; *first_seen* — THIS
    node's first observation (epoch); *view* — the verified curator view;
    *dispute_weight* — how many counted authors dispute it; *verdict* — the
    curator's current verdict for it, if any; *fields* — the report's closed
    fields (R9 reads ``kind``).
    """
    clusters = clusters_for(authors, view)
    result = _stage(identifier, first_seen, clusters, dispute_weight, verdict, now, allowlist.check(identifier, fields))
    attested = view.attestation(identifier)
    if attested is not None and result.stage not in _NOT_ATTESTABLE:
        # R3-attest: readers prefer the curator's attested stage. Terminal verdicts
        # (rejected / revoked) and this reader's own lifetime expiry still dominate,
        # and counted disputes still reduce — reductions always apply (LES-016).
        result = _apply_disputes(_attested(attested.field("stage"), attested.sequence, clusters), clusters, dispute_weight)
    return replace(result, counted=clusters.total)


#: Stages no attestation overrides: terminal verdicts and the reader's own expiry.
_NOT_ATTESTABLE = frozenset({Stage.REVOKED, Stage.REJECTED, Stage.EXPIRED})


def _attested(stage_value: str, sequence: int, clusters: Clusters) -> StageResult:
    """The curator's attested stage with the enforcement that stage carries
    locally: CORROBORATED flags, REPORTED flags only with counted weight,
    everything else monitors — a stage below VERIFIED never blocks."""
    stage = Stage(stage_value)
    if stage is Stage.CORROBORATED or (stage is Stage.REPORTED and clusters.total > 0):
        enforcement = Enforcement.FLAG
    else:
        enforcement = Enforcement.MONITOR
    return StageResult(stage, enforcement, f"attested by the curator (statement #{sequence})", source="curator")


def _stage(identifier: str, first_seen: float, clusters: "Clusters", dispute_weight: int,
           verdict: Optional[CuratorStatement], now: float, listed: allowlist.Verdict) -> StageResult:
    terminal = _terminal_stage(verdict)
    if terminal is not None:
        return terminal
    span_days = max(0.0, now - first_seen) / _DAY_SECONDS
    if span_days > lifetime_days(identifier):
        return StageResult(Stage.EXPIRED, Enforcement.MONITOR, f"community lifetime of {lifetime_days(identifier)} days passed")
    if is_whole_package(identifier):
        return StageResult(Stage.HELD, Enforcement.MONITOR, "whole-package report held: weight 0 until a curator checks it")
    if listed.holds:   # R9: a byte-exact allowlisted name, or name-level / vulnerability noise on a popular package
        return StageResult(Stage.HELD, Enforcement.MONITOR, f"held for a curator: {listed.reason}")
    result = _by_corroboration(identifier, clusters, threshold_for(identifier), span_days, verdict)
    if listed.confusable_of:   # R9 inverted look-alike rule: a homograph SUPPORTS the report
        result = replace(result, reason=f"{result.reason}; {listed.reason}", confusable_of=listed.confusable_of)
    return _apply_disputes(result, clusters, dispute_weight)


def _terminal_stage(verdict: Optional[CuratorStatement]) -> Optional[StageResult]:
    if verdict is CuratorStatement.REVOCATION:
        return StageResult(Stage.REVOKED, Enforcement.MONITOR, "revoked by the curator")
    if verdict is CuratorStatement.REJECTION:
        return StageResult(Stage.REJECTED, Enforcement.MONITOR, "rejected by the curator")
    return None


def _by_corroboration(identifier: str, clusters: Clusters, threshold: Threshold, span_days: float,
                      verdict: Optional[CuratorStatement]) -> StageResult:
    if verdict is CuratorStatement.CONFIRMATION:
        return StageResult(Stage.CORROBORATED, Enforcement.FLAG, "confirmed by the curator")
    if not threshold.met(clusters):
        if clusters.total == 0:
            return StageResult(Stage.REPORTED, Enforcement.MONITOR, "reported by unlisted authors only")
        return StageResult(Stage.REPORTED, Enforcement.FLAG,
                           f"reported by {clusters.total} counted cluster(s); corroboration needs more")
    if span_days < threshold.days:
        return StageResult(Stage.REPORTED, Enforcement.FLAG,
                           f"class count met; corroboration needs {threshold.days} observed days")
    if verdict is CuratorStatement.DEFERRAL:
        return StageResult(Stage.DEFERRED, Enforcement.MONITOR, "corroborated; the curator deferred it (no evidence yet)")
    if identifier.startswith(_THIRD_PARTY_IOC) and clusters.partner == 0:
        return StageResult(Stage.CORROBORATED, Enforcement.MONITOR,
                           "corroborated by established authors; a domain or wallet flags only with a partner cluster")
    lapsed = " (a curator deferral lapsed)" if verdict is CuratorStatement.DEFERRAL_LAPSED else ""
    return StageResult(Stage.CORROBORATED, Enforcement.FLAG,
                       f"corroborated by {clusters.partner} partner and {clusters.established} established cluster(s){lapsed}")


def _apply_disputes(result: StageResult, clusters: Clusters, dispute_weight: int) -> StageResult:
    """A counted dispute tags the threat; enough of them decay it to MONITOR
    (Σ counted dispute weight ≥ the corroborating weight)."""
    if dispute_weight <= 0:
        return result
    if dispute_weight >= clusters.total and result.enforcement is Enforcement.FLAG:
        return StageResult(result.stage, Enforcement.MONITOR,
                           f"{result.reason}; disputed by {dispute_weight} counted author(s) — decayed to monitor",
                           disputed=True)
    return StageResult(result.stage, result.enforcement, f"{result.reason}; disputed by {dispute_weight} counted author(s)",
                       disputed=True)
