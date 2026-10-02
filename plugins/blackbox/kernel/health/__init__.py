"""Operator health — ONE health item for both surfaces (Refine R10, plan §12 alarms).

Every alarm is a :class:`HealthItem`: ``audience`` (operator | curator),
``klass`` (ACTION — do something; SECURITY — something is wrong with trust;
INFO — nothing to do, protection unchanged), ``message`` and ``what_to_do``.
INFO never renders red. The SAME items feed ``blackbox status`` and the
dashboard banner, so the two can never disagree (one Value Object, two views).

Phase 1 states (the plan's operator list, those the code can decide today):
stale node / old ruleset (ACTION), empty ruleset (ACTION), community read
unavailable (INFO), community ingest paused (INFO), no trusted curator keys
(INFO), curator backlog (INFO), curator key away (INFO), revoked threat
(INFO, + ACTION when it blocked here), statements held by the budget (INFO).
Signing-key revocation, manifest conflicts, minReaderVersion and heartbeat
arrive with reader policy (R7b).

A kernel sub-package (the kernel folder is at its file limit).

Usage::

    items = health.operator_health(health.HealthInputs(...))
    for line in health.render_lines(items): print(line)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Mapping, Optional


class HealthClass(Enum):
    ACTION = "action"
    SECURITY = "security"
    INFO = "info"


@dataclass(frozen=True)
class HealthItem:
    """One alarm. ``klass`` INFO is never rendered red by any surface."""

    audience: str
    klass: HealthClass
    message: str
    what_to_do: str

    def as_dict(self) -> dict:
        return {"audience": self.audience, "class": self.klass.value, "message": self.message, "what_to_do": self.what_to_do}


@dataclass(frozen=True)
class HealthInputs:
    """Everything the health rules look at (plain facts, gathered by the caller).

    ``node_reachable``; ``ruleset_age_s`` (seconds since the ruleset was
    compiled; None = never); ``sync_interval_s``; ``rule_count``;
    ``community_configured``; ``community_paused``; ``read_unavailable_reason``
    ("" when the last community read was fine); ``curator_trusted`` (a key
    manifest this network trusts); ``backlog`` (lanes text, "" when none);
    ``away_keys``; ``revoked`` ({identifier: actions it BLOCKED here});
    ``held_back`` (statements over the per-author budget); ``pending_shares``
    (this node's reports waiting to be retried, R16); ``shares_given_up``
    (reports abandoned after the retry window).
    """

    node_reachable: bool
    ruleset_age_s: Optional[float]
    sync_interval_s: float
    rule_count: int
    community_configured: bool = False
    community_paused: bool = False
    read_unavailable_reason: str = ""
    curator_trusted: bool = False
    backlog: str = ""
    away_keys: int = 0
    revoked: Mapping[str, int] = None  # type: ignore[assignment]
    held_back: int = 0
    pending_shares: int = 0
    shares_given_up: int = 0


#: A ruleset older than this many sync intervals is stale.
STALE_INTERVALS = 2.0

_OPERATOR = "operator"


def operator_health(inputs: HealthInputs) -> List[HealthItem]:
    """The operator's alarms for *inputs*, ACTION and SECURITY first."""
    items: List[HealthItem] = []
    items += _node_and_ruleset(inputs)
    if inputs.community_configured:
        items += _community(inputs)
    return sorted(items, key=lambda item: (item.klass is HealthClass.INFO, item.message))


def _node_and_ruleset(inputs: HealthInputs) -> List[HealthItem]:
    items = []
    stale = inputs.ruleset_age_s is None or inputs.ruleset_age_s > STALE_INTERVALS * max(1.0, inputs.sync_interval_s)
    if not inputs.node_reachable or stale:
        why = "the DKG node is unreachable" if not inputs.node_reachable else "the local ruleset is old"
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION, f"my node is stale: {why}",
                                "run `blackbox sync --wait`; check the DKG node is running"))
    if inputs.rule_count == 0:
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION, "UNPROTECTED: the threat ruleset is empty",
                                "run `blackbox sync --wait` to load the threat graph"))
    return items


def _community(inputs: HealthInputs) -> List[HealthItem]:
    items = []
    if inputs.read_unavailable_reason:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"community graph could not be read: {inputs.read_unavailable_reason}",
                                "nothing to do — the last good community tier is kept; verified rules still enforce"))
    if inputs.community_paused:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, "community ingest is paused by the curator",
                                "nothing to do — verified rules still enforce"))
    if not inputs.curator_trusted:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, "no trusted curator keys on this network yet",
                                "nothing to do — community reports count no author until a key manifest is pinned; verified rules still enforce"))
    if inputs.backlog:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"curator BACKLOG (lanes {inputs.backlog})",
                                "nothing to do — review times are extended; disputes and revocations still honoured"))
    if inputs.away_keys:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"{inputs.away_keys} curator key(s) away",
                                "nothing to do — new promotions may wait; flags and blocks unaffected"))
    for identifier, blocked in sorted((inputs.revoked or {}).items()):
        klass = HealthClass.ACTION if blocked else HealthClass.INFO
        todo = (f"it blocked {blocked} action(s) on this machine — review those findings; the rule is now withdrawn"
                if blocked else "nothing to do — the rule is withdrawn everywhere")
        items.append(HealthItem(_OPERATOR, klass, f"threat REVOKED by the curator: {identifier}", todo))
    if inputs.held_back:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"{inputs.held_back} community statement(s) held by the per-author daily budget",
                                "nothing to do — a flooding author is being rate-limited by every reader"))
    if inputs.pending_shares:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO,
                                f"{inputs.pending_shares} report(s) waiting for the network to accept this node's writes",
                                "nothing to do — a newly subscribed node is refused for a few minutes; they are retried automatically"))
    if inputs.shares_given_up:
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION,
                                f"{inputs.shares_given_up} report(s) could not be shared within 24 h",
                                "run `blackbox sync --wait`; check the node is subscribed to the community graph, then `blackbox report --status`"))
    return items


def render_lines(items: List[HealthItem]) -> List[str]:
    """The CLI view: one line per item, class first, what-to-do after a dash."""
    if not items:
        return ["  health:            ok — nothing to do"]
    return [f"  health:            [{item.klass.value.upper()}] {item.message} — {item.what_to_do}" for item in items]


def red(item: HealthItem) -> bool:
    """Whether a surface may render *item* in red: never for INFO."""
    return item.klass is not HealthClass.INFO


def gather(cfg: Any, rs: Any, node_reachable: bool, read: Optional[Any], blocked_by_identifier: Mapping[str, int],
           now: float, *, pending_shares: int = 0, shares_given_up: int = 0) -> HealthInputs:
    """Build :class:`HealthInputs` from a config, a compiled ruleset, node
    reachability, the last community read (or None), how many actions each
    threat blocked here (``audit.blocked_counts_by_identifier()``) and the
    share-retry counts (``community.share_retry_stats()``)."""
    view = getattr(read, "curator", None)
    revoked = {ident: int(blocked_by_identifier.get(ident, 0)) for ident in (view.revoked if view is not None else ())}
    return HealthInputs(
        node_reachable=node_reachable,
        ruleset_age_s=(now - getattr(rs, "synced_at", 0)) if getattr(rs, "synced_at", 0) else None,
        sync_interval_s=float(getattr(cfg, "sync_interval", 0) or 0),
        rule_count=sum(int(v) for k, v in rs.counts().items() if k != "community"),
        community_configured=bool(getattr(cfg, "community_graph_id", "")),
        community_paused=bool(getattr(rs, "community_paused", False)),
        read_unavailable_reason=("" if read is None or read.available else str(read.reason)),
        curator_trusted=bool(view is not None and view.manifest is not None),
        backlog=(view.backlog.field("lanes") if view is not None and view.backlog else ""),
        away_keys=len(view.away) if view is not None else 0,
        revoked=revoked,
        held_back=int(getattr(read, "held_back", 0) or 0),
        pending_shares=int(pending_shares),
        shares_given_up=int(shares_given_up),
    )


def ruleset_age_text(age_s: Optional[float]) -> str:
    if age_s is None:
        return "never compiled"
    minutes = int(age_s // 60)
    return f"{minutes} min ago" if minutes < 120 else f"{int(age_s // 3600)} h ago"
