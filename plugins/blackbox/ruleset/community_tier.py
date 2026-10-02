"""The community tier of a ruleset: merging community reports in, and making
the matchable ones O(1)-lookup rules.

Owns :func:`apply_community_tier` (called by the refresh cycle after the
verified build, so public rules already hold their keys — public beats
community structurally) and :func:`materialize_community_rules`. Community
rules match by identifier equality only; nothing community-sourced ever
reaches a pattern compile (KI-004). Fail-open at every boundary.

Usage (inside ruleset/): ``community_tier.apply_community_tier(rs, client, cfg, prior)``.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from .. import community
from ..kernel import threat_ids
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient
from . import compiler

logger = logging.getLogger(__name__)


def apply_community_tier(rs: compiler.Ruleset, client: DkgClient, cfg: BlackboxConfig,
                         prior: Optional[compiler.Ruleset] = None) -> None:
    """Enrich a freshly built ruleset with the community tier. Fail-open.

    Populates ``rs.community`` (the corroboration/display store, keyed by
    identifier literal) and materializes MATCHABLE community rules into the
    ``dependency``/``ioc`` O(1) lookup dicts only — identifier-equality
    matching, never pattern execution (KI-004). Public rules always win a
    key collision (merge precedence). Injection/escalation/fileaccess/skill
    community reports stay display-and-corroboration only in v1: their
    local detections derive the same deterministic identifiers, so
    corroboration works without ever interpreting community content.

    *prior* is this node's previous ruleset generation (first-seen history and
    the last-good fallback); the refresh cycle passes it in.
    """
    if not cfg.community_graph_id:
        return
    previous = dict(prior.community) if prior is not None else {}   # captured first: *prior* may be *rs* itself
    try:
        if community.community_pause_active(client, cfg):
            logger.warning("blackbox: community ingest PAUSED by curator flag")
            rs.community_paused = True
            return
        # KI-034: updated existing installs must join without a manual sync —
        # but only when the node says it is not subscribed, and at most once
        # per retry window (R0, KI-064/114; community/membership.py).
        community.ensure_community_subscription(client, cfg)
        # R0c/R0d: only reports whose signature verifies for THIS network and
        # graph are counted; the self-described reporter field never is.
        read = community.read_verified_reports(client, cfg)
        if not read.available:
            # Unavailable — a failed or malformed page, an unverifiable
            # network, or an unproven empty read: keep last-good (fail-open).
            # Never mistake "could not read" for "no threats" (KI-112).
            _keep_last_good(rs, prior)
            return
        rules = community.aggregate_community_reports(read.reports, _first_seen_history(prior))
        rs.community = {rule.identifier: {**rule.as_rule(), **_stage_fields(rule, read), "networkLive": "yes"}
                        for rule in rules}
        _carry_kept_locally(rs, previous, time.time())
        if getattr(cfg, "community_shadow", False):   # R15: stages logged, only MONITOR enforced
            community.shadow.clamp_to_monitor(rs.community)
        materialize_community_rules(rs)
    except Exception as exc:  # pragma: no cover - fail open at the tier boundary
        logger.debug("blackbox: community tier skipped: %s", exc)


#: R5 reader persistence: a counted threat whose network copies expired stays
#: in this node's tier this long after it was last read, so a slow-burn threat
#: survives its author's silence on the reader side too (plan §06: ≤90 d).
KEPT_LOCALLY_DAYS = 90
_DAY_SECONDS = 86_400.0


def _carry_kept_locally(rs: compiler.Ruleset, previous: Dict[str, Dict[str, Any]], now: float) -> None:
    """Carry over entries the fresh read no longer has — only threats with at
    least one counted cluster, within their type's lifetime (decay on this
    node's observation time, never the sender's), gone for ≤ KEPT_LOCALLY_DAYS.
    They keep their last stage and are marked ``networkLive: no`` so the
    dashboard shows "kept locally" apart from what the network still carries."""
    for identifier, rule in previous.items():
        if identifier in rs.community or int(rule.get("counted") or 0) < 1:
            continue
        gone_since = float(rule.get("keptSince") or now)
        first_seen = float(rule.get("firstSeen") or now)
        if now - gone_since > KEPT_LOCALLY_DAYS * _DAY_SECONDS:
            continue
        if now - first_seen > community.lifetime_days(identifier) * _DAY_SECONDS:
            continue
        rs.community[identifier] = {**rule, "networkLive": "no", "keptSince": gone_since}


def reapply_community_tier(rs: compiler.Ruleset, client: DkgClient, cfg: BlackboxConfig) -> None:
    """Refresh the community tier of a ruleset the refresh cycle is REUSING
    (the verified tier came back empty or failed, so last-good is kept).

    Without this the community tier would silently stop refreshing on those
    paths (R0 tri-state: "the community tier refreshes on every verified-tier
    path"). Community entries materialized last time are removed first —
    materializing only ever adds — then the tier is applied as usual, with
    the ruleset itself as the first-seen history and last-good fallback.
    """
    for table in (rs.dependency, rs.ioc):
        for key in [k for k, rule in table.items() if rule.get("source") == "community"]:
            del table[key]
    apply_community_tier(rs, client, cfg, rs)
    rs._graph_entries_cache.clear()


def _stage_fields(rule: community.CommunityRule, read: community.CommunityRead) -> Dict[str, str]:
    """R3: the threat's local stage, from the same inputs every node has —
    its signers, the curator view, counted disputes and the current verdict."""
    dispute_weight = community.counted_dispute_weight(read.disputes, read.curator).get(rule.identifier, 0)
    result = community.stage_for(rule.identifier, rule.authors, rule.first_seen, read.curator, dispute_weight,
                                 read.curator.verdict(rule.identifier), time.time(), dict(rule.fields))
    return result.as_fields()


def _first_seen_history(prior: Optional[compiler.Ruleset]) -> Dict[str, float]:
    """identifier -> when THIS node first saw it (KI-012: our observation,
    never a reporter-supplied date), carried over from the previous generation."""
    if prior is None:
        return {}
    return {
        ident: float(rule.get("firstSeen", 0) or 0)
        for ident, rule in prior.community.items()
        if rule.get("firstSeen")
    }


def _keep_last_good(rs: compiler.Ruleset, prior: Optional[compiler.Ruleset]) -> None:
    if prior is not None and prior.community:
        rs.community = dict(prior.community)
        materialize_community_rules(rs)


def materialize_community_rules(rs: compiler.Ruleset) -> None:
    """Copy matchable community rules into the dependency/ioc lookup dicts.

    Only identifier-keyed O(1) structures — nothing community-sourced ever
    reaches a pattern compile or scan list. Public rules keep precedence.
    R3: only rules whose local stage allows FLAG are matchable; MONITOR-level
    ones (unlisted authors only, held, deferred, rejected, revoked, expired)
    stay in the display store and never fire in the hot path.
    """
    for identifier, rule in rs.community.items():
        if rule.get("enforcement") == "monitor":
            continue
        if identifier.startswith("dep:"):
            eco = str(rule.get("packageEcosystem") or "").lower()
            pkg = str(rule.get("packageName") or "").lower()
            ver = str(rule.get("packageVersion") or "")
            if not (eco and pkg and ver):
                try:
                    _, rest = identifier.split(":", 1)
                    eco, tail = rest.split(":", 1)
                    pkg, ver = tail.rsplit("@", 1)
                    eco, pkg = eco.lower(), pkg.lower()
                except ValueError:
                    continue
            key = threat_ids.dependency_key(eco, pkg, ver)
            if key not in rs.dependency:  # public beats community
                rs.dependency[key] = {
                    **rule,
                    "ecosystem": eco,
                    "packageName": pkg,
                    "packageVersion": ver,
                    "advisoryId": "",
                    "kind": rule.get("kind") or None,
                }
        elif identifier.startswith("ioc:"):
            if identifier not in rs.ioc:  # public beats community
                parts = identifier.split(":", 2)
                fallback_type = parts[1] if len(parts) >= 3 else ""
                rs.ioc[identifier] = {**rule, "iocType": str(rule.get("iocType") or fallback_type)}
