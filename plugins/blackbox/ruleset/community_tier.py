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
from typing import Dict, Optional

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
    try:
        if community.community_pause_active(client, cfg):
            logger.warning("blackbox: community ingest PAUSED by curator flag")
            rs.community_paused = True
            return
        # KI-034: updated existing installs must join without a manual sync.
        try:
            client.subscribe_context_graph(cfg.community_graph_id, include_shared_memory=True)
        except Exception:
            pass
        raw = community.fetch_community_report_rows(client, cfg)
        environment = _node_environment(client) if raw is not None else ""
        if raw is None or not environment:
            # Fetch failed, or the network is unknown so nothing can be
            # verified: keep last-good community rows (fail-open).
            _keep_last_good(rs, prior)
            return
        # R0c: only reports whose signature verifies for THIS network and
        # graph are counted; the self-described reporter field never is.
        verifier = community.ReportVerifier(environment, cfg.community_graph_id)
        reports, _dropped = community.verify_report_rows(raw, verifier)
        rules = community.aggregate_community_reports(reports, _first_seen_history(prior))
        rs.community = {rule.identifier: rule.as_rule() for rule in rules}
        materialize_community_rules(rs)
    except Exception as exc:  # pragma: no cover - fail open at the tier boundary
        logger.debug("blackbox: community tier skipped: %s", exc)


def _node_environment(client: DkgClient) -> str:
    """This node's network id — what community signatures must be bound to."""
    try:
        return community.network_environment(client.status())
    except Exception as exc:  # node unreachable: treated as "cannot verify now"
        logger.debug("blackbox: node status unavailable for community verification: %s", exc)
        return ""


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
    """
    for identifier, rule in rs.community.items():
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
