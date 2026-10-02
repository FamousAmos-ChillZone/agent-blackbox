"""The dashboard's community endpoints — community statistics and the reports board.

Registered by :func:`.server.create_app` through :func:`register_community_routes`.
Every count comes from ONE verified community read (R0d), which the server
hands in as *verified_reports* (stale-while-revalidate, never blocking a
request). Every community-authored string is served through
:func:`.safe_payloads.safe_text`. Split out of :mod:`.server`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, List

from .safe_payloads import safe_text, sanitized_ledger


@dataclass(frozen=True)
class CommunityEndpoints:
    """The registered handlers, for callers that warm caches by calling them."""

    community_stats: Callable[[], Any]
    reports: Callable[..., Any]


VerifiedReportsRead = Callable[[Any], List[Any]]


def community_stats_payload(verified_reports: VerifiedReportsRead) -> Any:
    """The launch instruments: contributing agents, corroboration, health."""
    from .. import community, ruleset
    from ..kernel.config import load_blackbox_config

    cfg = load_blackbox_config()
    rs = ruleset.peek(cfg)
    community_rules = getattr(rs, "community", {}) or {}
    now = time.time()
    corroborated = sum(1 for r in community_rules.values() if int(r.get("reporterCount") or 0) >= 2)
    # Reports-today from OUR ingest observations (KI-012), not
    # reporter-supplied timestamps.
    fresh_today = sum(
        1 for r in community_rules.values()
        if float(r.get("lastSeen") or 0) >= now - 86400
        and float(r.get("firstSeen") or 0) >= now - 86400
    )
    ledger = sanitized_ledger(1)
    stats = {
        "configured": bool(getattr(cfg, "community_graph_id", "")),
        "sharing_enabled": bool(getattr(cfg, "community_enabled", False)),
        "paused": bool(getattr(rs, "community_paused", False)),
        "community_threats": len(community_rules),
        "corroborated_2plus": corroborated,
        "new_today": fresh_today,
        "last_refresh": rs.synced_at or None,
        "last_share": ledger[0] if ledger else None,
        # distinct VERIFIED signers (R0d); None when no community graph is configured
        "contributing_agents": community.contributing_agent_count(verified_reports(cfg)) if cfg.community_graph_id else None,
    }

    return stats


def reports_payload(verified_reports: VerifiedReportsRead, limit: int) -> Any:
    """The community corroboration board + this node's outbound ledger."""
    from .. import community
    from ..kernel.config import load_blackbox_config

    # B7 (KI-006): the dead code lives — community corroboration board,
    # served from the COMMUNITY graph, plus this node's own outbound
    # ledger so 'what did I contribute' is one call.
    cfg = load_blackbox_config()
    if not getattr(cfg, "community_graph_id", ""):
        return {
            "reports": [],
            "sharing_enabled": bool(getattr(cfg, "community_enabled", False)),
            "outbound": sanitized_ledger(limit),
        }

    # Most-reported threats by distinct VERIFIED signers (R0d).
    board = [
        {"identifier": safe_text(t["identifier"]), "reporters": t["reporters"], "severity": safe_text(t["severity"], 16)}
        for t in community.most_reported_threats(verified_reports(cfg), limit)
    ]
    return {
        "reports": board,
        "sharing_enabled": bool(getattr(cfg, "community_enabled", False)),
        "outbound": sanitized_ledger(limit),
    }


def register_community_routes(app: Any, *, verified_reports: VerifiedReportsRead) -> CommunityEndpoints:
    """Add the community endpoints to *app* (a FastAPI app); returns their handlers."""
    from fastapi import Query

    @app.get("/api/community-stats")
    def community_stats() -> Any:
        return community_stats_payload(verified_reports)

    @app.get("/api/reports")
    def reports(limit: int = Query(50, ge=1, le=200)) -> Any:
        return reports_payload(verified_reports, limit)

    return CommunityEndpoints(community_stats=community_stats, reports=reports)
