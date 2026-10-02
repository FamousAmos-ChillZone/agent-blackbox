"""The dashboard's community endpoints — statistics, the reports board, statements.

Registered by :func:`.server.create_app` through :func:`register_community_routes`.
Everything comes from ONE verified community read (R0d), which the server
hands in as *community_read* (the cached :class:`..community.CommunityRead`,
stale-while-revalidate, never blocking a request). Every community-authored
string is served through :func:`.safe_payloads.safe_text`.

* ``GET /api/community-stats`` — contributing agents, corroboration, health.
* ``GET /api/reports`` — the corroboration board + this node's outbound ledger.
* ``GET /api/community-statements`` — Refine R2: every statement the reader
  honoured, with who / when / why: disputes, curator verdicts, counted
  authors, backlog and away notices, held-back and pending counts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

from .safe_payloads import safe_text, sanitized_ledger


@dataclass(frozen=True)
class CommunityEndpoints:
    """The registered handlers, for callers that warm caches by calling them."""

    community_stats: Callable[[], Any]
    reports: Callable[..., Any]


VerifiedReportsRead = Callable[[Any], List[Any]]
#: The server's cached community read: cfg -> CommunityRead, or None before the first lands.
CommunityReadSource = Callable[[Any], Any]
#: Most rows of each statement kind one response carries.
_MAX_ROWS = 200


def own_reporter_author() -> str:
    """This node's signer key, or "" before it has ever signed a report."""
    from ..kernel import reporter_key

    store = reporter_key.ReporterKeyStore()
    try:
        return store.public_key_hex() if store.path.exists() else ""
    except reporter_key.ReporterKeyError:
        return ""


def _reports_of(community_read: CommunityReadSource) -> VerifiedReportsRead:
    def verified_reports(cfg: Any) -> List[Any]:
        read = community_read(cfg)
        return list(read.reports) if read is not None else []
    return verified_reports


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


def community_statements_payload(community_read: CommunityReadSource) -> Dict[str, Any]:
    """Refine R2: the statements the reader honoured, with who / when / why."""
    from ..kernel.config import load_blackbox_config

    cfg = load_blackbox_config()
    if not getattr(cfg, "community_graph_id", ""):
        return {"configured": False}
    read = community_read(cfg)
    if read is None:
        return {"configured": True, "available": False}
    return {
        "configured": True,
        "available": True,
        "disputes": [{"identifier": safe_text(d.identifier), "who": safe_text(d.reporter, 64),
                      "signer": safe_text(d.author[:16], 16), "when": safe_text(d.day, 16),
                      "why": safe_text(d.reason, 32)} for d in read.disputes[:_MAX_ROWS]],
        "retractions": [{"identifier": safe_text(r.identifier), "who": safe_text(r.reporter, 64),
                         "signer": safe_text(r.author[:16], 16), "when": safe_text(r.day, 16)}
                        for r in read.retractions[:_MAX_ROWS]],
        "held_back": int(read.held_back),
        "pending_tombstones": int(read.pending_tombstones),
        "curator": _curator_payload(read.curator),
    }


def _curator_payload(view: Any) -> Dict[str, Any]:
    if view.manifest is None:
        return {"trusted": False}
    manifest = view.manifest
    return {
        "trusted": True,
        "manifest": {"root_epoch": manifest.root_epoch, "version": manifest.version,
                     "keys": len(manifest.curator_keys), "threshold": manifest.threshold},
        "verdicts": [{"identifier": safe_text(identifier), "verdict": record.kind.value.split(".", 1)[1],
                      "when": safe_text(record.day, 16), "why": safe_text(record.field("reason"), 32),
                      "keys": len(record.signers)} for identifier, record in list(view.verdicts.items())[:_MAX_ROWS]],
        "counted_authors": [{"address": safe_text(a.address, 64), "class": a.author_class, "org": safe_text(a.org, 64),
                             "expires": a.expires} for a in list(view.counted.values())[:_MAX_ROWS]],
        "backlog": ({"lanes": safe_text(view.backlog.field("lanes"), 16), "until": safe_text(view.backlog.field("until"), 16)}
                    if view.backlog else None),
        "away": [{"key": safe_text(r.field("key")[:16], 16), "from": safe_text(r.field("from"), 16),
                  "until": safe_text(r.field("until"), 16)} for r in view.away[:_MAX_ROWS]],
    }


def register_community_routes(app: Any, *, community_read: CommunityReadSource) -> CommunityEndpoints:
    """Add the community endpoints to *app* (a FastAPI app); returns their handlers."""
    from fastapi import Query

    verified_reports = _reports_of(community_read)

    @app.get("/api/community-stats")
    def community_stats() -> Any:
        return community_stats_payload(verified_reports)

    @app.get("/api/reports")
    def reports(limit: int = Query(50, ge=1, le=200)) -> Any:
        return reports_payload(verified_reports, limit)

    @app.get("/api/community-statements")
    def community_statements() -> Any:
        return community_statements_payload(community_read)

    return CommunityEndpoints(community_stats=community_stats, reports=reports)
