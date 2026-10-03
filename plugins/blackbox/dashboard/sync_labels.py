"""Sync-state presentation for ``GET /api/graph-status`` (the ``sync_progress`` labels).

Three pure helpers, so the route body stays a wiring list:

* ``_sync_label("VM", state)`` → ``"VM syncing"`` — the verified tier's label.
* ``_community_progress(cfg, rs, count)`` → ``{"count", "state", "label"}`` — the community
  tier's whole ``sync_progress`` entry. Its state is independent of the VM catch-up: the
  community tier is live on its own (a pulse can change it with no VM sync at all).
"""

from __future__ import annotations

from typing import Any, Dict
_SYNC_LABEL_SUFFIX = {
    "ready": "synced",
    "syncing": "syncing",
    "unreachable": "offline",
    "empty": "empty",
    "incomplete": "incomplete",
    "pending-approval": "curator approval pending",
    "pending-encryption-profile": "waiting for workspace encryption profile",
    "joining": "joining private graph",
    "not-configured": "not configured",
    "not-subscribed": "not subscribed — run blackbox sync --wait",
    "paused": "paused by curators",
    "sync-envelope-error": "peer sync handshake malformed",
}

_COMMUNITY_PROGRESS_LABEL = {
    "not-configured": "Community graph not configured",
    "paused": "Community ingest paused by curators",
    "empty": "Community graph connected · no reports yet",
}


def _sync_label(tier: str, state: str) -> str:
    """Human label for a tier's sync state, e.g. ``"VM syncing"``."""
    return f"{tier} {_SYNC_LABEL_SUFFIX.get(state, state)}"


def _community_progress(cfg: Any, rs: Any, community: int) -> Dict[str, Any]:
    """The ``sync_progress.community`` entry of /api/graph-status: ``{count, state, label}``.
    Its state is independent of the VM catch-up — the community tier is live on its own."""
    if not getattr(cfg, "community_graph_id", ""):
        state = "not-configured"
    elif getattr(rs, "community_paused", False):
        state = "paused"
    else:
        state = "ready" if community else "empty"
    label = _COMMUNITY_PROGRESS_LABEL.get(state, f"Community graph live · {int(community or 0)} corroborated threats")
    return {"count": int(community or 0), "state": state, "label": label}



def not_subscribed_activity() -> Dict[str, Any]:
    """Sync-panel payload for a node with NO verified-graph subscription — says so,
    names the fix, and carries no clock (the pair showed '51 min elapsed' with nothing syncing)."""
    return {
        "status": "not-subscribed", "phase": "not-subscribed",
        "label": "Verified graph not subscribed",
        "detail": "This node is not subscribed to the verified threat graph — run `blackbox sync --wait` to join it. "
                  "Community reports still flow.",
        "started_at": None, "updated_at": None, "current": None, "expected": None,
        "percent": None, "indeterminate": True,
    }
