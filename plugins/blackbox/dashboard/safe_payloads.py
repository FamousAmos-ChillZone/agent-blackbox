"""Making community- and graph-derived values safe to serve (the dashboard's one sanitizer).

:func:`safe_text` is THE sanitization for every community-authored string an
endpoint serves (LES-001/002); :func:`sanitized_ledger` serves this node's
outbound share ledger through it. Split out of :mod:`.server` so the route
modules can use it without importing the server.
"""

from __future__ import annotations

from typing import Any, Dict, List


def safe_text(value: Any, limit: int = 256) -> str:
    """Sanitize a community/graph-derived string for any client payload.

    THE one sanitization implementation for the dashboard (the escaping twin
    of audit's redaction discipline, per LES-001/002): HTML-escaped so a
    hostile report can never smuggle markup to a renderer, control
    characters stripped so it can't drive a terminal, length clamped so it
    can't blow up a layout or a log. Every community-authored value served
    by any endpoint passes through here.
    """
    import html as _html

    text = str(value or "")
    cleaned = "".join(ch for ch in text if ch.isprintable())
    return _html.escape(cleaned[:limit], quote=True)


def sanitized_ledger(limit: int = 50) -> List[Dict[str, Any]]:
    """This node's outbound reports ledger, sanitized for serving."""
    from .. import audit as _audit

    rows = []
    try:
        for row in _audit.read_share_ledger(limit=limit):
            rows.append({
                "ts": safe_text(row.get("ts"), 32),
                "identifier": safe_text(row.get("identifier")),
                "category": safe_text(row.get("category"), 32),
                "severity": safe_text(row.get("severity"), 16),
                "ok": bool(row.get("ok")),
                "outcome": safe_text(row.get("outcome") or ("accepted" if row.get("ok") else "failed"), 32),
            })
    except Exception:  # pragma: no cover - fail open
        return []
    return rows
