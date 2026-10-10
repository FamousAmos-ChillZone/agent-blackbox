"""The dashboard's graph pages: how a tier's threats become one page.

Lifted out of ``server.py`` (at its size alarm) as pure functions, so the
``/api/graph`` and ``/api/threat`` handlers stay thin:

* :func:`_graph_entries` — a ruleset's threats of one source, in graph-entry shape.
* :func:`_balanced_graph_entries` — the front page shows a sample of every category.
* :func:`tier_response` — the page dict (totals describe the whole filtered result).
* :func:`compiled_rule` — the compiled rule / entry behind one identifier.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _graph_entries(rs: Any, source: str) -> List[Dict[str, Any]]:
    getter = getattr(rs, "graph_entries", None)
    if callable(getter):
        entries = getter(source) or []
        return entries if isinstance(entries, list) else list(entries)
    return [
        {
            "identifier": rule.get("identifier"),
            "category": category,
            "severity": str(rule.get("severity") or "info").lower(),
            "name": rule.get("name") or "",
            "subject": rule.get("subject") or "",
            "source": source,
        }
        for category, rule in rs.iter_rules()
        if rule.get("source") == source
    ]


def _balanced_graph_entries(
    entries: List[Dict[str, Any]], minimum_per_category: int = 24
) -> List[Dict[str, Any]]:
    """Front-load a small sample of every populated threat category."""
    category_order = (
        "dependency", "injection", "escalation", "fileaccess",
        "skill", "secret", "ioc", "other",
    )
    buckets: Dict[str, List[Dict[str, Any]]] = {key: [] for key in category_order}
    for entry in entries:
        key = str(entry.get("category") or "other").lower()
        buckets.setdefault(key, []).append(entry)

    front: List[Dict[str, Any]] = []
    skipped: Dict[str, int] = {}
    ordered_keys = category_order + tuple(k for k in buckets if k not in category_order)
    for key in ordered_keys:
        skipped[key] = min(len(buckets.get(key, [])), minimum_per_category)
    for index in range(minimum_per_category):
        for key in ordered_keys:
            bucket = buckets.get(key, [])
            if index < len(bucket):
                front.append(bucket[index])

    rest: List[Dict[str, Any]] = []
    consumed: Dict[str, int] = {}
    for entry in entries:
        key = str(entry.get("category") or "other").lower()
        used = consumed.get(key, 0)
        if used < skipped.get(key, 0):
            consumed[key] = used + 1
            continue
        rest.append(entry)
    return front + rest


def tier_response(tier: str, all_threats: List[Dict[str, Any]], offset: int, limit: int) -> Dict[str, Any]:
    """One page of *all_threats* (already filtered) with totals for the WHOLE result.

    Counts describe the complete filtered result, never the rendered page, so the
    dashboard can show the real threat magnitude on category / ecosystem hubs
    while progressively loading leaves.
    """
    category_totals: Dict[str, int] = {}
    ecosystem_totals: Dict[str, int] = {}
    for item in all_threats:
        item_category = str(item.get("category") or "other").lower()
        category_totals[item_category] = category_totals.get(item_category, 0) + 1
        if item_category == "dependency":
            parts = str(item.get("identifier") or "").split(":")
            ecosystem_name = (parts[1] if len(parts) > 1 else "other").lower()
            ecosystem_totals[ecosystem_name] = ecosystem_totals.get(ecosystem_name, 0) + 1
    return {
        "tier": tier,
        "threats": all_threats[offset:offset + limit],
        "total": len(all_threats),
        "category_totals": category_totals,
        "ecosystem_totals": ecosystem_totals,
        "offset": offset,
        "limit": limit,
        "partial": offset + limit < len(all_threats),
    }


def compiled_rule(rs: Any, tier: str, identifier: str) -> Dict[str, Any]:
    """The compiled rule of *tier* with this *identifier*, else its graph entry, else {}."""
    try:
        for _cat, rule in rs.iter_rules():
            if rule.get("source") == tier and rule.get("identifier") == identifier:
                return rule
    except Exception:
        pass
    try:
        return next(item for item in _graph_entries(rs, tier) if item.get("identifier") == identifier)
    except Exception:
        return {}
