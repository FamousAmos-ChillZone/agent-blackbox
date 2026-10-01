"""Community-graph agents — who has reported into the shared community graph.

Two different populations used to share the dashboard's "Connected agents"
strip: the agents THIS Blackbox protects (local, attached) and every reporter
seen in the community graph (other operators' nodes, reached only through the
DKG / sim layer). A remote reporter is not connected to this Blackbox, so the
API now serves them as a separate ``community_agents`` list and the UI renders
them in their own section.

Trust: ``g:reporter`` / ``g:framework`` are self-described payload fields
(LES-014) — display-only. Nothing here counts, weights or trusts them; the
caller sanitizes every string before it reaches a client.

Usage (inside the ``/api/agents`` route)::

    rows = client.query(REPORTERS_SPARQL, graph_id, view=..., on_error=None)
    reporters = parse_reporter_rows(rows)            # cached via _swr
    community = group_community_agents(reporters, local_address)
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, TypedDict

from ..kernel.dkg_client import extract_binding

# Report subjects grouped by (reporter, framework): one row per pair, with the
# number of report subjects that pair authored.
REPORTERS_SPARQL = (
    "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
    "SELECT ?reporter ?framework (COUNT(?r) AS ?n) WHERE { "
    "?r a g:ThreatReport . "
    "OPTIONAL { ?r g:reporter ?reporter } "
    "OPTIONAL { ?r g:framework ?framework } "
    "} GROUP BY ?reporter ?framework"
)


class ReporterRow(TypedDict):
    """One (reporter, framework) pair from the community graph."""

    address: str     # the self-described reporter address (display-only)
    framework: str   # lowercased; "unknown" when the report carried none
    count: int       # report subjects this pair authored


class CommunityAgent(TypedDict):
    """One reporter on the community graph, all its frameworks folded."""

    address: str
    frameworks: List[str]   # sorted, distinct
    reports: int            # summed over frameworks
    is_self: bool           # the address equals this node's wallet


def parse_reporter_rows(rows: Iterable[Mapping[str, Any]]) -> List[ReporterRow]:
    """Turn SPARQL bindings from :data:`REPORTERS_SPARQL` into typed rows.

    Rows without a reporter are skipped; a non-numeric count reads as 0.
    """
    reporters: List[ReporterRow] = []
    for row in rows:
        address = extract_binding(row.get("reporter"))
        if not address:
            continue
        framework = (extract_binding(row.get("framework")) or "").lower() or "unknown"
        try:
            count = int(extract_binding(row.get("n")) or "0")
        except (TypeError, ValueError):
            count = 0
        reporters.append({"address": str(address), "framework": framework, "count": count})
    return reporters


def group_community_agents(reporters: Iterable[ReporterRow], local_address: str) -> List[CommunityAgent]:
    """Fold reporter rows into one entry per address (case-insensitive).

    Ordered: this node first, then most reports, then address — stable across
    refreshes so the section does not reshuffle on every poll.
    """
    local = local_address.lower()
    by_address: Dict[str, CommunityAgent] = {}
    for rep in reporters:
        key = rep["address"].lower()
        agent = by_address.setdefault(
            key, {"address": rep["address"], "frameworks": [], "reports": 0, "is_self": bool(local) and key == local}
        )
        if rep["framework"] not in agent["frameworks"]:
            agent["frameworks"].append(rep["framework"])
        agent["reports"] += rep["count"]
    for agent in by_address.values():
        agent["frameworks"].sort()
    return sorted(by_address.values(), key=lambda a: (not a["is_self"], -a["reports"], a["address"].lower()))
