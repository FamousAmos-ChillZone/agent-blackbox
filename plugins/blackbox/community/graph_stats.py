"""Graph-wide statistics over the community graph — the dashboard's read model.

Three aggregate questions the local dashboard asks of the community graph's
shared memory: how many distinct agents have reported, how many reports each
reporter authored (the "Community graph — connected agents" section), and
which threats the most distinct reporters named. The dashboard owns HTTP,
caching and sanitization; this module owns the SPARQL and turns bindings into
typed rows. Every string returned here is UNSANITIZED community data — the
caller escapes it before it reaches a client.

Trust: ``g:reporter`` / ``g:framework`` are self-described payload fields
(LES-014) — display-only. Nothing here weights or trusts them.

Usage (through the package)::

    from .. import community
    count = community.contributing_agent_count(client, cfg.community_graph_id)
    reporters = community.fetch_reporter_rows(client, cfg.community_graph_id)
    agents = community.group_community_agents(reporters or [], local_address)
    threats = community.most_reported_threats(client, cfg.community_graph_id, limit=50)
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, TypedDict

from ..kernel import constants
from ..kernel.dkg_client import DkgClient, extract_binding

_GUARDIAN_PREFIX = "PREFIX g: <http://umanitek.ai/ontology/guardian/> "

#: Distinct reporters across every report subject.
CONTRIBUTING_AGENTS_SPARQL = (
    _GUARDIAN_PREFIX
    + "SELECT (COUNT(DISTINCT ?rep) AS ?n) WHERE { "
    "?r a g:ThreatReport ; g:reporter ?rep }"
)

#: Report subjects grouped by (reporter, framework): one row per pair, with
#: the number of report subjects that pair authored.
REPORTERS_SPARQL = (
    _GUARDIAN_PREFIX
    + "SELECT ?reporter ?framework (COUNT(?r) AS ?n) WHERE { "
    "?r a g:ThreatReport . "
    "OPTIONAL { ?r g:reporter ?reporter } "
    "OPTIONAL { ?r g:framework ?framework } "
    "} GROUP BY ?reporter ?framework"
)


def _most_reported_sparql(limit: int) -> str:
    """Threat identifiers ranked by distinct reporters, ``limit`` rows."""
    return (
        _GUARDIAN_PREFIX
        + "SELECT ?identifier (COUNT(DISTINCT ?reporter) AS ?reporters) "
        "(SAMPLE(?severity) AS ?sev) WHERE { "
        "?r a g:ThreatReport . ?r g:identifier ?identifier . ?r g:reporter ?reporter . "
        "OPTIONAL { ?r g:severity ?severity . } } "
        f"GROUP BY ?identifier ORDER BY DESC(?reporters) LIMIT {int(limit)}"
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


class ReportedThreat(TypedDict):
    """One threat identifier and how many distinct agents reported it."""

    identifier: str
    reporters: int
    severity: str   # a sample of the reported severities; "info" when none


def contributing_agent_count(client: DkgClient, graph_id: str) -> Optional[int]:
    """Distinct reporters in the community graph, or None when the node did
    not answer. Raises ``ValueError`` on a non-numeric count."""
    rows = client.query(
        CONTRIBUTING_AGENTS_SPARQL, graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY, on_error=None
    )
    if not rows:
        return None
    return int(extract_binding(rows[0].get("n")) or 0)


def fetch_reporter_rows(client: DkgClient, graph_id: str) -> Optional[List[ReporterRow]]:
    """Per-(reporter, framework) report counts, or None when the node did not
    answer (so a cache keeps its last-good value)."""
    rows = client.query(REPORTERS_SPARQL, graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY, on_error=None)
    return None if rows is None else parse_reporter_rows(rows)


def most_reported_threats(client: DkgClient, graph_id: str, limit: int) -> List[ReportedThreat]:
    """The ``limit`` threats with the most distinct reporters ([] on failure).
    Raises ``ValueError`` on a non-numeric reporter count."""
    rows = client.query(
        _most_reported_sparql(limit), graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY, on_error=[]
    ) or []
    return [
        {
            "identifier": extract_binding(row.get("identifier")),
            "reporters": int(extract_binding(row.get("reporters")) or "0"),
            "severity": extract_binding(row.get("sev")) or "info",
        }
        for row in rows
    ]


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
