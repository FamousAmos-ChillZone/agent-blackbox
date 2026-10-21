"""Read the graph's ``sandbox`` lane: the test statements every member has shared there.

This is the only reader of the sandbox lane. Nothing it returns reaches the
rules, the community tier or any flag: those readers query the ``reports`` lane
by name (``kernel/dkg_client.query``), so a sandbox statement is invisible to
them by construction.

The query is bounded by construction (LES-013/040): it names the record kind
(``g:ThreatReport``), reads four small fields and carries a LIMIT.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Optional

from ..kernel import constants, identity
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient, DkgError, extract_binding

logger = logging.getLogger(__name__)

LANE_LIMIT = 200   # newest statements shown; the lane expires on its own after the 30-day shared-memory TTL

_LANE_SPARQL = f"""
PREFIX g: <{constants.BLACKBOX_ONTOLOGY}>
SELECT ?r ?identifier ?reporter ?severity WHERE {{
  ?r a g:ThreatReport ;
     g:identifier ?identifier ;
     g:reporter ?reporter ;
     g:severity ?severity .
}} ORDER BY DESC(?r) LIMIT {LANE_LIMIT}
"""


@dataclass(frozen=True)
class LaneEntry:
    """One test statement in the sandbox lane. ``mine`` marks this node's own.

    ``reporter`` is the address the statement names; the sandbox lane only
    proves connectivity, so it is shown, never counted or trusted.
    """

    identifier: str
    reporter: str
    severity: str
    mine: bool


@dataclass(frozen=True)
class LaneView:
    """The sandbox lane as the dashboard shows it. ``readable`` False = the node did not answer."""

    graph: str
    readable: bool
    entries: tuple[LaneEntry, ...]

    @property
    def agents(self) -> int:
        """Distinct reporters heard on the lane, this node included."""
        return len({entry.reporter.lower() for entry in self.entries})

    def to_dict(self) -> dict[str, Any]:
        return {"graph": self.graph, "readable": self.readable, "agents": self.agents,
                "entries": [asdict(entry) for entry in self.entries]}


def read_lane(cfg: BlackboxConfig, client: Optional[DkgClient] = None) -> LaneView:
    """Ask the local node for the sandbox lane of the community graph. Fail-open."""
    graph = cfg.context_graph_id
    try:
        client = client or DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
        failed = object()
        rows = client.query(_LANE_SPARQL, graph, view=constants.VIEW_SHARED_WORKING_MEMORY,
                            on_error=failed, sub_graph=constants.SANDBOX_SUB_GRAPH)
        if rows is failed:
            return LaneView(graph, False, ())
        own = (identity.reporter_address(client) or "").lower()
    except (DkgError, OSError, ValueError) as exc:   # the node is down or busy: say so, never guess
        logger.debug("blackbox: sandbox lane unreadable: %s", exc)
        return LaneView(graph, False, ())
    return LaneView(graph, True, tuple(_entry(row, own) for row in rows))


def _entry(row: dict[str, Any], own: str) -> LaneEntry:
    reporter = extract_binding(row.get("reporter"))
    return LaneEntry(identifier=extract_binding(row.get("identifier")), reporter=reporter,
                     severity=extract_binding(row.get("severity")), mine=bool(own) and reporter.lower() == own)
