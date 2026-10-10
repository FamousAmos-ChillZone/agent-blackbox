"""Paged reads of the verified graph from the local DKG node.

Verified partitions are read one asset at a time as plain triples, cached
per asset (:mod:`.partitions`, KI-288/KI-289); the root data graph and
other views are cursor-paged in lanes here. Also row de-duplication. Returns
raw rows (or ``None`` on failure); turning rows into rules is
:mod:`.compiler`'s job.

Usage: ``rows = fetching.fetch_tier(client, context_graph_id, view)`` (called
by :mod:`.refresh_cycle` and the dashboard; tests patch it here).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple
from ..kernel import constants
from ..kernel.dkg_client import DkgClient, extract_binding
from ..kernel import sparql_text
from . import graph_queries, partitions

logger = logging.getLogger(__name__)

# Rows fetched per page when syncing a tier. One SPARQL round-trip each.
_PAGE_SIZE = 5000


_QUERY_ERROR = object()  # sentinel: distinguishes a tier failure from an empty tier


@dataclass(frozen=True)
class PartitionListing:
    """What the node's ``_meta`` says about the verified graph's assets.

    ``graphs`` — every VM assertion graph listed (any status); ``confirmed`` —
    the owner-pinned, on-chain-confirmed ones, sorted: the only graphs a
    public rule may come from.
    """

    graphs: FrozenSet[str]
    confirmed: Tuple[str, ...]


def confirmed_partitions(client: DkgClient, cg_id: str) -> Optional[PartitionListing]:
    """List the verified graph's assertion graphs; None when the node could
    not be asked, or lists partitions but confirms none yet (a broad read then
    would promote tentative assets to public rules — keep the last-good tier)."""
    partition_query = graph_queries._verified_partitions_sparql(cg_id)
    if not partition_query:
        return None
    metadata = client.query(partition_query, cg_id, view=None, on_error=_QUERY_ERROR)
    if metadata is _QUERY_ERROR:
        return None
    vm_prefix = f"{graph_queries._context_graph_data_uri(cg_id)}/_verifiable_memory/"
    partition_metadata = [
        (graph, extract_binding(row.get("status")))
        for row in metadata
        if (graph := extract_binding(row.get("assertionGraph"))).startswith(vm_prefix)
        and graph != vm_prefix
        and not any(char in graph for char in graph_queries._FORBIDDEN_IRI_CHARS)
    ]
    graphs = frozenset(graph for graph, _status in partition_metadata)
    confirmed = tuple(sorted({graph for graph, status in partition_metadata if status == "confirmed"}))
    if graphs and not confirmed:
        return None
    return PartitionListing(graphs=graphs, confirmed=confirmed)


def fetch_tier(
    client: DkgClient,
    cg_id: str,
    view: str,
    agent_address: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Fully paginate one tier. Returns all rows, or ``None`` if the node errored.

    ``None`` (error) is distinct from ``[]`` (the tier is genuinely empty) so
    the caller can preserve a tier's last-good rules through a transient failure
    instead of wiping them.
    """
    if view == constants.VIEW_VERIFIABLE_MEMORY:
        listing = confirmed_partitions(client, cg_id)
        if listing is None:
            return None
        data_graph = graph_queries._context_graph_data_uri(cg_id)
        confirmed = listing.confirmed
        # One plain triple read per asset, each confirmed asset cached once read:
        # the joined five-asset query this replaces exceeded the node's 30 s store
        # deadline even on one asset, freezing the rules at the first asset
        # (KI-288/KI-289). An empty read with partitions pending means nothing
        # usable yet: keep the last-good tier.
        verified = partitions.verified_partition_rows(client, cg_id, confirmed)
        partitions.record_progress(cg_id, verified)
        if confirmed and verified.compiled == 0:
            return None
        root_rows = _fetch_paged_lanes(
            client,
            cg_id,
            lambda limit, after: (
                graph_queries._legacy_threats_sparql(limit, after, data_graph),
                *graph_queries._defender_threats_sparql(limit, after, data_graph),
            ),
            view=None,
        )
        if root_rows is None:
            return None
        if len(verified.rows) + len(root_rows) >= sparql_text.MAX_ROWS:
            return None
        return _dedupe_threat_rows([*verified.rows, *root_rows])

    return _fetch_paged_lanes(
        client,
        cg_id,
        lambda limit, after: (
            graph_queries._legacy_threats_sparql(limit, after),
            *graph_queries._defender_threats_sparql(limit, after),
        ),
        view=view,
        agent_address=agent_address,
    )


def _fetch_paged_lanes(
    client: DkgClient,
    cg_id: str,
    query_lanes: Callable[[int, str], tuple],
    *,
    view: Optional[str],
    agent_address: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Cursor-page every lane until an empty page; None when any page fails."""
    rows: List[Dict[str, Any]] = []
    lane_count = len(query_lanes(1, ""))
    for lane_index in range(lane_count):
        after = ""
        fetched_subjects = 0
        while fetched_subjects < sparql_text.MAX_ROWS:
            kwargs: Dict[str, Any] = {"view": view, "on_error": _QUERY_ERROR}
            if agent_address:
                kwargs["agent_address"] = agent_address
            query = query_lanes(_PAGE_SIZE, after)[lane_index]
            page = client.query(query, cg_id, **kwargs)
            if page is _QUERY_ERROR:
                return None
            rows.extend(page)
            page_subjects = list(
                dict.fromkeys(
                    subject
                    for row in page
                    if (subject := extract_binding(row.get("threat")))
                )
            )
            if not page_subjects:
                if page:
                    return None
                break
            next_cursor = page_subjects[-1]
            if next_cursor <= after:
                return None
            fetched_subjects += len(page_subjects)
            # Keep paging until an EMPTY page. A short page does NOT mean the
            # lane is exhausted: DKG daemons cap a response below the requested
            # LIMIT (measured on 10.0.19: 5,000 requested -> 1,000 returned),
            # and the old short-page break silently truncated every lane to its
            # first page (the KI-052 "one _PAGE_SIZE compiled" signature).
            after = next_cursor
    return rows


def _dedupe_threat_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Prefer confirmed partition rows when a migrated root repeats a threat."""
    result: List[Dict[str, Any]] = []
    seen: set = set()
    for row in rows:
        threat = extract_binding(row.get("threat"))
        if threat and threat in seen:
            continue
        if threat:
            seen.add(threat)
        result.append(row)
    return result
