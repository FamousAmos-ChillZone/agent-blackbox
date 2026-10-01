"""Paged reads of the verified graph from the local DKG node.

Owns the paging discipline that survives DKG 10.0.19's 30 s store deadline
(KI-062): VM partition paging, verified-view lane fallback, retry/backoff
constants, and row de-duplication. Returns raw rows (or the ``_QUERY_ERROR``
sentinel); turning rows into rules is :mod:`.compiler`'s job.

Usage: ``rows = fetching.fetch_tier(client, context_graph_id, view)`` (called
by :mod:`.refresh_cycle` and the dashboard; tests patch it here).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional
from ..kernel import constants
from ..kernel.dkg_client import DkgClient, extract_binding
from ..kernel import sparql_text
from . import graph_queries

logger = logging.getLogger(__name__)

# Rows fetched per page when syncing a tier. One SPARQL round-trip each.
_PAGE_SIZE = 5000
# Public VM snapshots are stored in bounded, confirmed named graphs. Querying
# five partitions at a time keeps Blazegraph responses comfortably below the
# client timeout while avoiding the expensive all-VM deduplication rewrite.
_VM_PARTITION_BATCH_SIZE = 5
_VM_PARTITION_QUERY_TIMEOUT = 120.0
# DKG 10.0.19 enforces a 30s SERVER-side store deadline per query
# (STORE_OPERATION_TIMEOUT, retryable); the client timeout above is irrelevant
# to it. Under initial-sync insert load the partition query's ORDER BY forces a
# full scan of the batched graphs, so the deadline hits at ANY page size
# (measured live: LIMIT 50_000 down to 1_000 all killed at 30s — shrinking the
# LIMIT is not a lever for a sort-bound query). A killed query also flips the
# managed store into a short "recovering" window that rejects every immediate
# follow-up ("query was not started"). So the pager makes ONE full-size attempt
# plus one delayed retry, and the caller then falls back to the daemon's
# verified view, pausing first so the recovery window can clear (KI-062).
# Tests set the delay to 0.
_VM_PARTITION_RETRY_DELAY_S = 5.0
# The recovery window after back-to-back 30s kills outlasts the short retry
# delay (measured: lane queries that run in <1s on a calm store still failed
# 5s after the partition kills, and succeeded ~30s later), so the pre-lane
# pause gets its own, longer budget. Tests set it to 0.
_VM_FALLBACK_PAUSE_S = 30.0
#: Delayed retries per lane page (backoff multiplies by attempt).
_LANE_PAGE_RETRIES = 2


_QUERY_ERROR = object()  # sentinel: distinguishes a tier failure from an empty tier


def _fetch_vm_partition_rows(
    client: DkgClient, cg_id: str, partitions: List[str]
) -> Optional[List[Dict[str, Any]]]:
    """Page threat rows out of the confirmed VM partition graphs.

    KI-062: a page killed by the daemon's 30s server-side store deadline gets
    ONE delayed retry (a transient kill can be another query's recovery
    window); a second failure returns ``None`` immediately — the query is
    sort-bound, so smaller pages cannot help, and every extra attempt burns
    30s of store time and extends the recovery window that would then starve
    the caller's verified-view fallback too.
    """
    rows: List[Dict[str, Any]] = []
    for start in range(0, len(partitions), _VM_PARTITION_BATCH_SIZE):
        batch = partitions[start : start + _VM_PARTITION_BATCH_SIZE]
        offset = 0
        retried = False
        while len(rows) < sparql_text.MAX_ROWS:
            page = client.query(
                graph_queries._partition_threats_sparql(batch, offset=offset),
                cg_id,
                view=None,
                on_error=_QUERY_ERROR,
                timeout=_VM_PARTITION_QUERY_TIMEOUT,
            )
            if page is _QUERY_ERROR:
                if not retried:
                    retried = True
                    logger.debug("blackbox: partition page failed; one delayed retry")
                    if _VM_PARTITION_RETRY_DELAY_S > 0:
                        time.sleep(_VM_PARTITION_RETRY_DELAY_S)
                    continue  # retry the SAME page once
                return None  # store deadline is structural here: hand off
            rows.extend(page)
            if len(page) < graph_queries._VM_PARTITION_QUERY_LIMIT:
                break
            offset += len(page)
    return rows


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
        partition_query = graph_queries._verified_partitions_sparql(cg_id)
        if not partition_query:
            return None
        metadata = client.query(
            partition_query,
            cg_id,
            view=None,
            on_error=_QUERY_ERROR,
        )
        if metadata is _QUERY_ERROR:
            return None

        data_graph = graph_queries._context_graph_data_uri(cg_id)
        vm_prefix = f"{data_graph}/_verifiable_memory/"
        partition_metadata = [
            (graph, extract_binding(row.get("status")))
            for row in metadata
            if (graph := extract_binding(row.get("assertionGraph"))).startswith(vm_prefix)
            and graph != vm_prefix
            and not any(char in graph for char in graph_queries._FORBIDDEN_IRI_CHARS)
        ]
        partition_graphs = {graph for graph, _status in partition_metadata}
        partitions = sorted(
            {graph for graph, status in partition_metadata if status == "confirmed"}
        )
        # A broad VM query would union tentative assertion graphs and promote
        # them to public rules. Preserve the last-good tier until every graph
        # selected here is explicitly confirmed.
        if partition_graphs and not partitions:
            return None

        partition_rows = _fetch_vm_partition_rows(client, cg_id, partitions)
        if partition_rows is None or len(partition_rows) >= sparql_text.MAX_ROWS:
            # KI-062: the partition path was starved by the daemon's store
            # deadline / recovery window (heavy initial-sync insert load).
            # Fall back to cursor-paged lanes on the daemon's own
            # ``verifiable-memory`` view — the surface ``threat_count`` and the
            # dashboard already trust, which the daemon serves efficiently even
            # while the raw store is saturated. The daemon is the authority for
            # what that view contains, so verified-only semantics hold.
            logger.warning(
                "blackbox: VM partition read starved by store deadline; "
                "falling back to verified-view lanes"
            )
            # Let the store's post-kill recovery window clear before the lane
            # queries start, or they inherit the same "not started" rejections.
            if _VM_FALLBACK_PAUSE_S > 0:
                time.sleep(_VM_FALLBACK_PAUSE_S)
            fallback = _fetch_paged_lanes(
                client,
                cg_id,
                lambda limit, after: (
                    graph_queries._legacy_threats_sparql(limit, after),
                    *graph_queries._defender_threats_sparql(limit, after),
                ),
                view=constants.VIEW_VERIFIABLE_MEMORY,
                retry_delay_s=_VM_PARTITION_RETRY_DELAY_S,
                skip_failed_lanes=True,
            )
            if fallback is None or len(fallback) >= sparql_text.MAX_ROWS:
                return None
            return _dedupe_threat_rows(fallback)

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
        if len(partition_rows) + len(root_rows) >= sparql_text.MAX_ROWS:
            return None
        return _dedupe_threat_rows([*partition_rows, *root_rows])

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
    retry_delay_s: float = 0.0,
    skip_failed_lanes: bool = False,
) -> Optional[List[Dict[str, Any]]]:
    """Cursor-page every lane; see KI-062 for the retry/skip options.

    ``skip_failed_lanes`` trades completeness for availability: a lane that
    still fails after its retry is logged and SKIPPED instead of failing the
    whole fetch — used only by the VM verified-view fallback, where partial
    verified rules beat none (the partition path remains the completeness
    path). All lanes failing still returns ``None``.
    """
    rows: List[Dict[str, Any]] = []
    lane_count = len(query_lanes(1, ""))
    lanes_failed = 0
    for lane_index in range(lane_count):
        after = ""
        fetched_subjects = 0
        page_retries = 0
        lane_dead = False
        while fetched_subjects < sparql_text.MAX_ROWS:
            kwargs: Dict[str, Any] = {"view": view, "on_error": _QUERY_ERROR}
            if agent_address:
                kwargs["agent_address"] = agent_address
            query = query_lanes(_PAGE_SIZE, after)[lane_index]
            page = client.query(query, cg_id, **kwargs)
            if page is _QUERY_ERROR:
                if retry_delay_s > 0 and page_retries < _LANE_PAGE_RETRIES:
                    # Delayed retries per page: a long lane (tens of pages
                    # under sync load) WILL hit transient recovery windows;
                    # one hiccup must not kill the whole lane (KI-062).
                    page_retries += 1
                    time.sleep(retry_delay_s * page_retries)
                    continue
                if skip_failed_lanes:
                    logger.warning(
                        "blackbox: verified lane %d failed; continuing without it",
                        lane_index,
                    )
                    lanes_failed += 1
                    lane_dead = True
                    break
                return None
            page_retries = 0
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
        if lane_dead:
            continue
    if skip_failed_lanes and lanes_failed == lane_count:
        return None  # every lane failed: nothing real to offer
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
