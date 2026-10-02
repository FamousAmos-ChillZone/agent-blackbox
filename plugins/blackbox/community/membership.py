"""Community-graph membership — subscribe and join at most once, on the node's word.

Before Refine R0 (KI-064/114) the ruleset subscribed to the community graph on
EVERY refresh and `blackbox sync` subscribed and sent a join request on every
run, with no check that the curator peer was not this node itself. Now one
object owns that state:

* subscribe only when the node itself does not list the graph as subscribed,
  and at most once per ``RETRY_SECONDS`` while it keeps saying no;
* send the join request at most once per process (a failed attempt may be
  retried after ``RETRY_SECONDS``), and never to this node's own peer id.

Pattern: a single owner of mutable state with one lock, exposed as the
module-level :data:`MEMBERSHIP` (Global Object — the state is per process by
nature, like the node it talks to).

Usage::

    ok, detail = community.ensure_community_subscription(client, cfg)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, Set, Tuple

from ..kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)


class CommunityMembership:
    """Subscription + join state for this process, guarded by one lock."""

    #: How long to wait before repeating a subscribe the node did not take,
    #: or a join request that failed.
    RETRY_SECONDS = 600.0

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_subscribe: Dict[str, float] = {}
        self._last_join: Dict[str, float] = {}
        self._joined: Set[str] = set()

    def ensure(self, client: DkgClient, cfg: object) -> Tuple[bool, str]:
        """Make sure this node is subscribed to (and has asked to join) the
        community graph. Fail-open: returns ``(ok, detail-for-logs)``."""
        graph = str(getattr(cfg, "community_graph_id", "") or "")
        if not graph:
            return False, "no community graph configured"
        if not _node_says_subscribed(client, graph):
            if not self._due(self._last_subscribe, graph):
                return False, "subscribe attempted recently; waiting for the node"
            try:
                client.subscribe_context_graph(graph, include_shared_memory=True)
            except Exception as exc:
                logger.debug("blackbox: community subscribe failed: %s", exc)
                return False, f"subscribe failed: {exc}"
        self._join_once(client, graph, str(getattr(cfg, "community_graph_peer_id", "") or ""))
        return True, "subscribed"

    def _due(self, last: Dict[str, float], graph: str) -> bool:
        """Claim the next attempt for *graph* if the retry window has passed."""
        now = self._clock()
        with self._lock:
            if graph in last and now - last[graph] < self.RETRY_SECONDS:
                return False
            last[graph] = now
            return True

    def _join_once(self, client: DkgClient, graph: str, curator_peer: str) -> None:
        if not curator_peer or graph in self._joined:
            return
        try:
            own_peer = str((client.status() or {}).get("peerId") or "")
        except Exception:
            own_peer = ""
        if own_peer and own_peer == curator_peer:
            self._joined.add(graph)   # we ARE the curator: never ask ourselves to join
            return
        if not self._due(self._last_join, graph):
            return
        try:
            client.request_join(graph, curator_peer)
        except Exception as exc:  # best effort; retried after the window
            logger.debug("blackbox: community join request failed: %s", exc)
            return
        with self._lock:
            self._joined.add(graph)


def _node_says_subscribed(client: DkgClient, graph: str) -> bool:
    """The node's own word: is *graph* in its subscription list?"""
    try:
        entries = client.context_graphs()
    except Exception as exc:  # cannot tell -> treat as not subscribed (gated by the retry window)
        logger.debug("blackbox: subscription probe failed: %s", exc)
        return False
    return any(str(e.get("id") or "") == graph and bool(e.get("subscribed")) for e in entries)


#: The process's membership state (see module docstring).
MEMBERSHIP = CommunityMembership()


def ensure_community_subscription(client: DkgClient, cfg: object) -> Tuple[bool, str]:
    """Subscribe/join this node to the community graph — at most once, never
    to itself, only when the node says it is not subscribed (KI-064/114)."""
    return MEMBERSHIP.ensure(client, cfg)
