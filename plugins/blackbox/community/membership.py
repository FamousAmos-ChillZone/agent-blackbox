"""Community-graph membership — subscribe and join at most once, on the node's word.

Before Refine R0 (KI-064/114) the ruleset subscribed to the community graph on
EVERY refresh and `blackbox sync` subscribed and sent a join request on every
run, with no check that the curator peer was not this node itself. Now one
object owns that state:

* subscribe only when the node itself does not list the graph as subscribed,
  and at most once per ``RETRY_SECONDS`` while it keeps saying no;
* send the join request at most once per process (a failed attempt may be
  retried after ``RETRY_SECONDS``), never to this node's own peer id, and never
  for a PUBLIC graph (D-040: public graphs have no membership step);
* connect to the graph OWNER (``community_graph_peer_id``, DHT-resolved) before
  the first subscribe — an unregistered public graph has no on-chain pointer,
  so a fresh node that is not connected to the owner gets "read authority
  unavailable" forever (KI-216, FIX-0039). A failed subscribe is retried after
  ``FAILED_SUBSCRIBE_RETRY_SECONDS``, not the long window.

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
from typing import Callable, Dict, Optional, Set, Tuple

from ..kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)


class CommunityMembership:
    """Subscription + join state for this process, guarded by one lock."""

    #: How long to wait before repeating a subscribe the node did not take,
    #: or a join request that failed.
    RETRY_SECONDS = 600.0
    #: A subscribe the node REFUSED (owner not reachable yet, chain hiccup) is
    #: retried this soon — a fresh install should not sit dark for ten minutes.
    FAILED_SUBSCRIBE_RETRY_SECONDS = 60.0

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
        owner_peer = str(getattr(cfg, "community_graph_peer_id", "") or "")
        entry = _graph_entry(client, graph)
        if not (entry and entry.get("subscribed")):
            if not self._due(self._last_subscribe, graph):
                return False, "subscribe attempted recently; waiting for the node"
            _connect_owner(client, owner_peer)
            try:
                client.subscribe_context_graph(graph, include_shared_memory=True)
            except Exception as exc:
                logger.info("blackbox: community subscribe failed (retry in %ds): %s",
                            int(self.FAILED_SUBSCRIBE_RETRY_SECONDS), exc)
                self._retry_sooner(self._last_subscribe, graph)
                return False, f"subscribe failed: {exc}"
        if entry and str(entry.get("accessPolicy") or "") == "public":
            return True, "subscribed"   # D-040: a public graph has no join step
        self._join_once(client, graph, owner_peer)
        return True, "subscribed"

    def _retry_sooner(self, last: Dict[str, float], graph: str) -> None:
        """Pull the next attempt forward to ``FAILED_SUBSCRIBE_RETRY_SECONDS`` from now."""
        with self._lock:
            last[graph] = self._clock() - (self.RETRY_SECONDS - self.FAILED_SUBSCRIBE_RETRY_SECONDS)

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


def _graph_entry(client: DkgClient, graph: str) -> Optional[Dict[str, object]]:
    """The node's own listing row for *graph* (``subscribed``, ``accessPolicy``…), or None."""
    try:
        entries = client.context_graphs()
    except Exception as exc:  # cannot tell -> treat as not subscribed (gated by the retry window)
        logger.debug("blackbox: subscription probe failed: %s", exc)
        return None
    for entry in entries:
        if str(entry.get("id") or "") == graph:
            return entry
    return None


def _connect_owner(client: DkgClient, owner_peer: str) -> None:
    """Dial the graph owner by peer id (DHT-resolved) so the subscribe can find
    the read authority. Fail-open: a failed dial is logged, the subscribe still runs."""
    connect = getattr(client, "connect_peer", None)
    if not owner_peer or not callable(connect):
        return
    try:
        connect(owner_peer)
    except Exception as exc:
        logger.info("blackbox: could not reach the community graph owner %s: %s", owner_peer, exc)


#: The process's membership state (see module docstring).
MEMBERSHIP = CommunityMembership()


def ensure_community_subscription(client: DkgClient, cfg: object) -> Tuple[bool, str]:
    """Subscribe/join this node to the community graph — at most once, never
    to itself, only when the node says it is not subscribed (KI-064/114)."""
    return MEMBERSHIP.ensure(client, cfg)
