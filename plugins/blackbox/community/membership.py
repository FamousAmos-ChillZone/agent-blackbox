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
  ``FAILED_SUBSCRIBE_RETRY_SECONDS``, not the long window;
* keep the link to the owner alive: re-dial it every ``OWNER_LINK_SECONDS``
  whether or not the node is subscribed. Community reports reach a node over
  that link, and a node that lost it stayed "subscribed" while receiving
  nothing for hours (KI-297) — the DKG's sync-on-connect then replays what was
  missed;
* when the node is subscribed but its listing shows no access policy, the
  graph's public definition never arrived (it is served only by a peer that
  holds it, in practice the owner, and is fetched once, at subscribe time): the
  node can read but every post fails CONTEXT_GRAPH_NOT_FOUND (KI-295). Dial the
  owner and subscribe again, at most once per ``FAILED_SUBSCRIBE_RETRY_SECONDS``,
  until the definition is in.

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
    #: How often the live link to the graph owner is re-dialled (KI-297). A dial
    #: of a connected peer is a cheap no-op on the node; a dropped link costs at
    #: most this long plus the node's catch-up (169 s measured on the bench).
    OWNER_LINK_SECONDS = 120.0

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_subscribe: Dict[str, float] = {}
        self._last_join: Dict[str, float] = {}
        self._joined: Set[str] = set()
        #: graph -> when the node last confirmed it is subscribed; inside
        #: RETRY_SECONDS the listing is not re-read (the pulse calls every ~20 s).
        self._confirmed: Dict[str, float] = {}
        self._last_owner_dial: Dict[str, float] = {}
        self._own_peer = ""   # this node's peer id, once known (never dial ourselves)

    def ensure(self, client: DkgClient, cfg: object) -> Tuple[bool, str]:
        """Make sure this node is subscribed to (and has asked to join) the
        community graph. Fail-open: returns ``(ok, detail-for-logs)``."""
        graph = str(getattr(cfg, "community_graph_id", "") or "")
        if not graph:
            return False, "no community graph configured"
        owner_peer = str(getattr(cfg, "community_graph_peer_id", "") or "")
        dialled = self._keep_owner_link(client, owner_peer)
        if self._recently_confirmed(graph):
            return True, "subscribed"
        entry = _graph_entry(client, graph)
        if entry and entry.get("subscribed") and owner_peer and not _has_definition(entry):
            return self._fetch_definition(client, graph, owner_peer, dialled)
        if not (entry and entry.get("subscribed")):
            if not self._due(self._last_subscribe, graph):
                return False, "subscribe attempted recently; waiting for the node"
            if not dialled:
                _connect_owner(client, owner_peer)
            try:
                client.subscribe_context_graph(graph, include_shared_memory=True)
            except Exception as exc:
                logger.info("blackbox: community subscribe failed (retry in %ds): %s",
                            int(self.FAILED_SUBSCRIBE_RETRY_SECONDS), exc)
                self._retry_sooner(self._last_subscribe, graph)
                return False, f"subscribe failed: {exc}"
        # A join request is an OUTWARD action, so it fails closed: it is sent only
        # when the node's own listing says the graph is private. Before the first
        # subscribe the graph has no listing row at all — bench F sent a join to a
        # public graph through that gap (2026-10-03), so re-read after subscribing.
        entry = entry if entry and entry.get("subscribed") else _graph_entry(client, graph)
        if not owner_peer or (entry and _has_definition(entry)):
            with self._lock:   # confirmed only with the definition in (KI-295)
                self._confirmed[graph] = self._clock()
        else:
            self._retry_sooner(self._last_subscribe, graph)   # fetch the definition in a minute
        if not entry or str(entry.get("accessPolicy") or "") != "private":
            return True, "subscribed"   # D-040: a public (or unknown) graph has no join step
        self._join_once(client, graph, owner_peer)
        return True, "subscribed"

    def _keep_owner_link(self, client: DkgClient, owner_peer: str) -> bool:
        """Re-dial the graph owner every ``OWNER_LINK_SECONDS`` (KI-297); never
        this node itself. Returns True when it dialled on this call."""
        if not owner_peer or owner_peer == self._own_peer_id(client):
            return False
        if not self._due_after(self._last_owner_dial, owner_peer, self.OWNER_LINK_SECONDS):
            return False
        _connect_owner(client, owner_peer)
        return True

    def _fetch_definition(self, client: DkgClient, graph: str, owner_peer: str,
                          dialled: bool) -> Tuple[bool, str]:
        """Subscribed, but the graph's definition never arrived (KI-295): dial the
        owner and subscribe again, at most once per short window. Reads keep
        working meanwhile, so this still reports the node as subscribed."""
        if not self._due(self._last_subscribe, graph):
            return True, "subscribed; waiting for the graph definition from its owner"
        self._retry_sooner(self._last_subscribe, graph)   # look again in a minute, not ten
        if not dialled:
            _connect_owner(client, owner_peer)
        logger.info("blackbox: the community graph's definition is missing on this node "
                    "(posts would be refused); fetching it again from the owner")
        try:
            client.subscribe_context_graph(graph, include_shared_memory=True)
        except Exception as exc:
            logger.info("blackbox: community re-subscribe failed (retry in %ds): %s",
                        int(self.FAILED_SUBSCRIBE_RETRY_SECONDS), exc)
        return True, "subscribed; fetching the graph definition from its owner"

    def _own_peer_id(self, client: DkgClient) -> str:
        if not self._own_peer:
            try:
                self._own_peer = str((client.status() or {}).get("peerId") or "")
            except Exception:   # cannot tell yet: dial anyway (the node refuses a self-dial)
                return ""
        return self._own_peer

    def _due_after(self, last: Dict[str, float], key: str, window: float) -> bool:
        """Claim the next attempt for *key* if *window* seconds have passed."""
        now = self._clock()
        with self._lock:
            if key in last and now - last[key] < window:
                return False
            last[key] = now
            return True

    def _recently_confirmed(self, graph: str) -> bool:
        with self._lock:
            when = self._confirmed.get(graph)
        return when is not None and self._clock() - when < self.RETRY_SECONDS

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


def _has_definition(entry: Dict[str, object]) -> bool:
    """True when the node holds the graph's definition: its listing names an
    access policy. A node without it lists the graph with no policy (KI-295)."""
    return str(entry.get("accessPolicy") or "").strip().lower() in {"public", "private"}


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
