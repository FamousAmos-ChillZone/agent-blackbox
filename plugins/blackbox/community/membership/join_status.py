"""Where this node stands with the community's graph, as the node's own listing says.

Split out of the membership module (2026-10-21) when it reached the 400-line alarm:
this is the read side the dashboard shows (connected or not); the membership
module keeps the state machine that subscribes and joins.

Public surface: :class:`JoinState`, :data:`JOIN_STATE_TEXT`, :func:`join_state_of`
(pure), :func:`read_join_state` (one listing read), and the pure listing reads
:func:`has_definition`, :func:`needs_join` and :func:`owns`.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

from ...kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)


def has_definition(entry: dict[str, object]) -> bool:
    """True when the node holds the graph's definition: its listing names an
    access policy. A node without it lists the graph with no policy (KI-295)."""
    return str(entry.get("accessPolicy") or "").strip().lower() in {"public", "private"}


class JoinState(Enum):
    """Where this node stands with the graph the community lives in, as its own listing says.

    JOINED — subscribed with the graph's definition in (it can read and post);
    AWAITING_DEFINITION — subscribed, the definition still on its way (the node
    logs "not authorized" meanwhile, KI-295);
    JOINING — not subscribed yet;
    UNKNOWN — the node could not be asked (never read as "not joined", LES-011).
    """

    JOINED = "joined"
    AWAITING_DEFINITION = "awaiting-definition"
    JOINING = "joining"
    UNKNOWN = "unknown"


#: One plain line per state, for the dashboard (no jargon, no ids).
JOIN_STATE_TEXT: dict[JoinState, str] = {
    JoinState.JOINED: "connected",
    JoinState.AWAITING_DEFINITION: "connecting — fetching the graph's definition",
    JoinState.JOINING: "connecting — subscribing to the graph",
    JoinState.UNKNOWN: "could not check the connection (local node not answering)",
}


def needs_join(entry: dict[str, object]) -> bool:
    """Pure: whether writing to the listed graph needs the owner's admission — private
    access, or a registered graph with a CURATED publish policy (the verified graph)."""
    on_chain = entry.get("onChain") if isinstance(entry.get("onChain"), dict) else {}
    return (str(entry.get("accessPolicy") or "") == "private"
            or str(on_chain.get("publishPolicy") or "").lower() == "curated")


def owns(address: str, graph: str) -> bool:
    """*address* owns *graph*: a registered graph's id is its owner's address, "/", its name."""
    owner, slash, _name = graph.partition("/")
    return bool(slash) and owner.lower() == address.lower()


def join_state_of(entry: Optional[dict[str, object]], *, listing_read: bool) -> JoinState:
    """Pure: the :class:`JoinState` of the node's listing row *entry* for the
    graph (None when the graph is not listed). *listing_read* False means the
    listing itself could not be read."""
    if not listing_read:
        return JoinState.UNKNOWN
    if entry is None or not entry.get("subscribed"):
        return JoinState.JOINING
    return JoinState.JOINED if has_definition(entry) else JoinState.AWAITING_DEFINITION


def read_join_state(client: DkgClient, graph: str) -> JoinState:
    """Ask the node once (its context-graph listing) where it stands with *graph*."""
    try:
        entries = client.context_graphs()
    except Exception as exc:   # could not tell (LES-011)
        logger.debug("blackbox: community join state unreadable: %s", exc)
        return JoinState.UNKNOWN
    entry = next((row for row in entries if str(row.get("id") or "") == graph), None)
    return join_state_of(entry, listing_read=True)
