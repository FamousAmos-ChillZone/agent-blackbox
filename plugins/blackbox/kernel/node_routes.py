"""Node routes the curator uses that the hot path never does (Refine R6).

Thin, typed wrappers over the DKG node's HTTP API, all through the one HTTP
seam (:meth:`.dkg_client.DkgClient.request`). Route facts were read from the
node's own source on the bench (DKG 10.0.20, 2026-10-02):

* ``POST /api/knowledge-assets/{name}/vm/publish {contextGraphId}`` publishes
  an already-sealed KA to verifiable memory (on-chain; needs the publishing
  wallet funded — 200 confirmed, 207 minted but graph binding failed, 502 not
  confirmed).
* ``POST /api/chat {to, text, contextGraphId?}`` sends one private
  point-to-point message to a peer (name or peer id); ``GET /api/messages``
  with ``direction=in&order=asc&since=&sinceId=`` reads the inbox losslessly.
* ``POST /api/profile/query-catalog/write {contextGraphId, quads}`` saves
  immutable catalog entries in the ``prof:`` vocabulary;
  ``/read {contextGraphId}`` lists them.

Usage::

    from ..kernel import node_routes
    node_routes.publish_to_verified_memory(client, vm_graph, name, quads)
    node_routes.send_message(client, peer, text)
    for message in node_routes.inbox(client, since_id=last_seen): ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import quote, urlencode

from .dkg_client import DkgClient, Quad


@dataclass(frozen=True)
class InboxMessage:
    """One inbound message: ``id`` (the cursor), ``ts`` (sender-side epoch
    ms), ``peer`` (peer id), ``text``."""

    id: int
    ts: int
    peer: str
    text: str


def publish_to_verified_memory(client: DkgClient, graph: str, name: str, quads: List[Quad]) -> Dict[str, Any]:
    """Create + seal *quads* as KA *name*, then publish it to verifiable memory.

    Returns the node's publish result. Raises :class:`.dkg_client.DkgError` on
    any failure (a 502 "did not confirm" included): a promotion that did not
    confirm is NOT published, and the caller must say so.
    """
    client.write_private_knowledge_asset(graph, name, quads)
    return client.request("POST", f"/api/knowledge-assets/{quote(name, safe='')}/vm/publish", {"contextGraphId": graph})


def send_message(client: DkgClient, peer: str, text: str, graph: str = "") -> Dict[str, Any]:
    """Send one private message to *peer*; returns the node's delivery result."""
    body: Dict[str, Any] = {"to": peer, "text": text}
    if graph:
        body["contextGraphId"] = graph
    return client.request("POST", "/api/chat", body)


def inbox(client: DkgClient, *, since_id: int = 0, since: int = 0, limit: int = 100) -> List[InboxMessage]:
    """Inbound messages after the compound cursor (*since*, *since_id*),
    oldest first — the lossless pagination the node documents."""
    query = urlencode({"direction": "in", "order": "asc", "limit": limit, "since": since, "sinceId": since_id})
    result = client.request("GET", f"/api/messages?{query}", None)
    rows = result.get("messages") if isinstance(result, dict) else result
    out: List[InboxMessage] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            out.append(InboxMessage(id=int(row.get("id") or 0), ts=int(row.get("ts") or 0),
                                    peer=str(row.get("peer") or ""), text=str(row.get("text") or "")))
        except (TypeError, ValueError):
            continue
    return out


def write_query_catalog(client: DkgClient, graph: str, quads: List[Quad]) -> Dict[str, Any]:
    """Save immutable saved-query catalog entries for *graph*."""
    return client.request("POST", "/api/profile/query-catalog/write", {"contextGraphId": graph, "quads": quads})


def read_query_catalog(client: DkgClient, graph: str) -> Dict[str, Any]:
    """The saved-query catalog of *graph*, as the node returns it."""
    return client.request("POST", "/api/profile/query-catalog/read", {"contextGraphId": graph})

