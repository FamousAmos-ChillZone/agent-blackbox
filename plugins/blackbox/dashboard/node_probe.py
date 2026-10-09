"""One probe of the DKG node for ``GET /api/graph-status`` (cached by the route's SWR wrapper).

``node_sync_probe(cfg, reachable=...)`` → ``None`` when the node is down, else
``{"node_reachable": True, "catchup": <job dict>, "subscribed": True|False|None}``:
the verified graph's catch-up job and whether the node even LISTS that graph as
subscribed. ``subscribed`` is ``None`` when the listing could not be read —
unknown is not "no" (KI-215: the pair's panel counted "51 min elapsed" on a
graph the node never followed).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..kernel.dkg_client import DkgClient


def node_sync_probe(cfg: Any, *, reachable: bool) -> Optional[Dict[str, Any]]:
    if not reachable:
        return None
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    try:
        catchup = client.catchup_status(cfg.context_graph_id)
    except Exception:
        catchup = {}   # no job is normal on an already-settled node
    try:
        entries = client.context_graphs()
        subscribed: Optional[bool] = any(
            str(e.get("id") or "") == cfg.context_graph_id and bool(e.get("subscribed")) for e in entries
        )
    except Exception:
        subscribed = None
    return {"node_reachable": True, "catchup": catchup, "subscribed": subscribed}
