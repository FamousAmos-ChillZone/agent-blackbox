"""The graphs a sync keeps subscribed BESIDE the configured verified graph.

* the community graph (B4) — idempotent, fail-open, never blocks or fails the
  verified-graph transfer;
* the verified graph's successor (T2) — when a root-signed graph migration is
  in effect (:func:`community.active_verified_graph`), the node subscribes to
  the successor graph as well. The configured graph KEEPS its own subscription
  (requested by the catch-up in :mod:`.command`): its legacy assets stay
  readable there, and the successor only adds new rows.

Usage::

    side_subscriptions.ensure_side_subscriptions(client, cfg)   # before the verified subscription
"""

from __future__ import annotations

import logging
from typing import Tuple

from .. import community
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)


def ensure_side_subscriptions(client: DkgClient, cfg: BlackboxConfig) -> Tuple[str, ...]:
    """Subscribe the community graph and, when one is active, the successor of
    the verified graph. Returns the successor graphs a subscription was
    requested for (empty when none is active or the request failed). Fail-open."""
    if cfg.community_graph_id:
        community.ensure_community_subscription(client, cfg)
    successor = community.active_verified_graph(client, cfg).successor
    if not successor:
        return ()
    try:
        client.subscribe_context_graph(successor)
    except Exception as exc:  # fail-open: the next sync asks again
        logger.warning("blackbox: could not subscribe to the successor graph %s (%s)", successor, exc)
        return ()
    print(f"Subscribed to successor graph {successor}; {cfg.context_graph_id} stays subscribed for its legacy assets.")
    return (successor,)
