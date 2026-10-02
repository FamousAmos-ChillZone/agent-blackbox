"""The community pulse beat (R16): between full refreshes, retry refused shares
and re-apply the community tier when the community graph changed.

The probe itself (``community.PULSE``) only answers "did the graph change?";
this module owns the BEAT — spawning at most one background thread, at most
every ``config.community_poll_interval`` seconds (0 disables) — and the
write-through onto the cached generation (disk + memory, under the refresh
lock, so every process picks it up on its next call). Called from
``refresh_cycle.get`` (every hook) and by the dashboard's health poll.

Usage: ``ruleset.pulse(cfg)`` → True when a probe was started.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from .. import community
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient
from . import community_tier, disk_cache, locks

logger = logging.getLogger(__name__)

_pulsing = False
_pulsing_lock = threading.Lock()  # guards the spawn-one-background-pulse flag


def pulse(config: Optional[BlackboxConfig] = None) -> bool:
    """Start the beat if it is due; never blocks; returns whether a probe started."""
    global _pulsing
    config = config or load_blackbox_config()
    interval = float(getattr(config, "community_poll_interval", 0) or 0)
    if interval <= 0 or not config.community_graph_id or not community.PULSE.due(interval):
        return False
    with _pulsing_lock:
        if _pulsing:
            return False
        _pulsing = True
    try:
        threading.Thread(target=_background_pulse, args=(config,), name="blackbox-pulse", daemon=True).start()
    except Exception:  # pragma: no cover
        with _pulsing_lock:
            _pulsing = False
        return False
    return True


def _background_pulse(config: BlackboxConfig) -> None:
    global _pulsing
    try:
        from . import refresh_cycle   # lazy: refresh_cycle imports this module

        client = DkgClient(url=config.dkg_url, dkg_home=config.dkg_home)
        refresh_cycle._retry_shares(client, config)
        if community.PULSE.changed(client, config):
            _reapply_community(config, client)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: community pulse failed: %s", exc)
    finally:
        with _pulsing_lock:
            _pulsing = False


def _reapply_community(config: BlackboxConfig, client: DkgClient) -> None:
    """Re-read the community tier onto the cached generation and write it
    through (disk + memory), so every process picks it up on its next call.
    Skipped when a full refresh holds the lock — it will read everything."""
    from . import refresh_cycle   # lazy: refresh_cycle imports this module

    with locks._ruleset_refresh_lock(blocking=False) as held:
        if not held:
            return
        rs = refresh_cycle.peek(config)
        community_tier.reapply_community_tier(rs, client, config)
        disk_cache._write_cache(rs)
        refresh_cycle._memory.store(rs)
        logger.info("blackbox: community tier re-applied on pulse (%d community rule(s))", len(rs.community))
