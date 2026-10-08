"""When the dashboard's ruleset worker runs its first refresh (KI-205).

The installer performs an authoritative catch-up before it starts the
dashboard, so a dashboard that finds a compiled generation waits one full
``sync_interval`` before repeating that expensive transfer. A dashboard that
finds NOTHING compiled (a ``--skip-dkg`` install, a wiped home) must not sit
on "never compiled" for an hour: it refreshes after the short empty-ruleset
retry instead.

After each refresh the worker waits for whichever comes first: one full
``sync_interval`` from the start of that refresh, or the moment the compiled
ruleset itself asks to be refreshed. The ruleset carries that schedule in its
``synced_at`` (the refresh cycle moves it earlier while the verified graph is
still arriving or the ruleset came back empty, KI-288), so the worker and an
agent's own hooks follow ONE schedule instead of the worker sleeping an hour
behind a node that is still downloading the graph.

Usage::

    delay = sync_timing.initial_sync_delay(cfg, ruleset.peek(cfg), min_s, empty_retry_s)
    wait = sync_timing.next_sync_delay(cfg, ruleset.peek(cfg), elapsed_s, min_s)
"""

from __future__ import annotations

import time
from typing import Any


def initial_sync_delay(cfg: Any, cached: Any, min_retry_s: float, empty_retry_s: float) -> float:
    """Seconds the worker sleeps before its first refresh.

    Never compiled: the short empty-ruleset retry. Compiled: whatever the
    ruleset's own schedule asks for — a generation compiled just now waits one
    sync_interval as before, but one that asked for an early refresh (the
    verified graph still arriving, KI-288) gets it. Before, a dashboard
    (re)started after the installer compiled the first asset waited a full hour
    with the node still downloading (bench bb-ours, 2026-10-08: 1,000 rules
    for an hour while 100+ assets landed).
    """
    never_compiled = not float(getattr(cached, "synced_at", 0.0) or 0.0)
    if never_compiled:
        return max(min_retry_s, empty_retry_s)
    return next_sync_delay(cfg, cached, 0.0, min_retry_s)


def next_sync_delay(cfg: Any, cached: Any, elapsed_s: float, min_retry_s: float) -> float:
    """Seconds the worker sleeps after a refresh that took *elapsed_s*.

    *cached* is the ruleset that refresh left (``ruleset.peek(cfg)``); its
    ``synced_at`` + ``sync_interval`` is when it wants the next refresh.
    """
    interval = max(1.0, float(getattr(cfg, "sync_interval", 0) or 1))
    period_left = interval - elapsed_s
    synced_at = float(getattr(cached, "synced_at", 0.0) or 0.0)
    if synced_at:
        period_left = min(period_left, synced_at + interval - time.time())
    return max(min_retry_s, period_left)
