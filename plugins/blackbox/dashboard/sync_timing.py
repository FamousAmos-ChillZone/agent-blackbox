"""When the dashboard's ruleset worker runs its first refresh (KI-205).

The installer performs an authoritative catch-up before it starts the
dashboard, so a dashboard that finds a compiled generation waits one full
``sync_interval`` before repeating that expensive transfer. A dashboard that
finds NOTHING compiled (a ``--skip-dkg`` install, a wiped home) must not sit
on "never compiled" for an hour: it refreshes after the short empty-ruleset
retry instead.

Usage: ``delay = sync_timing.initial_sync_delay(cfg, ruleset.peek(cfg), min_s, empty_retry_s)``
"""

from __future__ import annotations

from typing import Any


def initial_sync_delay(cfg: Any, cached: Any, min_retry_s: float, empty_retry_s: float) -> float:
    """Seconds the worker sleeps before its first refresh."""
    never_compiled = not float(getattr(cached, "synced_at", 0.0) or 0.0)
    if never_compiled:
        return max(min_retry_s, empty_retry_s)
    return max(min_retry_s, float(getattr(cfg, "sync_interval", 0) or empty_retry_s))
