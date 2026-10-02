"""Epoch naming for keep-alive copies (R5) — pure.

Shared memory expires per node (30 days by default on DKG 10.0.20, measured
2026-10-02), a shared-memory-only asset never bumps its version, and peers
refuse a same-name re-share (KI-103) — so keeping a report alive means its
author publishes a NEW asset, named for the current epoch, carrying the same
signed statement. Readers fold the copies back to one by subject (KI-207).

The epoch is a fixed-width window of the wall clock: ``epoch_days`` wide
(plan §08: TTL / 3, ten days at the default expiry). Every window gets at
most one copy per report, so the oldest live copy on any peer is never more
than one window older than the newest — well inside the expiry.

Usage::

    epoch = current_epoch(time.time(), cfg.community_keepalive_epoch_days)
    asset = copy_name("report-1a2b…", epoch)      # "report-1a2b…-e1736"
"""

from __future__ import annotations

from typing import NewType

#: A keep-alive window index (how many ``epoch_days`` windows since the Unix epoch).
Epoch = NewType("Epoch", int)

#: Default window: a third of the default 30-day shared-memory expiry.
DEFAULT_EPOCH_DAYS = 10.0
_DAY_SECONDS = 86_400.0


def current_epoch(now: float, epoch_days: float) -> Epoch:
    """The window *now* falls in; ``Epoch(0)`` when keep-alive is off (``epoch_days <= 0``)."""
    if epoch_days <= 0:
        return Epoch(0)
    return Epoch(int(now // (epoch_days * _DAY_SECONDS)))


def copy_name(base_name: str, epoch: Epoch) -> str:
    """The asset name of *base_name*'s copy for *epoch* (``<base>-e<epoch>``).

    The base asset (the first share) keeps its plain name; the suffix form
    is what the R0P bench proved propagates (T6, 2026-10-02)."""
    return f"{base_name}-e{int(epoch)}"
