"""Keep-alive (Refine R5): each author keeps its own live reports on the network.

Shared memory expires per node and a same-name re-share is refused, so a
report stays visible only while its AUTHOR publishes a fresh epoch-named copy
of the same signed statement every ``community_keepalive_epoch_days`` (TTL/3,
10 days by default; 0 turns keep-alive off). Readers fold copies to one by
subject (KI-207) and keep a counted threat locally for a while after its
network copies expire (``ruleset.community_tier``).

Public surface — :func:`remember_accepted_share` (every share path, on an
ACCEPTED report), :func:`forget_retracted` (on a retraction),
:func:`publish_due_copies` (the publish step on the refresh cycle), the pure
:func:`current_epoch` / :func:`copy_name`, and :class:`LiveReportStore` for
tests and tooling.
"""

from __future__ import annotations

from .epochs import DEFAULT_EPOCH_DAYS, Epoch, copy_name, current_epoch
from .publisher import MAX_COPIES_PER_BEAT, OUTCOME_KEPT_ALIVE, forget_retracted, publish_due_copies, remember_accepted_share
from .store import MAX_LIVE, LiveReport, LiveReportStore

__all__ = [
    "DEFAULT_EPOCH_DAYS",
    "Epoch",
    "LiveReport",
    "LiveReportStore",
    "MAX_COPIES_PER_BEAT",
    "MAX_LIVE",
    "OUTCOME_KEPT_ALIVE",
    "copy_name",
    "current_epoch",
    "forget_retracted",
    "publish_due_copies",
    "remember_accepted_share",
]
