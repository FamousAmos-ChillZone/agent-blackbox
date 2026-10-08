"""Sync — keeping this node's copy of the verified threat graph current.

Owns the local DKG node's catch-up of Umanitek's verified graph and the
bookkeeping around it:

* :mod:`.state` — the last-sync record other surfaces read (status, dashboard).
* :mod:`.progress` — parses the node's durable catch-up progress (resume bookmark);
  :func:`read_durable_progress` and :func:`read_recovery_backlog` (how many
  verified assets the node still has to download) are re-exported for the dashboard.

* :func:`cmd_sync` — the ``blackbox sync`` command (internals: :mod:`.command`
  for the catch-up orchestration, :mod:`.managed_node` for the node process).

Usage: ``from ..sync import state as sync_state`` · ``from ..sync.progress import read_durable_progress``.
"""

from __future__ import annotations

from . import progress, state
from .command import cmd_sync
from .progress import read_durable_progress, read_recovery_backlog

__all__ = ["cmd_sync", "progress", "read_durable_progress", "read_recovery_backlog", "state"]
