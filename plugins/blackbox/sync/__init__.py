"""Sync — keeping this node's copy of the verified threat graph current.

Owns the local DKG node's catch-up of Umanitek's verified graph and the
bookkeeping around it:

* :mod:`.state` — the last-sync record other surfaces read (status, dashboard).
* :mod:`.progress` — parses the node's durable catch-up progress (resume bookmark).

Usage: ``from ..sync import state as sync_state`` · ``from ..sync.progress import read_durable_progress``.
"""
