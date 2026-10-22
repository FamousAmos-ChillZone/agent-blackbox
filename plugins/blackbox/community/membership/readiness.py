"""When this node may add the verified graph's shared memory (2026-10-22, KI-449).

On DKG 10.0.25 every subscribe that includes shared memory makes the node start a
shared-memory catch-up and repeat it for about an hour while the graph is not yet
"synced". Blackbox runs the node with one sync slot (``sync/node_profile.py``), so
on a fresh node those catch-ups starved the verified download: 30 of 565 assets
after 40 minutes. A bench experiment showed the download at full speed with the
graph subscribed without shared memory, and stalled again within minutes of one
subscribe that included it.

So the verified graph's shared memory is added only once the verified graph is
downloaded and compiled on this node (``sync`` records that), and added once: the
record survives restarts, so a fresh process never re-subscribes a graph whose
shared memory it already added. Nothing is lost by waiting: a node shares only
verified matches, and the join request is sent at once regardless.

One instance per process (:data:`READINESS`), backed by ``verified_ready.json`` in
the Blackbox home; one lock. An unreadable record reads as "not yet" (the node keeps
whatever subscription it already has; nothing is requested on a guess, LES-011).

Usage::

    READINESS.mark_verified_ready(graph)          # sync, when the graph is complete
    READINESS.verified_ready(graph)               # membership, before adding shared memory
    READINESS.mark_shared_memory_added(graph)     # membership, once the node confirmed it
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from ...kernel import constants, yaml_files

logger = logging.getLogger(__name__)

_VERIFIED_READY = "verified_ready_at"
_SHARED_MEMORY = "shared_memory_at"


class GraphReadiness:
    """Per graph: when its verified sync finished here, and when its shared memory was added."""

    def __init__(self, store: Optional[Callable[[], Path]] = None, clock: Callable[[], float] = time.time) -> None:
        self._store = store or (lambda: constants.blackbox_home() / "verified_ready.json")
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: Optional[dict[str, dict[str, float]]] = None

    def verified_ready(self, graph: str) -> bool:
        """True once :meth:`mark_verified_ready` ran for *graph* on this node."""
        return _VERIFIED_READY in self._read().get(graph, {})

    def shared_memory_added(self, graph: str) -> bool:
        """True once the node confirmed a subscription of *graph* with its shared memory."""
        return _SHARED_MEMORY in self._read().get(graph, {})

    def mark_verified_ready(self, graph: str) -> None:
        """Record that *graph*'s verified sync is complete here (idempotent)."""
        self._mark(graph, _VERIFIED_READY)

    def mark_shared_memory_added(self, graph: str) -> None:
        """Record that *graph*'s shared memory is in the node's subscription (idempotent)."""
        self._mark(graph, _SHARED_MEMORY)

    def _read(self) -> dict[str, dict[str, float]]:
        with self._lock:
            if self._cache is None:
                try:
                    data = json.loads(self._store().read_text(encoding="utf-8-sig"))
                    self._cache = {g: dict(v) for g, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}
                except (OSError, ValueError):
                    self._cache = {}
            return self._cache

    def _mark(self, graph: str, key: str) -> None:
        cache = self._read()   # the same dict the lock guards
        if not graph or key in cache.get(graph, {}):
            return
        with self._lock:
            cache.setdefault(graph, {})[key] = self._clock()
            try:
                yaml_files.atomic_write(self._store(), json.dumps(cache))
            except OSError as exc:   # the memory is lost; the next process re-learns it
                logger.warning("blackbox: could not record the verified graph's readiness: %s", exc)


#: The process's readiness record (see module docstring).
READINESS = GraphReadiness()
