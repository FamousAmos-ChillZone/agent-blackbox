"""The community pulse — "did the community graph change?" between full refreshes (R16, KI-202).

Before R16 the community tier was re-read only when the WHOLE ruleset
refreshed: a 15-minute floor on the dashboard, one hour by default. The
near-real-time arrival the benches showed came from a watcher that existed
only in the sandbox. Now one cheap probe — a single aggregate query over the
community graph's shared memory, count plus newest subject — runs at most
every ``cfg.community_poll_interval`` seconds (default 20, 0 = off) while the
agent is active, and only when its answer differs from last time does the
ruleset re-apply the community tier (see ``ruleset.pulse``). Reading stays
the reader's job; this module only says whether there is anything new.

Pattern: one stateful object with one lock (the last fingerprint and the
last probe time), module-level because the state is per process like the
node it talks to.

Usage::

    if community.PULSE.due(interval_s) and community.PULSE.changed(client, cfg): ...re-apply the tier...
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from ..kernel import constants
from ..kernel.dkg_client import DkgClient, extract_binding

logger = logging.getLogger(__name__)

#: One aggregate over the community graph's shared memory: how many reports,
#: and the newest subject (subjects are unique per reporter and threat).
_FINGERPRINT_SPARQL = (
    "SELECT (COUNT(DISTINCT ?r) AS ?n) (MAX(STR(?r)) AS ?last) WHERE { "
    "?r a <http://umanitek.ai/ontology/guardian/ThreatReport> }"
)


def fingerprint(client: DkgClient, cfg: Any) -> Optional[str]:
    """``"<count>:<newest subject>"`` for the community graph, or None when the
    probe failed (fail-open: no change is ever inferred from a failed probe)."""
    graph = str(getattr(cfg, "community_graph_id", "") or "")
    if not graph:
        return None
    rows = client.query(_FINGERPRINT_SPARQL, graph, view=constants.VIEW_SHARED_WORKING_MEMORY, on_error=None)
    if not rows:
        return None
    first = rows[0]
    return f"{extract_binding(first.get('n')) or '0'}:{extract_binding(first.get('last')) or ''}"


class CommunityPulse:
    """Remembers when the graph was last probed and what it looked like."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_probe = 0.0
        self._fingerprint: Optional[str] = None
        self._baselined_now = False

    def due(self, interval_s: float) -> bool:
        """Claim the next probe slot when *interval_s* has passed (atomic)."""
        if interval_s <= 0:
            return False
        now = self._clock()
        with self._lock:
            if now - self._last_probe < interval_s:
                return False
            self._last_probe = now
            return True

    def changed(self, client: DkgClient, cfg: Any) -> bool:
        """Probe the graph; True when its fingerprint differs from the last
        successful probe. The first successful probe only sets the baseline."""
        current = fingerprint(client, cfg)
        if current is None:
            return False
        with self._lock:
            previous, self._fingerprint = self._fingerprint, current
            self._baselined_now = previous is None
        if previous is None:
            return False
        if previous != current:
            logger.debug("blackbox: community graph changed (%s -> %s)", previous, current)
            return True
        return False

    @property
    def baselined_now(self) -> bool:
        """True right after the probe that SET the baseline (a process that just
        started, or the first probe after a reset) — the beat uses it to apply
        the reports that already exist when the cached tier has none yet."""
        with self._lock:
            return self._baselined_now

    @property
    def report_count(self) -> int:
        """How many reports the last successful probe counted (0 before any)."""
        with self._lock:
            head = (self._fingerprint or "0:").split(":", 1)[0]
        try:
            return int(head)
        except ValueError:
            return 0

    def reset(self) -> None:
        """Forget the baseline (tests, and after a full refresh re-read everything)."""
        with self._lock:
            self._last_probe = 0.0
            self._fingerprint = None
            self._baselined_now = False


#: The per-process pulse.
PULSE = CommunityPulse()
