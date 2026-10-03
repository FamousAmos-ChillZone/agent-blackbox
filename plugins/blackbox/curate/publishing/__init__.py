"""Publishing — the last step of every curator verb: number it, check its
signatures, take consent, write it where it lives.

* :func:`publish` (+ :func:`summary`) — an APPROVED proposal into its graph.
* :func:`next_sequence` — the sequence number the next statement takes.
* :class:`VerbError` — what a verb raises when it refuses (printed, never a traceback).
"""

from __future__ import annotations

from .errors import VerbError
from .publish import MANIFEST_KIND, publish, summary
from .sequences import next_sequence

__all__ = ["MANIFEST_KIND", "VerbError", "next_sequence", "publish", "summary"]
