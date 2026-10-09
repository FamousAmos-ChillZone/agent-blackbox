"""Publishing — the last step of every curator verb: number it, check its
signatures, take consent, write it where it lives.

* :func:`publish` (+ :func:`summary`, :class:`PublishOutcome`) — an APPROVED proposal into the
  graph it was signed for, then read back: published means readable.
* :func:`next_sequence` — the sequence number the next statement takes.
* :class:`VerbError` — what a verb raises when it refuses (printed, never a traceback).
"""

from __future__ import annotations

from .errors import VerbError
from .publish import MANIFEST_KIND, PublishOutcome, publish, summary
from .sequences import next_sequence

__all__ = ["MANIFEST_KIND", "PublishOutcome", "VerbError", "next_sequence", "publish", "summary"]
