"""Trust — everything a READER does to know whom to trust.

* :func:`read_curator_view` — what the curators have said, verified: one view
  per authority (verified, community), combined.
* :func:`combine` — the rule between the two authorities: the most restrictive
  current word wins.
* :mod:`.manifests` — which key manifest a reader acts on (time-lock, conflicts).
* :mod:`.bounded_read` — trust statements are looked up by identifier in the
  open community graph, never scanned; an incomplete lookup proves nothing.
* :mod:`.trust_store` — this node's own verified copy of the trust statements:
  the state of record, re-verified on every load.
* :mod:`.raising_budget` — the reader's daily cap on what the community
  curators can raise; reductions are never held.

Curators' own tooling lives in ``curate/``; the statement formats live in
``community/statements/`` and ``kernel/signing/``.
"""

from __future__ import annotations

from . import manifests
from .authority_read import known_curator_statements, read_curator_view
from .combine import combine

__all__ = ["combine", "known_curator_statements", "manifests", "read_curator_view"]
