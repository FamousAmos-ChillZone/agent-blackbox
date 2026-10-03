"""Trust — everything a READER does to know whom to trust.

* :func:`read_curator_view` — what the curators have said, verified: one view
  per authority (verified, community), combined.
* :func:`combine` — the rule between the two authorities: the most restrictive
  current word wins.
* :mod:`.manifests` — which key manifest a reader acts on (time-lock, conflicts).

Curators' own tooling lives in ``curate/``; the statement formats live in
``community/statements/`` and ``kernel/signing/``.
"""

from __future__ import annotations

from . import manifests
from .authority_read import read_curator_view
from .combine import combine

__all__ = ["combine", "manifests", "read_curator_view"]
