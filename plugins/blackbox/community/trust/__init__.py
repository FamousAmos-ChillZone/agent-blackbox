"""Trust — everything a READER does to know whom to trust.

* :func:`read_curator_view` — the verified view of what the curator has said.
* :mod:`.manifests` — which key manifest a reader acts on (time-lock, conflicts).

Curators' own tooling lives in ``curate/``; the statement formats live in
``community/statements/`` and ``kernel/signing/``.
"""

from __future__ import annotations

from . import manifests
from .authority_read import read_curator_view

__all__ = ["manifests", "read_curator_view"]
