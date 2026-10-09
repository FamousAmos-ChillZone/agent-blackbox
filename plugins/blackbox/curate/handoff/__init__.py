"""Hand-off — the valve between the community's confirmed pool and whoever owns the verified graph (Community Curation C8).

* :func:`read_live_pool` -> :class:`LivePool` — the confirmed pool as this node verifies it.
* :func:`print_pool` / :func:`export` / :func:`verify_file` — ``blackbox curate pool | export | verify-bundle``.
* :func:`confirmation_for` — the community confirmation and its evidence, for the curator's dossier
  (from the live graph, or from a verified bundle file).

The pool and the bundle format themselves are ``community.pool``.
"""

from __future__ import annotations

from .commands import check, confirmation_for, export, print_pool, verify_file
from .live_pool import LivePool, bundle_text, read_live_pool

__all__ = ["LivePool", "bundle_text", "check", "confirmation_for", "export", "print_pool", "read_live_pool", "verify_file"]
