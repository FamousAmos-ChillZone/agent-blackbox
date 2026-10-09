"""Pool — the confirmed pool and how it is handed on (Community Curation C8).

* :func:`confirmed_pool` -> :class:`PoolEntry` — threats with a standing,
  evidenced confirmation from the community curators (a view, :mod:`.confirmed`).
* :class:`Bundle` / :func:`verify_bundle` -> :class:`BundleReport` — the pool
  as one file, checkable offline from the community root key (:mod:`.bundle`).
* :func:`held_manifest_texts` — the signed key manifests this node holds for a
  graph: the chain a bundle carries.
"""

from __future__ import annotations

from ..trust.trust_store import held_manifest_texts
from .bundle import Bundle, BundleReport, EntryResult, entry_document, verify_bundle
from .confirmed import PoolEntry, confirmed_pool

__all__ = ["Bundle", "BundleReport", "EntryResult", "PoolEntry", "confirmed_pool", "entry_document",
           "held_manifest_texts", "verify_bundle"]
