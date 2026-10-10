"""Verified partitions: the row builder, refresh progress, download totals.

* **Builder** — :mod:`.rows`, :func:`rows_from_triples` turns one asset's triples into exactly
  the rows the old joined query produced (same columns, same SPARQL semantics, see
  :data:`COLUMN_PREDICATES`). The live lookups (:mod:`..live`) run every store
  answer through it, so a looked-up rule equals the compiled one.
* **Progress** — :mod:`.reader`: how many confirmed assets the last refresh covered,
  when the node's asset count last grew (:func:`catching_up`), and the sync meter's
  download totals (:func:`verified_download_totals`).

The per-asset triple reader and its gzip cache (KI-288/KI-289) were retired by the
live lookups (DKG-lookup B6); :func:`forget_cached_assets` cleans the old files up.

Usage::

    partitions.record_progress(cg_id, partitions.PartitionRead(total=n, compiled=n))
    rows = partitions.rows_from_triples(graph_iri, triples)
"""

from .reader import DownloadTotals, PartitionRead, catching_up, forget_cached_assets, progress, record_progress, verified_download_totals
from .rows import COLUMN_PREDICATES, THREAT_TYPES, rows_from_triples

__all__ = [
    "COLUMN_PREDICATES",
    "DownloadTotals",
    "PartitionRead",
    "THREAT_TYPES",
    "catching_up",
    "forget_cached_assets",
    "progress",
    "record_progress",
    "rows_from_triples",
    "verified_download_totals",
]
