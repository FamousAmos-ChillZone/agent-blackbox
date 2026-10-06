"""Verified partitions: read as plain triples, rebuilt into threat rows, cached per asset.

WHY (KI-288/KI-289): the verified graph lives in one named graph per asset
(564 assets, 6.4M triples on 2026-10-06). The single joined query Blackbox used
to read them — one row per threat, ~27 OPTIONAL columns, DISTINCT, OFFSET paging
over five assets at a time — exceeded DKG 10.0.21's 30 s store deadline even for
ONE asset on a calm node, so every compile after the first asset failed and the
rules froze at that asset (exactly 1,000 IOC rules). A plain read of one asset's
triples takes ~2 s, and the rows are rebuilt here in Python.

Two patterns:

* **Builder** — :mod:`.rows`, :func:`rows_from_triples` turns one asset's triples into exactly
  the rows the joined query produced (same columns, same SPARQL semantics, see
  :data:`COLUMN_PREDICATES`), so :mod:`.compiler` and everything after it are
  unchanged.
* **Cache-aside** — :mod:`.reader`: a confirmed partition is anchored on chain and never
  changes, so :class:`PartitionCache` keeps each one's rows on disk and a
  refresh reads only partitions it has not read before. Rules grow as the
  graph arrives instead of freezing, and a store deadline costs one partition
  until the next refresh rather than the whole compile.

Usage::

    read = partitions.verified_partition_rows(client, cg_id, confirmed)
    rows, progress = read.rows, (read.compiled, read.total)
"""

from .reader import PartitionCache, PartitionRead, catching_up, progress, read_partition_triples, record_progress, verified_partition_rows
from .rows import COLUMN_PREDICATES, THREAT_TYPES, rows_from_triples

__all__ = [
    "COLUMN_PREDICATES",
    "PartitionCache",
    "PartitionRead",
    "THREAT_TYPES",
    "catching_up",
    "progress",
    "read_partition_triples",
    "record_progress",
    "rows_from_triples",
    "verified_partition_rows",
]
