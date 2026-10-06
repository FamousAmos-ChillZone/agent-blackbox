"""Reading verified partitions from the node, cached per partition (Cache-aside).

A confirmed partition is anchored on chain and never changes, so each one is
read once — one plain triple query, cursor-paged — and its rows kept on disk.
A refresh reads only partitions it has not read before, stops at the first
node failure (a store deadline leaves the store refusing queries for a while)
or when its time budget runs out, and records progress for ``blackbox status``.

Usage: ``read = verified_partition_rows(client, cg_id, partitions)``
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Union

from ...kernel import constants
from ...kernel.dkg_client import DkgClient, extract_binding
from .. import graph_queries
from .rows import Row, Triple, rows_from_triples

logger = logging.getLogger(__name__)

#: Triples per page. DKG 10.0.21 returned all 15,032 triples of the largest
#: asset for one request, so one page per asset is normal; the cursor is the
#: fallback for a node that caps responses.
PAGE_TRIPLES = 50_000
#: New partitions read per refresh at most this long; the rest wait for the next.
READ_BUDGET_SECONDS = 600.0


def read_partition_triples(client: DkgClient, cg_id: str, partition: str) -> Optional[List[Triple]]:
    """Every triple of one partition, cursor-paged; None when the node failed."""
    failure = object()
    triples: List[Triple] = []
    after = ""
    while True:
        page = client.query(graph_queries._partition_triples_sparql(partition, after=after, limit=PAGE_TRIPLES),
                            cg_id, view=None, on_error=failure)
        if page is failure:
            return None
        # Subject and predicate are unwrapped for matching; the object stays exactly as
        # the node sent it, as in the joined query's rows — the compiler unwraps every
        # value itself, and unwrapping twice would mangle a value that starts with a quote.
        batch = [(extract_binding(row.get("threat")), extract_binding(row.get("p")), _raw(row.get("o")))
                 for row in page]
        if len(batch) < PAGE_TRIPLES:
            triples.extend(batch)
            return triples
        # A full page may cut the last threat's triples: keep the complete ones and resume after them.
        last = batch[-1][0]
        complete = [triple for triple in batch if triple[0] != last]
        if not complete:
            logger.warning("blackbox: one threat in %s exceeds a whole page; partition skipped", partition)
            return None
        triples.extend(complete)
        after = complete[-1][0]


def _raw(cell: Union[Dict[str, object], str, None]) -> str:
    """An object cell as the joined query delivered it (SPARQL-JSON cells keep their value)."""
    if isinstance(cell, dict):
        value = cell.get("value")
        return "" if value is None else str(value)
    return "" if cell is None else str(cell)


@dataclass
class PartitionRead:
    """What one refresh read: the rows of every partition available, and progress."""

    rows: List[Row] = field(default_factory=list)
    total: int = 0          # confirmed partitions the node lists
    compiled: int = 0       # of those, how many have rows (cached or read now)
    read_now: int = 0       # read from the node in this refresh
    stopped_early: str = "" # why reading new partitions stopped, if it did


class PartitionCache:
    """Each confirmed partition's rows on disk, one gzip file per partition.

    Usage: ``cache = PartitionCache(); rows = cache.load(p) or ...; cache.store(p, rows)``.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = root or constants.blackbox_home() / "verified_partitions"

    def _path(self, partition: str) -> Path:
        return self.root / f"{hashlib.sha256(partition.encode('utf-8')).hexdigest()}.json.gz"

    def load(self, partition: str) -> Optional[List[Row]]:
        try:
            with gzip.open(self._path(partition), "rt", encoding="utf-8") as handle:
                stored = json.load(handle)
        except (OSError, ValueError):
            return None
        return stored.get("rows") if isinstance(stored, dict) and stored.get("partition") == partition else None

    def store(self, partition: str, rows: List[Row]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(partition)
        tmp = path.with_suffix(f".tmp-{os.getpid()}")
        with gzip.open(tmp, "wt", encoding="utf-8") as handle:
            json.dump({"partition": partition, "rows": rows}, handle)
        os.replace(tmp, path)

    def prune(self, keep: Iterable[str]) -> None:
        """Drop cached partitions the node no longer lists as confirmed."""
        wanted = {self._path(partition).name for partition in keep}
        for path in self.root.glob("*.json.gz") if self.root.is_dir() else []:
            if path.name not in wanted:
                path.unlink(missing_ok=True)


def verified_partition_rows(
    client: DkgClient,
    cg_id: str,
    partitions: Sequence[str],
    *,
    cache: Optional[PartitionCache] = None,
    budget_seconds: float = READ_BUDGET_SECONDS,
) -> PartitionRead:
    """Rows of every confirmed partition: cached ones from disk, new ones from the node.

    Reading new partitions stops at the first node failure (a store deadline
    leaves the store refusing queries for a while) or when the budget runs out;
    those partitions are read on a later refresh, so the rules only ever grow.
    """
    cache = cache or PartitionCache()
    read = PartitionRead(total=len(partitions))
    deadline = time.monotonic() + budget_seconds
    for partition in partitions:
        rows = cache.load(partition)
        if rows is None and not read.stopped_early:
            if time.monotonic() >= deadline:
                read.stopped_early = "time budget used; the rest are read on the next refresh"
            else:
                triples = read_partition_triples(client, cg_id, partition)
                if triples is None:
                    read.stopped_early = "the node refused a read; the rest are read on the next refresh"
                else:
                    rows = rows_from_triples(partition, triples)
                    cache.store(partition, rows)
                    read.read_now += 1
        if rows is not None:
            read.rows.extend(rows)
            read.compiled += 1
    cache.prune(partitions)
    return read


def _progress_path() -> Path:
    return constants.blackbox_home() / "verified_partitions" / "progress.json"


def record_progress(cg_id: str, read: PartitionRead) -> None:
    """Remember how much of the verified graph the last refresh compiled (KI-290).

    ``blackbox status`` shows it, so rules that cover only part of what the node
    holds are visible instead of looking complete. Best effort: a failed write
    only loses the status line.
    """
    path = _progress_path()
    record = {
        "context_graph_id": cg_id, "assets_total": read.total, "assets_compiled": read.compiled,
        "assets_read_now": read.read_now, "stopped_early": read.stopped_early, "at": time.time(),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".tmp-{os.getpid()}")
        tmp.write_text(json.dumps(record), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning("blackbox: could not record verified-graph progress: %s", exc)


def progress(cg_id: str) -> Optional[Dict[str, object]]:
    """The last recorded compile progress for *cg_id*, or None."""
    try:
        record = json.loads(_progress_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and record.get("context_graph_id") == cg_id else None


def catching_up(cg_id: str) -> bool:
    """True while the last refresh compiled only part of *cg_id*'s verified
    graph (a fresh node, or assets deferred by a store deadline or the read
    budget). False when nothing was recorded: a graph never read partition by
    partition is not catching up."""
    done = progress(cg_id) or {}
    compiled, total = done.get("assets_compiled"), done.get("assets_total")
    return isinstance(compiled, int) and isinstance(total, int) and compiled < total
