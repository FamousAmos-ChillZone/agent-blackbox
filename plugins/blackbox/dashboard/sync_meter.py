"""The dashboard's verified-sync meter — how much of Umanitek's verified threat
graph this node holds, measured against the graph's real size.

Three numbers, each from the place that actually knows it:

* **graph size** — assets the node has downloaded + the backlog its own
  reconcile pass reports (``pending=N`` in daemon.log, via
  :func:`..sync.read_recovery_backlog`). No DKG API states the on-chain total,
  and the node's _meta lists only assets it already holds, so this sum is the
  only honest total. It is re-read on every poll: when Umanitek publishes new
  assets the total grows and the meter dips until the node catches up —
  "synced" means caught up with the graph as it is NOW, not a final state.
  The two parts are read at slightly different instants (the live _meta vs
  the last pass, a minute or so old), so mid-sync the sum can be off by the
  one or two assets that moved in between; once caught up it is exact
  (checked on mainnet 2026-10-08: 153 downloaded + 411 pending = 564).
* **downloaded** — assets + triples confirmed in the node's _meta, one
  aggregate query (:func:`..ruleset.verified_download_totals`).
* **compiled** — assets the last refresh turned into rules
  (:func:`..ruleset.verified_progress`), plus the live verified rule count.

A number nobody could read is reported as unknown, never as zero (LES-011):
the meter shows a percentage only when the graph size is known.

Registered by :func:`.server.create_app` through
:func:`register_sync_meter_routes` → ``GET /api/verified-sync``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Optional

from .. import ruleset
from ..kernel.dkg_client import DkgClient
from ..sync import read_recovery_backlog

#: Seconds one meter reading is reused — the page polls every few seconds and
#: the node only moves every minute or two, so the node is asked at most this often.
CACHE_SECONDS = 10.0
#: The _meta aggregate is small; a node that cannot answer in this long is busy,
#: and the meter says "could not tell" rather than wait.
QUERY_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class SyncMeter:
    """One reading of the verified-sync meter, as served to the dashboard.

    ``state`` is one of:

    * ``synced`` — nothing left to download and every downloaded asset compiled;
    * ``syncing`` — the node is still downloading, or rules lag the download;
    * ``unknown`` — the node answered but its backlog is unknown, so there is
      no total to take a percentage of (counts are still shown);
    * ``unavailable`` — the node could not be read at all.

    ``graph_assets`` / ``percent_*`` are None whenever the total is unknown.
    ``checked_at`` is the node's own timestamp of the backlog it reported.
    """

    state: str
    graph_assets: Optional[int]
    downloaded_assets: Optional[int]
    downloaded_triples: Optional[int]
    compiled_assets: Optional[int]
    verified_rules: int
    percent_downloaded: Optional[float]
    percent_compiled: Optional[float]
    checked_at: str


def _percent(part: int, whole: int) -> float:
    """``part`` of ``whole`` as a percentage, one decimal, never above 100."""
    return round(min(100.0, 100.0 * part / whole), 1) if whole > 0 else 0.0


def build_sync_meter(*, downloaded: Optional[ruleset.DownloadTotals], pending: Optional[int],
                     compiled_assets: Optional[int], verified_rules: int, checked_at: str = "") -> SyncMeter:
    """Combine the three readings into one :class:`SyncMeter` (pure — no I/O).

    *downloaded* None = the node could not be read; *pending* None = its
    backlog is unknown; *compiled_assets* None = nothing compiled yet.
    """
    if downloaded is None:
        return SyncMeter(state="unavailable", graph_assets=None, downloaded_assets=None, downloaded_triples=None,
                         compiled_assets=compiled_assets, verified_rules=verified_rules,
                         percent_downloaded=None, percent_compiled=None, checked_at=checked_at)
    # The compile record can trail a download that was rolled back or re-read;
    # rules never cover more assets than the node holds.
    compiled = min(compiled_assets, downloaded.assets) if compiled_assets is not None else None
    if pending is None:
        return SyncMeter(state="unknown", graph_assets=None, downloaded_assets=downloaded.assets,
                         downloaded_triples=downloaded.triples, compiled_assets=compiled, verified_rules=verified_rules,
                         percent_downloaded=None, percent_compiled=None, checked_at=checked_at)
    graph_assets = downloaded.assets + pending
    done = pending == 0 and compiled is not None and compiled >= downloaded.assets
    return SyncMeter(
        state="synced" if done else "syncing",
        graph_assets=graph_assets,
        downloaded_assets=downloaded.assets,
        downloaded_triples=downloaded.triples,
        compiled_assets=compiled,
        verified_rules=verified_rules,
        percent_downloaded=_percent(downloaded.assets, graph_assets),
        percent_compiled=_percent(compiled or 0, graph_assets),
        checked_at=checked_at,
    )


def read_sync_meter(cfg: Any, *, node_reachable: bool, verified_rules: int) -> SyncMeter:
    """Take one live reading for *cfg*'s verified graph (``cfg.context_graph_id``)."""
    graph_id = cfg.context_graph_id
    downloaded = None
    if node_reachable:
        client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
        downloaded = ruleset.verified_download_totals(client, graph_id, timeout=QUERY_TIMEOUT_SECONDS)
    backlog = read_recovery_backlog(cfg.dkg_home, graph_id)
    compiled = (ruleset.verified_progress(graph_id) or {}).get("assets_compiled")
    return build_sync_meter(
        downloaded=downloaded,
        pending=backlog.pending if backlog else None,
        compiled_assets=compiled if isinstance(compiled, int) else None,
        verified_rules=verified_rules,
        checked_at=backlog.logged_at if backlog else "",
    )


def register_sync_meter_routes(app: Any, *, load_config: Callable[[], Any],
                               node_reachable: Callable[[Any], bool],
                               verified_rules: Callable[[Any], int]) -> Callable[[], Dict[str, Any]]:
    """Add ``GET /api/verified-sync`` to *app* (a FastAPI app); returns the handler.

    *node_reachable* is the server's cached liveness probe (never blocks);
    *verified_rules* maps cfg → the compiled verified-rule count. Readings are
    cached for :data:`CACHE_SECONDS` behind one lock, so concurrent polls
    trigger one node query, not one each.
    """
    lock = threading.Lock()
    cached: Dict[str, Any] = {"at": -1e9, "body": None}

    @app.get("/api/verified-sync")
    def verified_sync() -> Dict[str, Any]:
        with lock:
            if cached["body"] is None or time.monotonic() - cached["at"] >= CACHE_SECONDS:
                cfg = load_config()
                meter = read_sync_meter(cfg, node_reachable=node_reachable(cfg), verified_rules=verified_rules(cfg))
                cached["body"], cached["at"] = asdict(meter), time.monotonic()
            return dict(cached["body"])

    return verified_sync
