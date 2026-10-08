"""The dashboard's verified-sync meter: % of the verified threat graph's REAL size.

Covers the three readings (node backlog from daemon.log, downloaded totals from
one aggregate _meta query, compiled progress), the pure combination into a
state + percentages, and the cached ``GET /api/verified-sync`` route. A number
nobody could read must come back unknown, never zero (LES-011).
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from plugins.blackbox import ruleset
from plugins.blackbox.dashboard import sync_meter
from plugins.blackbox.ruleset import graph_queries
from plugins.blackbox.sync import read_recovery_backlog
from plugins.blackbox.sync.progress import RecoveryBacklog

VM_GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
OTHER_GRAPH = "0x00000000000000000000000000000000000000aa/other-vm"


def _reconcile_line(stamp: str, graph: str, pending: int) -> str:
    """A reconcile-pass line in the exact shape DKG 10.0.21 writes (bb-ours, 2026-10-08)."""
    return (f"{stamp} system 7a27ac23 [DKGAgent] VM reconcile pass timing for \"{graph}\": source=periodic "
            f"gapSincePreviousPassMs=50697 scanMs=1603 recoverMs=65128 totalMs=66818 processed=10 "
            f"reconciled=2 pending={pending} continue=1\n")


# --- the node's backlog (daemon.log) ----------------------------------------

def test_the_backlog_is_the_newest_reconcile_pass_for_the_graph(tmp_path):
    (tmp_path / "daemon.log").write_text(
        _reconcile_line("2026-10-08 06:51:39", VM_GRAPH, 429)
        + "2026-10-08 06:52:00 unrelated line pending=1\n"
        + _reconcile_line("2026-10-08 06:53:37", VM_GRAPH, 427)
        + _reconcile_line("2026-10-08 06:54:00", OTHER_GRAPH, 9),
        encoding="utf-8")

    backlog = read_recovery_backlog(str(tmp_path), VM_GRAPH)

    assert backlog == RecoveryBacklog(pending=427, logged_at="2026-10-08 06:53:37")


def test_a_missing_log_is_an_unknown_backlog_not_zero(tmp_path):
    assert read_recovery_backlog(str(tmp_path), VM_GRAPH) is None


def test_a_log_without_a_pass_for_the_graph_is_an_unknown_backlog(tmp_path):
    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-08 06:54:00", OTHER_GRAPH, 0), encoding="utf-8")

    assert read_recovery_backlog(str(tmp_path), VM_GRAPH) is None


# --- downloaded totals (one aggregate _meta query) --------------------------

def test_the_totals_query_is_one_owner_pinned_aggregate_over_confirmed_assets():
    query = graph_queries._verified_partition_totals_sparql(VM_GRAPH)

    assert "COUNT(DISTINCT ?ka)" in query and "SUM(?publicTriples)" in query
    assert '"/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/"' in query      # KI-106 owner pin
    assert 'STR(?status) = "confirmed"' in query and "_verifiable_memory/" in query


def test_the_totals_query_shares_the_partition_listings_owner_pin():
    pin = graph_queries._owner_pin(VM_GRAPH)

    assert pin and pin in graph_queries._verified_partitions_sparql(VM_GRAPH)
    assert pin in graph_queries._verified_partition_totals_sparql(VM_GRAPH)


class _Client:
    """Answers every query with *rows* and records the call."""

    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self.rows, self.calls = rows, []

    def query(self, sparql: str, cg_id: str, **kwargs: Any) -> List[Dict[str, Any]]:
        self.calls.append((sparql, cg_id, kwargs))
        return self.rows


def test_downloaded_totals_are_read_from_the_aggregate_row():
    client = _Client([{"assets": "137", "triples": "1531200"}])

    totals = ruleset.verified_download_totals(client, VM_GRAPH, timeout=5.0)

    assert totals == ruleset.DownloadTotals(assets=137, triples=1531200)
    assert client.calls[0][2]["timeout"] == 5.0


@pytest.mark.parametrize("rows", [[], [{"assets": "lots", "triples": "1"}]])
def test_an_unreadable_aggregate_is_unknown_not_zero(rows):
    assert ruleset.verified_download_totals(_Client(rows), VM_GRAPH) is None


# --- combining the readings ---------------------------------------------------

def _meter(downloaded=ruleset.DownloadTotals(assets=137, triples=1_500_000), pending=427, compiled=124, rules=106_760):
    return sync_meter.build_sync_meter(downloaded=downloaded, pending=pending, compiled_assets=compiled,
                                       verified_rules=rules, checked_at="2026-10-08 06:53:37")


def test_the_meter_measures_both_stages_against_the_real_graph_size():
    meter = _meter()

    assert meter.state == "syncing"
    assert meter.graph_assets == 564
    assert meter.percent_downloaded == 24.3 and meter.percent_compiled == 22.0


def test_a_caught_up_node_with_every_asset_compiled_is_synced():
    meter = _meter(downloaded=ruleset.DownloadTotals(assets=564, triples=6_385_136), pending=0, compiled=564)

    assert meter.state == "synced"
    assert meter.percent_downloaded == 100.0 and meter.percent_compiled == 100.0


def test_new_assets_on_the_graph_move_a_synced_node_back_to_syncing():
    meter = _meter(downloaded=ruleset.DownloadTotals(assets=564, triples=6_385_136), pending=3, compiled=564)

    assert meter.state == "syncing"
    assert meter.graph_assets == 567 and meter.percent_compiled == 99.5


def test_downloaded_but_not_yet_compiled_is_still_syncing():
    meter = _meter(downloaded=ruleset.DownloadTotals(assets=564, triples=6_385_136), pending=0, compiled=560)

    assert meter.state == "syncing" and meter.percent_downloaded == 100.0


def test_rules_never_claim_more_assets_than_the_node_holds():
    meter = _meter(compiled=900)

    assert meter.compiled_assets == 137 and meter.percent_compiled == meter.percent_downloaded


def test_an_unknown_backlog_shows_counts_without_a_percentage():
    meter = _meter(pending=None)

    assert meter.state == "unknown"
    assert meter.graph_assets is None and meter.percent_downloaded is None and meter.percent_compiled is None
    assert meter.downloaded_assets == 137


def test_an_unreadable_node_is_unavailable_not_zero_percent():
    meter = _meter(downloaded=None)

    assert meter.state == "unavailable"
    assert meter.downloaded_assets is None and meter.percent_compiled is None


def test_an_unreachable_node_is_never_queried(monkeypatch, tmp_path):
    def must_not_query(*args, **kwargs):
        raise AssertionError("queried an unreachable node")

    monkeypatch.setattr(ruleset, "verified_download_totals", must_not_query)
    cfg = type("Cfg", (), {"context_graph_id": VM_GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": str(tmp_path)})()

    meter = sync_meter.read_sync_meter(cfg, node_reachable=False, verified_rules=0)

    assert meter.state == "unavailable"


# --- the route ------------------------------------------------------------------

def test_the_route_serves_the_meter_and_reuses_a_reading_within_the_cache_window(monkeypatch, tmp_path):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-08 06:53:37", VM_GRAPH, 427), encoding="utf-8")
    monkeypatch.setattr(ruleset, "verified_download_totals",
                        lambda client, graph, timeout=None: ruleset.DownloadTotals(assets=137, triples=1_500_000))
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: {"assets_compiled": 124})
    cfg = type("Cfg", (), {"context_graph_id": VM_GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": str(tmp_path)})()
    loads: List[int] = []

    def load_config():
        loads.append(1)
        return cfg

    app = fastapi.FastAPI()
    sync_meter.register_sync_meter_routes(app, load_config=load_config, node_reachable=lambda c: True,
                                          verified_rules=lambda c: 106_760)
    with TestClient(app) as client:
        first = client.get("/api/verified-sync").json()
        second = client.get("/api/verified-sync").json()

    assert first == second and len(loads) == 1
    assert first["state"] == "syncing" and first["graph_assets"] == 564
    assert first["verified_rules"] == 106_760 and first["checked_at"] == "2026-10-08 06:53:37"
