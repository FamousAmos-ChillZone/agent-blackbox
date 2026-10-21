"""The sandbox lane drawn as the Community graph (2026-10-21).

In sandbox mode the dashboard's Community tab reads /api/playground/graph and
/api/playground/threat. These must return the same shapes as /api/graph and
/api/threat for the community tier, built from every field a sandbox report
carries, and must be empty outside sandbox mode.
"""

from __future__ import annotations

import dataclasses

from plugins.blackbox import playground
from plugins.blackbox.dashboard import playground_routes
from plugins.blackbox.kernel import config as bb_config
from plugins.blackbox.playground import graph
from plugins.blackbox.playground.lane import entries_from_rows

G = "http://umanitek.ai/ontology/guardian/"
A, B = "0x" + "aa" * 20, "0x" + "bb" * 20


def _rows(subject, **fields):
    return [{"r": subject, "p": G + key, "o": value} for key, value in fields.items()]


ROWS = (
    _rows("urn:guardian:report:a:1", identifier="ioc:domain:phish.example", reporter=A, severity="high",
          category="ioc", iocType="domain", toolName="web_fetch", outcome="flagged",
          signedStatement="x" * 900)
    + _rows("urn:guardian:report:b:1", identifier="ioc:domain:phish.example", reporter=B, severity="high")
    + _rows("urn:guardian:report:a:2", identifier="dep:npm:evil-pkg@1.0.0", reporter=A, severity="critical",
            packageName="evil-pkg", packageEcosystem="npm")
    + _rows("urn:guardian:report:x:9", severity="high")   # no identifier/reporter: not a statement
)


def _view():
    return playground.LaneView("0xabc/graph", True, entries_from_rows(ROWS, own=A.lower()))


def test_rows_fold_into_one_entry_per_report_keeping_every_short_field():
    entries = {(e.identifier, e.reporter): e for e in _view().entries}
    assert len(entries) == 3
    phish = dict(entries[("ioc:domain:phish.example", A)].fields)
    assert phish["toolName"] == "web_fetch" and phish["outcome"] == "flagged"
    assert "signedStatement" not in phish          # proof material is never shown
    assert entries[("ioc:domain:phish.example", A)].mine is True


def test_the_graph_page_has_the_community_shape_one_bubble_per_threat():
    page = graph.graph_page(_view())
    assert {"threats", "total", "category_totals", "ecosystem_totals", "offset", "limit", "partial"} <= set(page)
    bubbles = {t["identifier"]: t for t in page["threats"]}
    assert set(bubbles) == {"ioc:domain:phish.example", "dep:npm:evil-pkg@1.0.0"}
    assert bubbles["ioc:domain:phish.example"]["reporterCount"] == 2
    assert bubbles["dep:npm:evil-pkg@1.0.0"]["category"] == "dependency"
    assert page["category_totals"] == {"ioc": 1, "dependency": 1} and page["ecosystem_totals"] == {"npm": 1}
    assert all(t["sandbox"] and t["enforcement"] == "none" for t in page["threats"])


def test_the_graph_page_filters_like_the_community_page():
    assert [t["identifier"] for t in graph.graph_page(_view(), q="PHISH")["threats"]] == ["ioc:domain:phish.example"]
    assert graph.graph_page(_view(), category="dependency")["total"] == 1
    assert graph.graph_page(_view(), ecosystem="npm")["total"] == 1
    paged = graph.graph_page(_view(), limit=1)
    assert len(paged["threats"]) == 1 and paged["partial"] is True


def test_the_threat_detail_carries_what_the_member_submitted():
    detail = graph.threat_detail(_view(), "ioc:domain:phish.example")
    assert detail["found"] and detail["sandbox"] and detail["reporters"] == 2
    assert detail["toolName"] == "web_fetch" and detail["severity"] == "high"
    assert graph.threat_detail(_view(), "ioc:domain:absent.example")["found"] is False


def test_the_routes_are_empty_outside_sandbox_mode(monkeypatch):
    monkeypatch.setattr(bb_config, "load_blackbox_config",
                        lambda: dataclasses.replace(bb_config.BlackboxConfig(), community_sandbox=False))
    monkeypatch.setattr(playground, "read_lane", lambda cfg: (_ for _ in ()).throw(AssertionError("not read")))
    assert playground_routes.graph_payload("", "", "", 0, 200)["threats"] == []
    assert playground_routes.threat_payload("ioc:domain:phish.example")["found"] is False


def test_the_routes_serve_the_sandbox_lane_in_sandbox_mode(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    monkeypatch.setattr(bb_config, "load_blackbox_config",
                        lambda: dataclasses.replace(bb_config.BlackboxConfig(), community_sandbox=True))
    monkeypatch.setattr(playground, "read_lane", lambda cfg: _view())
    app = FastAPI()
    playground_routes.register(app, lambda *a: None)
    client = TestClient(app)
    page = client.get("/api/playground/graph", params={"tier": "community", "limit": 200}).json()
    assert page["total"] == 2
    detail = client.get("/api/playground/threat", params={"tier": "community", "identifier": "dep:npm:evil-pkg@1.0.0"}).json()
    assert detail["found"] and detail["packageName"] == "evil-pkg"
