"""Community-graph agents are their own list, never "Connected agents".

Regression (2026-10-01, testnet-c dashboard): every reporter seen in the
community graph was merged into ``/api/agents``' ``agents`` list, so remote
nodes reached only through the DKG sim layer showed up as agents connected to
this Blackbox. They now arrive as ``community_agents`` and render in a
separate dashboard section.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import attach, audit
from plugins.blackbox.dashboard import server
from plugins.blackbox.community.graph_stats import (
    group_community_agents,
    parse_reporter_rows,
)
from plugins.blackbox.kernel import dkg_client

LOCAL = "0xAAAA000000000000000000000000000000000001"
REMOTE = "0xBBBB000000000000000000000000000000000002"
GRAPH = "did:dkg:context-graph:agent-blackbox-community-test"


def _binding(value: str) -> dict:
    return {"value": value}


def _rows() -> list:
    return [
        {"reporter": _binding(LOCAL), "framework": _binding("hermes"), "n": _binding("2")},
        {"reporter": _binding(REMOTE), "framework": _binding("hermes"), "n": _binding("5")},
        {"reporter": _binding(REMOTE.lower()), "framework": _binding("openclaw"), "n": _binding("1")},
    ]


# ------------------------------------------------------------- pure functions


def test_parse_skips_rows_without_a_reporter_and_defaults_framework():
    rows = [{"framework": _binding("hermes"), "n": _binding("3")},
            {"reporter": _binding(REMOTE), "n": _binding("x")}]
    assert parse_reporter_rows(rows) == [{"address": REMOTE, "framework": "unknown", "count": 0}]


def test_group_folds_frameworks_per_address_case_insensitively():
    agents = group_community_agents(parse_reporter_rows(_rows()), LOCAL)
    remote = next(a for a in agents if not a["is_self"])
    assert remote["frameworks"] == ["hermes", "openclaw"]
    assert remote["reports"] == 6


def test_group_puts_this_node_first_and_flags_it():
    agents = group_community_agents(parse_reporter_rows(_rows()), LOCAL.lower())
    assert [a["is_self"] for a in agents] == [True, False]


def test_group_without_a_local_address_flags_nobody():
    agents = group_community_agents(parse_reporter_rows(_rows()), "")
    assert not any(a["is_self"] for a in agents)
    assert agents[0]["address"] == REMOTE  # most reports first


# -------------------------------------------------------------------- endpoint


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setenv("BLACKBOX_COMMUNITY_GRAPH_ID", GRAPH)
    monkeypatch.setattr(dkg_client.DkgClient, "reachable", lambda self, timeout=None: True)
    monkeypatch.setattr(dkg_client.DkgClient, "agent_identity", lambda self: {"agentAddress": LOCAL})
    monkeypatch.setattr(dkg_client.DkgClient, "query", lambda self, sparql, *a, **k: _rows())
    monkeypatch.setattr(audit, "local_active_frameworks", lambda: ["hermes"])
    monkeypatch.setattr(attach, "attach_all", lambda **kwargs: {"hermes": [], "openclaw": []})
    with TestClient(server.create_app(), base_url="http://127.0.0.1") as c:
        yield c


def _agents_once_reporters_land(client) -> dict:
    """The reporters + identity load off the request path (stale-while-
    revalidate); poll until the first refresh lands."""
    deadline = time.monotonic() + 5
    while True:
        body = client.get("/api/agents").json()
        if body["community_agents"] and any(a["is_self"] for a in body["community_agents"]):
            return body
        assert time.monotonic() < deadline, f"community agents never loaded: {body}"
        time.sleep(0.05)


def test_remote_reporters_are_not_connected_agents(client):
    body = _agents_once_reporters_land(client)
    addresses = {row["address"].lower() for row in body["agents"]}
    assert REMOTE.lower() not in addresses
    assert all(row.get("is_local") for row in body["agents"])


def test_community_agents_list_every_reporter_with_this_node_flagged(client):
    body = _agents_once_reporters_land(client)
    by_address = {a["address"].lower(): a for a in body["community_agents"]}
    assert set(by_address) == {LOCAL.lower(), REMOTE.lower()}
    assert by_address[LOCAL.lower()]["is_self"] is True
    assert by_address[REMOTE.lower()]["reports"] == 6


# ------------------------------------------------- extracted dashboard queries


class _FakeClient:
    """Answers every query with ``rows``; records what was asked."""

    def __init__(self, rows):
        self.rows = rows
        self.asked = []

    def query(self, sparql, graph_id, view=None, on_error=None):
        self.asked.append((sparql, graph_id, view))
        return self.rows


def test_contributing_agent_count_reads_the_count():
    from plugins.blackbox.community.graph_stats import contributing_agent_count
    assert contributing_agent_count(_FakeClient([{"n": _binding("3")}]), GRAPH) == 3


def test_contributing_agent_count_is_none_when_the_node_does_not_answer():
    from plugins.blackbox.community.graph_stats import contributing_agent_count
    assert contributing_agent_count(_FakeClient(None), GRAPH) is None


def test_most_reported_threats_types_rows_and_defaults_severity():
    from plugins.blackbox.community.graph_stats import most_reported_threats
    client = _FakeClient([{"identifier": _binding("ioc:domain:x.example"), "reporters": _binding("4")}])
    assert most_reported_threats(client, GRAPH, limit=7) == [
        {"identifier": "ioc:domain:x.example", "reporters": 4, "severity": "info"}
    ]
    assert "LIMIT 7" in client.asked[0][0]


def test_fetch_reporter_rows_keeps_none_for_a_silent_node():
    from plugins.blackbox.community.graph_stats import fetch_reporter_rows
    assert fetch_reporter_rows(_FakeClient(None), GRAPH) is None
