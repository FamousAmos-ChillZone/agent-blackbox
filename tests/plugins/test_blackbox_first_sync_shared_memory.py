"""A fresh node downloads the verified graph first, and adds its shared memory after (KI-449).

Bench 2026-10-22, DKG 10.0.25: every subscribe that included shared memory made the node
run shared-memory catch-ups for about an hour; with Blackbox's single sync slot they
starved the verified download (30 of 565 assets in 40 min). Subscribed WITHOUT shared
memory, the same node downloaded at full speed; one subscribe WITH it stalled it again.
These tests hold the rules: sync subscribes verified memory only and only when the node
says it is not subscribed; membership adds shared memory only once the graph is complete,
once per node; nothing is requested when the node's listing cannot be read (LES-011).
"""

from __future__ import annotations

from types import SimpleNamespace

from plugins.blackbox import community
from plugins.blackbox.community.membership import CommunityMembership
from plugins.blackbox.community.membership.readiness import GraphReadiness
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.sync import native
from plugins.blackbox.sync.progress import RecoveryBacklog

GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"


def _readiness(tmp_path):
    return GraphReadiness(store=lambda: tmp_path / "verified_ready.json", clock=lambda: 1_000.0)


class _Node:
    """A member's node: its listing says whether the graph is subscribed; records subscribes."""

    def __init__(self, listed=True, readable=True):
        self.listed, self.readable, self.subscribes = listed, readable, []

    def context_graphs(self):
        if not self.readable:
            raise OSError("node busy")
        row = {"id": GRAPH, "subscribed": True, "accessPolicy": "public",
               "onChainId": "14", "onChain": {"publishPolicy": "curated"}, "callerInvolved": True}
        return [row] if self.listed else []

    def subscribe_context_graph(self, graph, include_shared_memory=True):
        self.subscribes.append(include_shared_memory)
        self.listed = True
        return {"subscribed": graph, "catchup": {"status": "queued", "includeWorkspace": include_shared_memory}}

    def agent_identity(self):
        return {"agentAddress": "0x" + "60" * 20}


def _cfg():
    return SimpleNamespace(context_graph_id=GRAPH, graph_peer_id="12D3KooWowner", report=False)


# --------------------------------------------------------------------------- the record


def test_the_readiness_record_survives_a_new_process(tmp_path):
    first = _readiness(tmp_path)
    assert not first.verified_ready(GRAPH)
    first.mark_verified_ready(GRAPH)
    first.mark_shared_memory_added(GRAPH)
    again = _readiness(tmp_path)
    assert again.verified_ready(GRAPH) and again.shared_memory_added(GRAPH)


def test_an_unreadable_record_means_not_yet(tmp_path):
    (tmp_path / "verified_ready.json").write_text("not json", encoding="utf-8")
    assert not _readiness(tmp_path).verified_ready(GRAPH)


# --------------------------------------------------------------------------- membership


def test_before_the_graph_is_complete_membership_requests_no_shared_memory(tmp_path):
    node = _Node(listed=True)
    ok, detail = CommunityMembership(readiness=_readiness(tmp_path)).ensure(node, _cfg())
    assert not ok and "waiting for the verified graph" in detail and node.subscribes == []


def test_once_complete_shared_memory_is_added_once_per_node(tmp_path):
    readiness = _readiness(tmp_path)
    readiness.mark_verified_ready(GRAPH)
    node = _Node(listed=True)
    assert CommunityMembership(readiness=readiness).ensure(node, _cfg())[0]
    assert node.subscribes == [True]
    # A fresh process (a `blackbox sync` run, a dashboard restart) only confirms it.
    assert CommunityMembership(readiness=_readiness(tmp_path)).ensure(node, _cfg())[0]
    assert node.subscribes == [True]


def test_an_unreadable_listing_requests_nothing(tmp_path):
    readiness = _readiness(tmp_path)
    readiness.mark_verified_ready(GRAPH)
    readiness.mark_shared_memory_added(GRAPH)
    node = _Node(listed=True, readable=False)
    ok, detail = CommunityMembership(readiness=readiness).ensure(node, _cfg())
    assert not ok and "could not be read" in detail and node.subscribes == []


# --------------------------------------------------------------------------- sync (native route)


def _seen():
    return native._Observation()


def test_sync_subscribes_verified_memory_only_and_only_when_not_subscribed():
    cfg = BlackboxConfig()
    fresh = _Node(listed=False)
    native._subscribe(fresh, cfg, _seen())
    assert fresh.subscribes == [False]
    already = _Node(listed=True)
    seen = _seen()
    native._subscribe(already, cfg, seen)
    assert already.subscribes == [] and seen.subscribed


def test_sync_requests_nothing_when_the_listing_cannot_be_read():
    node = _Node(readable=False)
    seen = _seen()
    native._subscribe(node, BlackboxConfig(), seen)
    assert node.subscribes == [] and not seen.subscribed and "could not be read" in seen.error


def test_a_complete_graph_is_recorded_and_its_shared_memory_added(monkeypatch):
    calls = []
    monkeypatch.setattr(native, "read_recovery_backlog", lambda home, graph: RecoveryBacklog(0, "2026-10-22 02:00:00"))
    monkeypatch.setattr(native.ruleset, "verified_progress", lambda graph: {"assets_compiled": 565, "assets_total": 565})
    monkeypatch.setattr(community, "mark_verified_ready", lambda graph: calls.append(("ready", graph)))
    monkeypatch.setattr(community, "ensure_community_subscription", lambda client, cfg: calls.append(("ensure", cfg.context_graph_id)))
    native._open_shared_memory(object(), BlackboxConfig())
    assert [kind for kind, _ in calls] == ["ready", "ensure"]


def test_a_graph_still_arriving_adds_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(native, "read_recovery_backlog", lambda home, graph: RecoveryBacklog(535, "2026-10-22 02:00:00"))
    monkeypatch.setattr(community, "mark_verified_ready", lambda graph: calls.append(graph))
    native._open_shared_memory(object(), BlackboxConfig())
    assert calls == []
    monkeypatch.setattr(native, "read_recovery_backlog", lambda home, graph: None)     # could not tell
    native._open_shared_memory(object(), BlackboxConfig())
    assert calls == []
