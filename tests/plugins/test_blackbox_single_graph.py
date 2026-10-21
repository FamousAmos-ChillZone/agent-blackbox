"""One graph per node (2026-10-21): community statements live in the verified graph's
shared working memory, in named lanes, and a sandbox lane keeps tests out of everything real.

Covers: config resolution (the shipped default and the legacy community graph both
resolve to the context graph; a named test graph is kept), the lane a share goes to,
the client's lane parameter, the join decision for a curated graph (KI-439), the
owner's auto-approver, and the audit sandbox context that keeps a test's local
records out of the real logs.
"""

from __future__ import annotations

import contextvars
import dataclasses
import threading
from types import SimpleNamespace

import pytest

from plugins.blackbox import audit
from plugins.blackbox.community import membership, sharing
from plugins.blackbox.community.membership import CommunityMembership, needs_join, pending_join_agents
from plugins.blackbox.kernel import config as bb_config
from plugins.blackbox.kernel import constants
from plugins.blackbox.kernel.dkg_client import DkgClient

TEST_GRAPH = "0xb4e20cce08D1b42c2a088F970e6313858f61aE0d/single-graph-bench"
LEGACY = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-community"
OWNER = "12D3KooWowner"


@pytest.fixture
def clean_env(monkeypatch):
    for var in ("BLACKBOX_COMMUNITY_GRAPH_ID", "BLACKBOX_CONTEXT_GRAPH_ID", "BLACKBOX_COMMUNITY_SANDBOX",
                "BLACKBOX_COMMUNITY_AUTO_APPROVE", "BLACKBOX_COMMUNITY_GRAPH_PEER_ID"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def _load(monkeypatch, entry):
    monkeypatch.setattr(bb_config, "_blackbox_entry", lambda: dict(entry))
    return bb_config.load_blackbox_config()


# --------------------------------------------------------------------------- config


def test_a_fresh_install_uses_one_graph(clean_env):
    cfg = _load(clean_env, {})
    assert cfg.community_graph_id == cfg.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID


def test_the_legacy_community_graph_moves_to_the_verified_graph(clean_env):
    assert LEGACY in constants.LEGACY_COMMUNITY_GRAPH_IDS
    assert _load(clean_env, {"community_graph_id": LEGACY}).community_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID


def test_the_community_graph_follows_a_custom_context_graph(clean_env):
    cfg = _load(clean_env, {"context_graph_id": "0xabc/custom-verified"})
    assert cfg.community_graph_id == "0xabc/custom-verified"


def test_a_named_test_graph_is_kept(clean_env):
    assert _load(clean_env, {"community_graph_id": TEST_GRAPH}).community_graph_id == TEST_GRAPH


def test_sandbox_and_auto_approve_default_off(clean_env):
    cfg = _load(clean_env, {})
    assert cfg.community_sandbox is False and cfg.community_auto_approve is False
    assert cfg.community_lane == constants.COMMUNITY_SUB_GRAPH


def test_sandbox_mode_moves_the_lane(clean_env):
    cfg = _load(clean_env, {"community_sandbox": True})
    assert cfg.community_lane == constants.SANDBOX_SUB_GRAPH == "sandbox"


# --------------------------------------------------------------------------- the client's lanes


class _RecordingClient(DkgClient):
    def __init__(self):
        self.posts: list[tuple[str, str, dict]] = []

    def request(self, method, path, body=None, timeout=None):
        self.posts.append((method, path, dict(body or {})))
        if path == "/api/query":
            return {"result": {"bindings": []}}
        if path.endswith("/swm/share-async"):
            return {"jobId": "j1"}
        if "/swm/share-jobs/" in path:
            return {"state": "succeeded"}
        return {}


def test_a_shared_memory_query_reads_the_reports_lane_unless_told_otherwise():
    client = _RecordingClient()
    client.query("SELECT ?r WHERE { ?r ?p ?o } LIMIT 1", TEST_GRAPH, view=constants.VIEW_SHARED_WORKING_MEMORY)
    client.query("SELECT ?r WHERE { ?r ?p ?o } LIMIT 1", TEST_GRAPH, view=constants.VIEW_SHARED_WORKING_MEMORY,
                 sub_graph=constants.SANDBOX_SUB_GRAPH)
    lanes = [body.get("subGraphName") for _, path, body in client.posts if path == "/api/query"]
    assert lanes == ["reports", "sandbox"]


def test_a_verified_query_names_no_lane():
    client = _RecordingClient()
    client.query("SELECT ?r WHERE { ?r ?p ?o } LIMIT 1", TEST_GRAPH)
    assert "subGraphName" not in client.posts[-1][2]


def test_send_report_writes_into_the_lane_it_is_given(monkeypatch):
    seen = {}

    class _Client:
        def request(self, *_args, **_kwargs):
            return {}

        def share_knowledge_asset(self, graph, name, quads, sub_graph=constants.COMMUNITY_SUB_GRAPH):
            seen.update(graph=graph, name=name, sub_graph=sub_graph)
            return {}

    monkeypatch.setattr(sharing.audit, "previously_accepted", lambda name: False)
    outcome, _ = sharing.send_report(_Client(), TEST_GRAPH, "sandbox-abc", [], lane=constants.SANDBOX_SUB_GRAPH)
    assert outcome is sharing.ShareOutcome.ACCEPTED
    assert seen == {"graph": TEST_GRAPH, "name": "sandbox-abc", "sub_graph": "sandbox"}


def test_a_member_registers_both_lanes_before_its_first_write():
    client = _RecordingClient()
    assert CommunityMembership().ensure_report_lane(client, TEST_GRAPH)
    created = [body["subGraphName"] for _, path, body in client.posts if path == "/api/sub-graph/create"]
    assert created == ["reports", "sandbox"]


# --------------------------------------------------------------------------- membership


def test_a_curated_registered_graph_needs_a_join():
    verified = {"accessPolicy": "public", "onChain": {"publishPolicy": "curated"}}
    assert needs_join(verified)


def test_an_open_public_graph_needs_no_join():
    assert not needs_join({"accessPolicy": "public"})
    assert not needs_join({"accessPolicy": "public", "onChain": {"publishPolicy": "open"}})


def test_a_private_graph_needs_a_join():
    assert needs_join({"accessPolicy": "private"})


class _MemberNode:
    """A member's node listing the verified graph as public + curated (what 10.0.25 reports)."""

    def __init__(self):
        self.joins = 0

    def context_graphs(self):
        return [{"id": TEST_GRAPH, "subscribed": True, "accessPolicy": "public",
                 "onChain": {"publishPolicy": "curated"}}]

    def status(self):
        return {"peerId": "12D3KooWmember"}

    def connect_peer(self, peer):
        return {"connected": peer}

    def request_join(self, graph, peer):
        self.joins += 1
        return {"ok": True}


def test_a_member_asks_to_join_the_curated_graph_once_even_with_sharing_off():
    node, member = _MemberNode(), CommunityMembership()
    cfg = SimpleNamespace(community_graph_id=TEST_GRAPH, community_graph_peer_id=OWNER, report=False)
    for _ in range(3):
        member.ensure(node, cfg)
    assert node.joins == 1


class _OwnerNode:
    def __init__(self, requests):
        self.requests, self.approved = requests, []

    def request(self, method, path, body=None, timeout=None):
        if method == "GET" and path.endswith("/join-requests"):
            return {"requests": self.requests}
        if method == "POST" and path.endswith("/approve-join"):
            self.approved.append(body["agentAddress"])
        return {}


AGENT_A = "0x60f85c1bfc29E70855E1608D355250383291aeD7"
AGENT_B = "0x6cc0F62899805EbB6Ab48C2319C3745BeFF4b2AB"


def test_pending_join_agents_keeps_only_well_formed_pending_requests():
    reply = {"requests": [{"agentAddress": AGENT_A, "status": "pending"},
                          {"agentAddress": AGENT_B, "status": "approved"},
                          {"agentAddress": "not-an-address", "status": "pending"}]}
    assert pending_join_agents(reply) == [AGENT_A]
    assert pending_join_agents({"unexpected": True}) == []


def test_the_owner_auto_approves_pending_joins_at_most_once_a_minute():
    clock = [1000.0]
    owner = _OwnerNode([{"agentAddress": AGENT_A, "status": "pending"}, {"agentAddress": AGENT_B}])
    member = CommunityMembership(clock=lambda: clock[0])
    assert member._approve_pending(owner, TEST_GRAPH) == 2
    assert member._approve_pending(owner, TEST_GRAPH) == 0   # inside the window: nothing read
    clock[0] += CommunityMembership.APPROVE_SECONDS
    member._approve_pending(owner, TEST_GRAPH)
    assert owner.approved == [AGENT_A, AGENT_B, AGENT_A, AGENT_B]


def test_auto_approve_is_off_unless_configured():
    owner = _OwnerNode([{"agentAddress": AGENT_A, "status": "pending"}])
    cfg = SimpleNamespace(community_graph_id=TEST_GRAPH, community_graph_peer_id="", community_auto_approve=False)

    class _Quiet(_OwnerNode):
        def context_graphs(self):
            return []

        def subscribe_context_graph(self, graph, include_shared_memory=False):
            return {}

    quiet = _Quiet(owner.requests)
    CommunityMembership().ensure(quiet, cfg)
    assert quiet.approved == []


# --------------------------------------------------------------------------- the sandbox context


def test_a_sandbox_run_writes_its_findings_into_the_sandbox_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    finding = {"identifier": "ioc:domain:example.test", "category": "ioc", "severity": "high"}
    with audit.sandbox_run():
        assert audit.in_sandbox_run()
        audit.record(event="pre_tool_call", findings=[finding], detail={"tool": "web_fetch"})
    assert not audit.in_sandbox_run()
    assert (tmp_path / "sandbox" / "findings.jsonl").exists()
    assert not (tmp_path / "findings.jsonl").exists()


def test_a_sandbox_cooldown_never_silences_the_real_report(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    with audit.sandbox_run():
        audit.mark_reported("ioc:domain:example.test")
        assert audit.recently_reported("ioc:domain:example.test")
    assert not audit.recently_reported("ioc:domain:example.test")


def test_a_share_thread_inherits_the_sandbox_context():
    seen = []
    with audit.sandbox_run():
        worker = threading.Thread(target=contextvars.copy_context().run, args=(lambda: seen.append(audit.in_sandbox_run()),))
        worker.start()
        worker.join()
    assert seen == [True]


def test_the_sandbox_share_uses_its_own_asset_name_and_lane(monkeypatch):
    sent = {}
    cfg = dataclasses.replace(bb_config.BlackboxConfig(), report=True, community_graph_id=TEST_GRAPH,
                              community_sandbox=True)
    monkeypatch.setattr(sharing.report_signer, "resolve_report_signer", lambda client, graph: object())
    monkeypatch.setattr(sharing.community, "build_report_quads", lambda **kw: [])
    monkeypatch.setattr(sharing, "shareable_fields", lambda finding: {})

    def fake_send(client, graph, name, quads, lane=constants.COMMUNITY_SUB_GRAPH):
        sent.update(graph=graph, name=name, lane=lane)
        return sharing.ShareOutcome.ACCEPTED, ""

    ledgered = []
    monkeypatch.setattr(sharing, "send_report", fake_send)
    monkeypatch.setattr(sharing, "_ledger_share", lambda *a, **k: ledgered.append(k.get("outcome")))
    monkeypatch.setattr(sharing.keep_alive, "remember_accepted_share",
                        lambda *a, **k: pytest.fail("a sandbox test is never kept alive"))
    sharing._share_sighting(object(), cfg, {"identifier": "ioc:domain:example.test", "severity": "high"}, "0x" + "ab" * 20)
    assert sent["lane"] == "sandbox" and sent["name"].startswith("sandbox-") and sent["graph"] == TEST_GRAPH
    assert ledgered == ["accepted"]


def test_membership_lanes_are_reports_and_sandbox():
    assert membership.COMMUNITY_LANES == ("reports", "sandbox")
