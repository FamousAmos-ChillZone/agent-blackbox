"""Community membership: subscribe and join at most once, never to self (Refine R0, KI-064/114).

Before: the ruleset subscribed on every refresh and `blackbox sync` sent a
join request on every run, even toward this node's own peer id.
"""

from __future__ import annotations

from types import SimpleNamespace

from plugins.blackbox.community.membership import CommunityMembership

GRAPH = "0xabc/agent-blackbox-community-test"
CURATOR = "12D3KooWcurator"


class _Node:
    def __init__(self, subscribed=False, own_peer="12D3KooWself", join_fails=False,
                 access_policy="private", connect_fails=False, subscribe_fails=False):
        self.subscribed = subscribed
        self.own_peer = own_peer
        self.join_fails = join_fails
        self.access_policy = access_policy
        self.connect_fails = connect_fails
        self.subscribe_fails = subscribe_fails
        self.subscribe_calls = 0
        self.join_calls = 0
        self.calls = []   # ordered verbs: "connect", "subscribe", "join"

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": self.subscribed, "synced": self.subscribed,
                 "accessPolicy": self.access_policy}]

    def connect_peer(self, peer):
        self.calls.append(("connect", peer))
        if self.connect_fails:
            raise RuntimeError("peer discovery pending")
        return {"connected": peer}

    def subscribe_context_graph(self, graph, include_shared_memory=False):
        self.subscribe_calls += 1
        self.calls.append(("subscribe", graph))
        if self.subscribe_fails:
            raise RuntimeError("Context Graph read authority is temporarily unavailable")
        return {"subscribed": graph}

    def status(self):
        return {"peerId": self.own_peer}

    def request_join(self, graph, peer):
        self.join_calls += 1
        self.calls.append(("join", peer))
        if self.join_fails:
            raise RuntimeError("curator unreachable")
        return {"ok": True}


def _cfg(peer=CURATOR):
    return SimpleNamespace(community_graph_id=GRAPH, community_graph_peer_id=peer)


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_fifty_sync_passes_send_one_join():
    node, membership = _Node(), CommunityMembership()
    for _ in range(50):
        membership.ensure(node, _cfg())
    assert node.join_calls == 1


def test_no_subscribe_when_the_node_says_it_is_subscribed():
    node = _Node(subscribed=True)
    ok, _ = CommunityMembership().ensure(node, _cfg())
    assert ok and node.subscribe_calls == 0


def test_subscribe_is_not_repeated_inside_the_retry_window():
    node, clock = _Node(subscribed=False), _Clock()
    membership = CommunityMembership(clock=clock)
    for _ in range(10):
        membership.ensure(node, _cfg(peer=""))
    assert node.subscribe_calls == 1
    clock.now += CommunityMembership.RETRY_SECONDS + 1
    membership.ensure(node, _cfg(peer=""))
    assert node.subscribe_calls == 2


def test_never_asks_itself_to_join():
    node = _Node(own_peer=CURATOR)
    CommunityMembership().ensure(node, _cfg())
    assert node.join_calls == 0


def test_a_failed_join_is_retried_only_after_the_window():
    node, clock = _Node(join_fails=True), _Clock()
    membership = CommunityMembership(clock=clock)
    membership.ensure(node, _cfg())
    membership.ensure(node, _cfg())
    assert node.join_calls == 1
    clock.now += CommunityMembership.RETRY_SECONDS + 1
    node.join_fails = False
    membership.ensure(node, _cfg())
    membership.ensure(node, _cfg())
    assert node.join_calls == 2


def test_no_graph_configured_does_nothing():
    node = _Node()
    ok, detail = CommunityMembership().ensure(node, SimpleNamespace(community_graph_id="", community_graph_peer_id=""))
    assert not ok and node.subscribe_calls == 0 and node.join_calls == 0


# ---------------------------------------------------------------------------
# KI-216 / FIX-0039: a fresh node must reach the graph OWNER before it can subscribe
# ---------------------------------------------------------------------------


def test_connects_to_the_owner_before_the_first_subscribe():
    node = _Node()
    CommunityMembership().ensure(node, _cfg())
    assert node.calls[:2] == [("connect", CURATOR), ("subscribe", GRAPH)]


def test_no_connect_without_an_owner_peer_id():
    node = _Node()
    CommunityMembership().ensure(node, _cfg(peer=""))
    assert ("connect", CURATOR) not in node.calls and node.subscribe_calls == 1


def test_a_failed_owner_dial_does_not_stop_the_subscribe():
    node = _Node(connect_fails=True)
    ok, _ = CommunityMembership().ensure(node, _cfg())
    assert ok and node.subscribe_calls == 1


def test_a_refused_subscribe_is_retried_after_the_short_window_not_the_long_one():
    clock = _Clock()
    node = _Node(subscribe_fails=True)
    membership = CommunityMembership(clock=clock)
    assert membership.ensure(node, _cfg())[0] is False
    clock.now += CommunityMembership.FAILED_SUBSCRIBE_RETRY_SECONDS - 1
    membership.ensure(node, _cfg())
    assert node.subscribe_calls == 1, "still inside the short window"
    clock.now += 2
    membership.ensure(node, _cfg())
    assert node.subscribe_calls == 2, "retried after the short window, long before RETRY_SECONDS"


def test_no_join_request_for_a_public_graph():
    """D-040: public graphs have no membership step — with an owner peer now
    configured for discovery, the join request must NOT start firing at it."""
    node = _Node(access_policy="public")
    CommunityMembership().ensure(node, _cfg())
    assert node.join_calls == 0 and node.subscribe_calls == 1
