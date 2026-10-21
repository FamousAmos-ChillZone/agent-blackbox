"""Is this node connected to the verified graph, and has its owner approved it? (2026-10-21)

The dashboard's Community card shows one mark for each (the founder asked for a check
mark: a member still waiting for approval has its warnings silently dropped by the
owner). Both come from ONE read of the node's own listing; "approval" is the node's
``callerInvolved`` answer for this agent (DKG 10.0.25: the curator, or an allowlisted
participant), and a missing answer is "could not tell", never "not approved" (LES-011).
"""

from __future__ import annotations

import pytest

from plugins.blackbox import community
from plugins.blackbox.community.membership import join_status
from plugins.blackbox.community.membership.join_status import Admission, JoinState, admission_of
from plugins.blackbox.kernel import identity

OWNER = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70"
GRAPH = f"{OWNER}/agent-blackbox-vm"
MEMBER = "0x" + "60" * 20
CURATED = {"id": GRAPH, "subscribed": True, "accessPolicy": "public", "onChainId": "14",
           "onChain": {"publishPolicy": "curated"}}


@pytest.mark.parametrize(("entry", "address", "admission"), [
    (None, MEMBER, Admission.UNKNOWN),                                      # listing unreadable / not listed
    ({**CURATED, "callerInvolved": True}, OWNER, Admission.OWNER),
    ({**CURATED, "callerInvolved": True}, MEMBER, Admission.APPROVED),
    ({**CURATED, "callerInvolved": False}, MEMBER, Admission.WAITING),
    (CURATED, MEMBER, Admission.UNKNOWN),                                   # the node could not tell
    ({"id": GRAPH, "accessPolicy": "public", "onChainId": "9", "onChain": {"publishPolicy": "open"}}, MEMBER,
     Admission.OPEN),
    ({"id": GRAPH, "accessPolicy": "public", "onChainId": "14"}, MEMBER, Admission.UNKNOWN),   # chain record not in
    ({"id": GRAPH, "accessPolicy": "public"}, MEMBER, Admission.OPEN),     # unregistered P2P graph
    ({"id": GRAPH, "subscribed": True}, MEMBER, Admission.UNKNOWN),        # definition not in yet
])
def test_admission(entry, address, admission):
    assert admission_of(entry, address, GRAPH) is admission


class _Node:
    def __init__(self, rows=None, fail=False):
        self.rows, self.fail, self.listings = rows or [], fail, 0

    def context_graphs(self):
        self.listings += 1
        if self.fail:
            raise OSError("node down")
        return self.rows

    def agent_identity(self):
        return {"agentAddress": MEMBER}


@pytest.fixture(autouse=True)
def _fresh_identity(monkeypatch):
    monkeypatch.setattr(identity, "_reporter_cache", {})


def test_connected_and_approved_come_from_one_listing_read():
    node = _Node([{**CURATED, "callerInvolved": True}])
    status = join_status.read_membership_status(node, GRAPH)
    assert (status.join, status.admission) == (JoinState.JOINED, Admission.APPROVED)
    assert node.listings == 1


def test_an_unreadable_listing_is_unknown_for_both_never_not_approved():
    status = join_status.read_membership_status(_Node(fail=True), GRAPH)
    assert (status.join, status.admission) == (JoinState.UNKNOWN, Admission.UNKNOWN)


def test_the_community_card_carries_both_marks(monkeypatch):
    from plugins.blackbox.dashboard import community_routes

    monkeypatch.setattr(community, "read_membership_status",
                        lambda client, graph: join_status.MembershipStatus(JoinState.JOINED, Admission.WAITING))
    stats = community_routes.community_stats_payload(lambda cfg: [])
    assert stats["join_state"] == "joined" and stats["admission"] == "waiting"
    assert "waiting for the graph owner's approval" in stats["admission_text"]
