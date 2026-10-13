"""Community statements are written into the community subgraph (2026-10-12).

DKG 10.0.23 refuses members' direct shares into a catalog-mode graph's root;
a named subgraph keeps the member lane, and a node writes into a subgraph only
once it is registered locally. ``community.ensure_report_lane`` registers it
once per process per graph before the first write.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.community.membership import CommunityMembership
from plugins.blackbox.kernel import constants
from plugins.blackbox.kernel.dkg_client import DkgError


class _Node:
    def __init__(self, fail_with: str = "") -> None:
        self.calls = []
        self.fail_with = fail_with

    def request(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body))
        if self.fail_with:
            raise DkgError(self.fail_with, status_code=400)
        return {"created": body["subGraphName"]}


def test_the_lane_is_registered_once_per_graph():
    node, membership = _Node(), CommunityMembership()
    assert membership.ensure_report_lane(node, "g") and membership.ensure_report_lane(node, "g")
    assert node.calls == [("POST", "/api/sub-graph/create", {"contextGraphId": "g", "subGraphName": constants.COMMUNITY_SUB_GRAPH})]
    membership.ensure_report_lane(node, "other")
    assert len(node.calls) == 2                                                     # a second graph registers its own


def test_an_already_registered_lane_counts_as_ready():
    node, membership = _Node('Sub-graph "reports" already exists'), CommunityMembership()
    assert membership.ensure_report_lane(node, "g") is True
    node.fail_with = ""
    membership.ensure_report_lane(node, "g")
    assert len(node.calls) == 1                                                     # remembered as ready


def test_a_failed_registration_is_logged_and_tried_again(caplog):
    node, membership = _Node("context graph not found"), CommunityMembership()
    assert membership.ensure_report_lane(node, "g") is False
    assert "could not register the community subgraph" in caplog.text
    node.fail_with = ""
    assert membership.ensure_report_lane(node, "g") is True and len(node.calls) == 2


@pytest.mark.parametrize("module_path", ["plugins/blackbox/community/sharing.py",
                                         "plugins/blackbox/curate/publishing/publish.py",
                                         "plugins/blackbox/curate/upkeep/published.py"])
def test_every_community_writer_registers_the_lane_before_sharing(module_path):
    """Every call of share_knowledge_asset is preceded by the lane registration."""
    from pathlib import Path
    lines = Path(module_path).read_text(encoding="utf-8").splitlines()
    shares = [i for i, line in enumerate(lines) if "share_knowledge_asset(" in line]
    assert shares
    for i in shares:
        assert "ensure_report_lane(" in lines[i - 1], f"{module_path}:{i + 1}"
