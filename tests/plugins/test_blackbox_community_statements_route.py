"""Refine R2 — every honoured statement is visible on the dashboard with who / when / why.

``GET /api/community-statements`` serves disputes, curator verdicts, counted
authors, backlog and away notices, and the held-back / pending counts, from
the ONE cached community read. Every community-authored string passes
through the dashboard sanitizer.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.community import CommunityRead, ReadState
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements.curator_statements import CuratorRecord
from plugins.blackbox.community.statements.disputes import VerifiedDispute
from plugins.blackbox.community.statements.retractions import VerifiedRetraction
from plugins.blackbox.dashboard import community_routes
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

GRAPH = "0x51E5dE758A45/agent-blackbox-community-dev"
HOSTILE = 'ioc:url:https://x.example/?q=<script>alert(1)</script>'


def _view():
    manifest = km.KeyManifest(environment="net", graph="vm", chain="", root_epoch=1, version=3,
                              curator_keys=("a" * 64, "b" * 64, "c" * 64), threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    revoked = CuratorRecord(kind=Kind.REVOCATION, identifier="dep:npm:x@1", sequence=5, day="2026-10-02",
                            fields=(("reason", "false-positive"),), signers=frozenset({"a" * 64, "b" * 64}))
    away = CuratorRecord(kind=Kind.AWAY, identifier="curator", sequence=1, day="2026-10-02",
                         fields=(("from", "2026-10-02"), ("key", "c" * 64), ("until", "2026-10-05")),
                         signers=frozenset({"c" * 64}))
    counted = cv.CountedAuthor(key="d" * 64, address="0x" + "d" * 40, author_class="partner", org="acme",
                               expires="2027-01-01")
    return cv.CuratorView(manifest=manifest, verdicts={"dep:npm:x@1": revoked}, counted={"d" * 64: counted},
                          away=(away,))


def _read():
    dispute = VerifiedDispute(subject="s", identifier=HOSTILE, author="e" * 64, reporter="0xreporter",
                              reason="wrong", day="2026-10-01")
    retraction = VerifiedRetraction(author="f" * 64, identifier="ioc:domain:mine.example", subject="t",
                                    reporter="0xretractor", day="2026-10-02")
    return CommunityRead(ReadState.ROWS, disputes=(dispute,), retractions=(retraction,), held_back=7,
                         pending_tombstones=2, curator=_view())


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config",
                        lambda: BlackboxConfig(community_graph_id=GRAPH))


def test_statements_carry_who_when_why(configured):
    payload = community_routes.community_statements_payload(lambda cfg: _read())
    dispute = payload["disputes"][0]
    assert (dispute["who"], dispute["when"], dispute["why"]) == ("0xreporter", "2026-10-01", "wrong")
    verdict = payload["curator"]["verdicts"][0]
    assert (verdict["verdict"], verdict["when"], verdict["why"], verdict["keys"]) == ("revocation", "2026-10-02",
                                                                                       "false-positive", 2)
    assert payload["curator"]["manifest"] == {"root_epoch": 1, "version": 3, "keys": 3, "threshold": 2}
    assert payload["curator"]["counted_authors"][0]["org"] == "acme"
    assert payload["curator"]["away"][0]["until"] == "2026-10-05"
    assert (payload["held_back"], payload["pending_tombstones"]) == (7, 2)
    retraction = payload["retractions"][0]
    assert (retraction["identifier"], retraction["who"], retraction["when"]) == ("ioc:domain:mine.example",
                                                                                 "0xretractor", "2026-10-02")


def test_community_strings_are_sanitized(configured):
    identifier = community_routes.community_statements_payload(lambda cfg: _read())["disputes"][0]["identifier"]
    assert "<script>" not in identifier and "&lt;script&gt;" in identifier


def test_unconfigured_and_unreadable_states(monkeypatch, configured):
    assert community_routes.community_statements_payload(lambda cfg: None) == {"configured": True, "available": False}
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: BlackboxConfig())
    assert community_routes.community_statements_payload(lambda cfg: _read()) == {"configured": False}


def test_without_trusted_curator_keys_the_view_says_so(configured):
    read = CommunityRead(ReadState.ROWS)
    assert community_routes.community_statements_payload(lambda cfg: read)["curator"] == {"trusted": False}


def test_the_route_is_served(configured):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    app = fastapi.FastAPI()
    community_routes.register_community_routes(app, community_read=lambda cfg: _read())
    body = TestClient(app).get("/api/community-statements").json()
    assert body["available"] is True and body["disputes"][0]["why"] == "wrong"
