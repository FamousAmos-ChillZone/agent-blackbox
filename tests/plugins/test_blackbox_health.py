"""Refine R10 — reporter + operator surfaces lite.

One health item feeds both surfaces: every operator state carries a
what-to-do line, INFO never renders red, ACTION/SECURITY sort first.
`report --status` says what happened to each report (share outcome, then the
threat's local stage and reason); `--standing` says counted or probation with
a co-sighting estimate; the dashboard serves the same health items and the
"My reports" rows.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.community import CommunityRead, ReadState
from plugins.blackbox.community.report_cli import report_tracking
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements.curator_statements import CuratorRecord
from plugins.blackbox.community.statements.digests import HeatEstimate
from plugins.blackbox.community.verification import VerifiedReport
from plugins.blackbox.dashboard import community_routes
from plugins.blackbox.kernel import health
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import compiler

GRAPH = "0x51E5dE758A45/agent-blackbox-community-dev"
THREAT = "dep:npm:evil@1.0.0"


def _inputs(**over):
    base = dict(node_reachable=True, ruleset_age_s=60.0, sync_interval_s=300.0, rule_count=10,
                community_configured=True, curator_trusted=True)
    base.update(over)
    return health.HealthInputs(**base)


# ------------------------------------------------------------------ the health rules


def test_a_healthy_node_has_nothing_to_do():
    assert health.operator_health(_inputs()) == []
    assert health.render_lines([]) == ["  health:            ok — nothing to do"]


@pytest.mark.parametrize("over, klass, needle", [
    ({"node_reachable": False}, health.HealthClass.ACTION, "stale"),
    ({"ruleset_age_s": 2_000.0}, health.HealthClass.ACTION, "stale"),
    ({"ruleset_age_s": None}, health.HealthClass.ACTION, "stale"),
    ({"rule_count": 0}, health.HealthClass.ACTION, "UNPROTECTED"),
    ({"read_unavailable_reason": "node status unavailable"}, health.HealthClass.INFO, "could not be read"),
    ({"community_paused": True}, health.HealthClass.INFO, "paused"),
    ({"curator_trusted": False}, health.HealthClass.INFO, "no trusted curator keys"),
    ({"backlog": "3,4,5"}, health.HealthClass.INFO, "BACKLOG"),
    ({"away_keys": 1}, health.HealthClass.INFO, "away"),
    ({"revoked": {THREAT: 0}}, health.HealthClass.INFO, "REVOKED"),
    ({"revoked": {THREAT: 3}}, health.HealthClass.ACTION, "blocked 3"),
    ({"held_back": 7}, health.HealthClass.INFO, "held"),
])
def test_every_operator_state_has_a_class_and_a_what_to_do(over, klass, needle):
    items = health.operator_health(_inputs(**over))
    assert len(items) == 1 and items[0].klass is klass and needle in items[0].message + " " + items[0].what_to_do
    assert items[0].what_to_do and items[0].audience == "operator"


def test_info_is_never_red_and_action_sorts_first():
    items = health.operator_health(_inputs(node_reachable=False, community_paused=True, held_back=2))
    assert [i.klass for i in items][0] is health.HealthClass.ACTION
    assert all(not health.red(i) for i in items if i.klass is health.HealthClass.INFO)
    assert health.red(items[0])


def test_gather_reads_the_ruleset_and_the_community_read():
    rs = compiler.Ruleset()
    rs.synced_at = 1_000.0
    rs.community_paused = True
    rs.ioc = {"ioc:domain:x.example": {"identifier": "ioc:domain:x.example", "source": "public"}}
    manifest = km.KeyManifest(environment="n", graph="vm", chain="", root_epoch=1, version=1, curator_keys=("a" * 64, "b" * 64),
                              threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    revoked = CuratorRecord(kind=Kind.REVOCATION, identifier=THREAT, sequence=2, day="2026-10-02",
                            fields=(("reason", "false-positive"),), signers=frozenset({"a" * 64}))
    read = CommunityRead(ReadState.ROWS, held_back=4, curator=cv.CuratorView(manifest=manifest, verdicts={THREAT: revoked}))
    inputs = health.gather(BlackboxConfig(community_graph_id=GRAPH, sync_interval=300), rs, True, read, {THREAT: 2}, 1_600.0)
    assert (inputs.ruleset_age_s, inputs.rule_count, inputs.community_paused, inputs.curator_trusted) == (600.0, 1, True, True)
    assert inputs.revoked == {THREAT: 2} and inputs.held_back == 4
    assert health.ruleset_age_text(inputs.ruleset_age_s) == "10 min ago"


# ------------------------------------------------------------------ what happened to my report


def test_outcome_line_carries_the_share_outcome_then_the_stage_and_reason():
    row = {"ts": "2026-10-02T06:00:00Z", "identifier": THREAT, "category": "dependency", "ok": True, "outcome": "accepted"}
    compiled = {THREAT: {"stage": "corroborated", "enforcement": "flag", "stageReason": "corroborated by 3 partner clusters"}}
    line = report_tracking.outcome_line(row, compiled)
    assert "[ok]" in line and "corroborated (flag)" in line and "3 partner" in line
    assert "not in the compiled community tier" in report_tracking.outcome_line(row, {})
    assert "[already shared]" in report_tracking.outcome_line({**row, "outcome": "already-shared"}, {})


def test_standing_says_counted_or_probation_with_co_sightings():
    own, other = "c" * 64, "d" * 64
    reports = (VerifiedReport("s1", THREAT, own, "0x1", "high"), VerifiedReport("s2", "ioc:domain:x", other, "0x2", "high"))
    heat = {THREAT: HeatEstimate(THREAT, "2026-W40", 56, 2)}
    manifest = km.KeyManifest(environment="n", graph="vm", chain="", root_epoch=1, version=1, curator_keys=("a" * 64, "b" * 64),
                              threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    counted = cv.CuratorView(manifest=manifest, counted={own: cv.CountedAuthor(own, "0x1", "partner", "acme", "2027-01-01")})
    lines = report_tracking.standing_lines(own, CommunityRead(ReadState.ROWS, reports=reports, heat=heat, curator=counted))
    assert lines[0].startswith("Standing: COUNTED (partner, acme)") and "~56 agent" in lines[1] and "1 verified report" in lines[1]
    probation = report_tracking.standing_lines(own, CommunityRead(ReadState.ROWS, reports=reports, curator=cv.CuratorView(manifest=manifest)))
    assert probation[0].startswith("Standing: PROBATION")
    no_manifest = report_tracking.standing_lines(own, CommunityRead(ReadState.ROWS, reports=reports))
    assert "no curator key manifest" in no_manifest[0]
    assert "do not build reputation" in lines[-1]


# ------------------------------------------------------------------ the dashboard


def test_api_health_and_my_reports_serve_the_same_facts(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from plugins.blackbox import audit
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    rs = compiler.Ruleset()
    rs.community = {THREAT: {"stage": "reported", "enforcement": "monitor", "stageReason": "reported by unlisted authors only"}}
    monkeypatch.setattr("plugins.blackbox.ruleset.peek", lambda cfg=None: rs)
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: BlackboxConfig(community_graph_id=GRAPH))
    audit.record_share_outcome(identifier=THREAT, category="dependency", severity="high", subject="s", asset_name="n",
                               ok=True, outcome="accepted")
    app = FastAPI()
    community_routes.register_community_routes(app, community_read=lambda cfg: None, node_reachable=lambda cfg: False)
    client = TestClient(app)
    items = client.get("/api/health").json()["items"]
    assert any(i["class"] == "action" and i["red"] for i in items)          # node unreachable -> ACTION, red
    assert all(not i["red"] for i in items if i["class"] == "info")        # INFO never red
    row = client.get("/api/reports").json()["outbound"][0]
    assert (row["identifier"], row["outcome"], row["stage"]) == (THREAT, "accepted", "reported")
    assert "unlisted" in row["stage_reason"]


def test_the_audit_counts_only_the_firings_that_blocked(monkeypatch, tmp_path):
    """KI-189: the hook's decision travels with the finding; a flag-only firing is not a lost action."""
    from plugins.blackbox import audit
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    finding = {"identifier": THREAT, "category": "dependency", "severity": "critical", "title": "t"}
    audit.record(event="pre_tool_call", findings=[finding], detail={"tool_name": "terminal", "decision": "block"})
    audit.record(event="pre_tool_call", findings=[finding], detail={"tool_name": "terminal", "decision": "flag"})
    audit.record(event="pre_tool_call", findings=[finding], detail={"tool_name": "terminal"})      # a pre-KI-189 row
    assert audit.blocked_counts_by_identifier() == {THREAT: 1}
    assert [row["decision"] for row in audit.read_findings(limit=10)].count("block") == 1
