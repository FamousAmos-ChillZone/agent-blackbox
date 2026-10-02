"""Refine R3 — local stages from the counted-author list.

Every node computes the same stage for the same inputs (table-driven per
type), stages below VERIFIED never change blocking, an unavailable read
freezes the last stages, and verified rules never expire. MONITOR-level
community rules never fire in the hot path.
"""

from __future__ import annotations

import pytest
from _community_rows import GRAPH, Reporter, signed_row

from plugins.blackbox.community import CommunityRead, ReadState, aggregate_community_reports, stages
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.stages import Enforcement, Stage
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

DAY = 86_400
NOW = 1_800_000_000.0


def _view(partners=(), established=()):
    """partners: [(key, org)]; established: [key]."""
    counted = {k: cv.CountedAuthor(k, "0x" + k[:40], "partner", org, "2027-01-01") for k, org in partners}
    counted.update({k: cv.CountedAuthor(k, "0x" + k[:40], "established", "", "2027-01-01") for k in established})
    return cv.CuratorView(counted=counted)


def _keys(prefix, n):
    return [f"{prefix}{i:02d}".ljust(64, "0") for i in range(n)]


def _stage(identifier, authors, view, *, days=10, dispute_weight=0, verdict=None):
    return stages.stage_for(identifier, authors, NOW - days * DAY, view, dispute_weight, verdict, NOW)


# ------------------------------------------------------------------ the table


@pytest.mark.parametrize("identifier, partners_by_org, established, days, stage, enforcement", [
    # IOC class: 2 PARTNER orgs, or 1 PARTNER + 2 ESTABLISHED, or 5 ESTABLISHED, over 2 days
    ("ioc:ip:203.0.113.7", 2, 0, 2, Stage.CORROBORATED, Enforcement.FLAG),
    ("ioc:ip:203.0.113.7", 1, 2, 2, Stage.CORROBORATED, Enforcement.FLAG),
    ("ioc:ip:203.0.113.7", 0, 5, 2, Stage.CORROBORATED, Enforcement.FLAG),
    ("ioc:ip:203.0.113.7", 0, 4, 2, Stage.REPORTED, Enforcement.FLAG),          # counted but short of the table
    ("ioc:ip:203.0.113.7", 2, 0, 1, Stage.REPORTED, Enforcement.FLAG),          # class count met, span too short
    ("ioc:ip:203.0.113.7", 0, 0, 30, Stage.REPORTED, Enforcement.MONITOR),      # unlisted authors only (decision 15)
    # a domain flags only with a PARTNER cluster, even when corroborated
    ("ioc:domain:evil.example", 0, 5, 2, Stage.CORROBORATED, Enforcement.MONITOR),
    ("ioc:domain:evil.example", 1, 2, 2, Stage.CORROBORATED, Enforcement.FLAG),
    ("ioc:wallet:0xabc", 0, 6, 2, Stage.CORROBORATED, Enforcement.MONITOR),
    # malware class: 3 PARTNER orgs, or 2 + 2, or 8 ESTABLISHED, over 3 days
    ("dep:npm:evil@1.0.0", 3, 0, 3, Stage.CORROBORATED, Enforcement.FLAG),
    ("dep:npm:evil@1.0.0", 2, 2, 3, Stage.CORROBORATED, Enforcement.FLAG),
    ("dep:npm:evil@1.0.0", 0, 8, 3, Stage.CORROBORATED, Enforcement.FLAG),
    ("dep:npm:evil@1.0.0", 2, 1, 3, Stage.REPORTED, Enforcement.FLAG),
    ("dep:npm:evil@1.0.0", 3, 0, 2, Stage.REPORTED, Enforcement.FLAG),
    ("escalation:terminal:rm-rf-system-paths", 0, 8, 3, Stage.CORROBORATED, Enforcement.FLAG),
    ("skill:artifact:" + "a" * 64 + ":obfuscation", 0, 7, 3, Stage.REPORTED, Enforcement.FLAG),
])
def test_the_class_count_table_per_type(identifier, partners_by_org, established, days, stage, enforcement):
    partner_keys = _keys("p", partners_by_org)
    established_keys = _keys("e", established)
    view = _view([(k, f"org{i}") for i, k in enumerate(partner_keys)], established_keys)
    result = _stage(identifier, partner_keys + established_keys, view, days=days)
    assert (result.stage, result.enforcement) == (stage, enforcement), result.reason
    assert result.source == "local"


def test_a_partner_organisation_is_one_cluster_however_many_keys_it_runs():
    keys = _keys("p", 6)
    view = _view([(k, "acme") for k in keys])                        # six keys, ONE organisation
    assert _stage("ioc:ip:203.0.113.7", keys, view).stage is Stage.REPORTED
    view = _view([(k, f"org{i % 2}") for i, k in enumerate(keys)])  # two organisations
    assert _stage("ioc:ip:203.0.113.7", keys, view).stage is Stage.CORROBORATED


# ------------------------------------------------------------------ holds, verdicts, expiry, disputes


def test_a_whole_package_report_is_held_at_weight_zero():
    keys = _keys("p", 3)
    result = _stage("dep:npm:evil@*", keys, _view([(k, f"org{i}") for i, k in enumerate(keys)]))
    assert (result.stage, result.enforcement) == (Stage.HELD, Enforcement.MONITOR)


def test_curator_verdicts_decide_the_stage():
    keys = _keys("p", 3)
    view = _view([(k, f"org{i}") for i, k in enumerate(keys)])
    assert _stage("dep:npm:x@1", keys, view, verdict=Kind.REJECTION).stage is Stage.REJECTED
    assert _stage("dep:npm:x@1", keys, view, verdict=Kind.REVOCATION).stage is Stage.REVOKED
    deferred = _stage("dep:npm:x@1", keys, view, verdict=Kind.DEFERRAL)
    assert (deferred.stage, deferred.enforcement) == (Stage.DEFERRED, Enforcement.MONITOR)
    lapsed = _stage("dep:npm:x@1", keys, view, verdict=Kind.DEFERRAL_LAPSED)
    assert lapsed.stage is Stage.CORROBORATED and "lapsed" in lapsed.reason
    confirmed = _stage("dep:npm:x@1", _keys("u", 1), cv.CuratorView(), verdict=Kind.CONFIRMATION)
    assert (confirmed.stage, confirmed.enforcement) == (Stage.CORROBORATED, Enforcement.FLAG)
    for verdict in (Kind.REJECTION, Kind.REVOCATION, Kind.DEFERRAL):
        assert _stage("dep:npm:x@1", keys, view, verdict=verdict).enforcement is Enforcement.MONITOR


def test_community_stages_expire_by_type_lifetime_on_reader_observed_time():
    keys = _keys("p", 3)
    view = _view([(k, f"org{i}") for i, k in enumerate(keys)])
    assert _stage("ioc:ip:203.0.113.7", keys, view, days=47).stage is Stage.CORROBORATED
    assert _stage("ioc:ip:203.0.113.7", keys, view, days=48).stage is Stage.EXPIRED
    assert _stage("dep:npm:x@1", keys, view, days=460).stage is Stage.CORROBORATED
    assert _stage("dep:npm:x@1", keys, view, days=461).stage is Stage.EXPIRED


def test_a_dispute_tags_but_only_enough_counted_disputes_decay():
    keys = _keys("p", 3)
    view = _view([(k, f"org{i}") for i, k in enumerate(keys)])
    tagged = _stage("dep:npm:x@1", keys, view, dispute_weight=1)
    assert tagged.disputed and tagged.enforcement is Enforcement.FLAG
    decayed = _stage("dep:npm:x@1", keys, view, dispute_weight=3)
    assert decayed.disputed and decayed.enforcement is Enforcement.MONITOR and decayed.stage is Stage.CORROBORATED


def test_two_nodes_reading_the_same_list_compute_identical_stages():
    keys = _keys("e", 9)
    inputs = [("dep:npm:x@1", keys[:8]), ("ioc:ip:1.2.3.4", keys[:5]), ("ioc:domain:a.example", keys[:2])]
    node_a = [_stage(i, a, _view(established=keys)).as_fields() for i, a in inputs]
    node_b = [_stage(i, list(reversed(a)), _view(established=list(reversed(keys)))).as_fields() for i, a in inputs]
    assert node_a == node_b


# ------------------------------------------------------------------ in the ruleset


def _read(reports, view):
    return CommunityRead(ReadState.ROWS, reports=tuple(reports), curator=view)


class _FrozenClient:
    def status(self):
        return {"networkId": "n"}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        return on_error


def test_the_tier_stores_stage_reason_and_source_and_materializes_only_flag_level(monkeypatch):
    from plugins.blackbox.community.verification import VerifiedReport
    listed, unlisted = "c" * 64, "u" * 64
    reports = [VerifiedReport("s1", "ioc:domain:listed.example", listed, "0x1", "high", (("iocType", "domain"),)),
               VerifiedReport("s2", "ioc:domain:unlisted.example", unlisted, "0x2", "high", (("iocType", "domain"),))]
    view = _view(partners=[(listed, "acme")])
    monkeypatch.setattr(community_tier.community, "read_verified_reports", lambda c, cfg: _read(reports, view))
    monkeypatch.setattr(community_tier.community, "community_pause_active", lambda c, cfg: False)
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda c, cfg: None)
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, _FrozenClient(), BlackboxConfig(community_graph_id=GRAPH))
    flagged, monitored = rs.community["ioc:domain:listed.example"], rs.community["ioc:domain:unlisted.example"]
    assert (flagged["stage"], flagged["enforcement"], flagged["stageSource"]) == ("reported", "flag", "local")
    assert (monitored["stage"], monitored["enforcement"]) == ("reported", "monitor") and monitored["stageReason"]
    assert "ioc:domain:listed.example" in rs.ioc and "ioc:domain:unlisted.example" not in rs.ioc   # never fires
    entry = next(e for e in rs.graph_entries("community") if e["identifier"] == "ioc:domain:unlisted.example")
    assert entry["stage"] == "reported" and entry["enforcement"] == "monitor" and entry["stageReason"]


def test_an_unavailable_read_freezes_the_last_stages():
    prior = compiler.Ruleset()
    prior.community = {"dep:npm:x@1": {"identifier": "dep:npm:x@1", "severity": "high", "source": "community",
                                       "reporterCount": 3, "firstSeen": 5.0, "stage": "corroborated",
                                       "enforcement": "flag", "stageReason": "r", "stageSource": "local"}}
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, _FrozenClient(), BlackboxConfig(community_graph_id=GRAPH), prior)
    assert rs.community["dep:npm:x@1"]["stage"] == "corroborated"


def test_verified_rules_never_expire_or_gain_a_stage(monkeypatch):
    """Stages are a COMMUNITY concept: the verified tier is untouched however old."""
    monkeypatch.setattr(community_tier.community, "read_verified_reports",
                        lambda c, cfg: _read([], cv.CuratorView()))
    monkeypatch.setattr(community_tier.community, "community_pause_active", lambda c, cfg: False)
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda c, cfg: None)
    rs = compiler.Ruleset()
    rs.ioc = {"ioc:ip:203.0.113.7": {"identifier": "ioc:ip:203.0.113.7", "source": "public", "severity": "high"}}
    community_tier.apply_community_tier(rs, _FrozenClient(), BlackboxConfig(community_graph_id=GRAPH))
    assert rs.ioc["ioc:ip:203.0.113.7"]["source"] == "public" and "stage" not in rs.ioc["ioc:ip:203.0.113.7"]


def test_aggregation_carries_the_signers_a_stage_needs():
    one, two = Reporter("0xa"), Reporter("0xb")
    from plugins.blackbox.community.verification import ReportVerifier, verify_report_rows
    from _community_rows import NETWORK
    reports, _ = verify_report_rows([signed_row("ioc:domain:x.example", one), signed_row("ioc:domain:x.example", two)],
                                    ReportVerifier(NETWORK, GRAPH))
    rule = aggregate_community_reports(reports, {})[0]
    assert rule.authors == tuple(sorted((one.author, two.author)))
