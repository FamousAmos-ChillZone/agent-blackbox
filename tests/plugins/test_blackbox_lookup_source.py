"""Where a verified answer came from is never silent (DKG-lookup, Amos 2026-10-10):
the panel line, the status text and the finding itself say when the local index
answered because the graph store was down."""

from __future__ import annotations

from types import SimpleNamespace

from plugins.blackbox import detection
from plugins.blackbox.dashboard import sync_meter
from plugins.blackbox.ruleset import compiler, live


def _health(degraded: bool, reason: str = "timeout", since: float = 1_791_600_000.0):
    return SimpleNamespace(degraded=degraded, reason=reason, since=since)


def test_lookup_status_names_each_state():
    ready = live.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset({"g"}))
    assert sync_meter.lookup_status(None, _health(False))["state"] == "not-live"
    assert sync_meter.lookup_status(live.VerifiedScope(), _health(False))["state"] == "not-live"
    assert sync_meter.lookup_status(ready, _health(False)) == {
        "state": "live", "label": "Live from graph", "text": "Verified checks are answered live from the graph on this node."}
    paused = sync_meter.lookup_status(ready, _health(True))
    assert paused["label"] == "Checks paused · graph down"
    assert paused["state"] == "paused" and "PAUSED" in paused["text"] and "timeout" in paused["text"] and "UTC" in paused["text"]
    indexed = live.VerifiedScope(**{**ready.__dict__, "fallback": "index"})
    fallback = sync_meter.lookup_status(indexed, _health(True, "http 503"))
    assert fallback["label"] == "Local index · graph down"
    assert fallback["state"] == "fallback" and "local index" in fallback["text"] and "http 503" in fallback["text"]


def test_the_meter_payload_carries_the_lookup_status(monkeypatch):
    from plugins.blackbox import ruleset
    scope = live.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset({"g"}))
    monkeypatch.setattr(ruleset, "peek", lambda cfg: compiler.Ruleset(verified_scope=scope))
    monkeypatch.setattr(ruleset.live.HEALTH, "read", lambda: _health(True))
    monkeypatch.setattr(ruleset, "verified_download_totals", lambda client, cg, timeout=None: None)
    monkeypatch.setattr(ruleset, "verified_progress", lambda cg: None)
    monkeypatch.setattr(sync_meter, "read_recovery_backlog", lambda home, cg: None)
    cfg = SimpleNamespace(context_graph_id="cg", dkg_url="http://127.0.0.1:9320", dkg_home="/tmp/x")
    meter = sync_meter.read_sync_meter(cfg, node_reachable=True, verified_rules=3)
    assert meter.lookups["state"] == "paused" and meter.verified_rules == 3


def test_a_finding_answered_by_the_local_index_says_so():
    rule = {"identifier": "dep:npm:evil@1.0", "source": "public", "severity": "critical", "kind": "malware"}
    rs = compiler.Ruleset()
    rs.dependency_rules = lambda candidates: live.LookupAnswer({"npm:evil@1.0": rule}, live.HIT, "fallback index")  # type: ignore[method-assign]
    rs.ioc_rules = lambda ids: live.LookupAnswer(   # type: ignore[method-assign]
        {"ioc:ip:203.0.113.9": {"identifier": "ioc:ip:203.0.113.9", "source": "public", "severity": "high", "iocType": "ip"}},
        live.HIT, "fallback index")
    dep = detection.detect_dependency("bash", {"command": "npm install evil@1.0"}, rs)
    assert dep[0].fields["answered_by"] == detection.ANSWERED_BY_FALLBACK and dep[0].confirmed
    ioc = detection.detect_ioc("bash", {"command": "curl 203.0.113.9"}, rs)
    assert ioc[0].fields["answered_by"] == detection.ANSWERED_BY_FALLBACK
    rs.dependency_rules = lambda candidates: live.LookupAnswer({"npm:evil@1.0": rule}, live.HIT, "")  # type: ignore[method-assign]
    assert "answered_by" not in detection.detect_dependency("bash", {"command": "npm install evil@1.0"}, rs)[0].fields


def test_the_local_only_marker_never_reaches_a_shared_report():
    """A finding the local index answered still shares: `answered_by` describes this
    machine's check, not the threat, and the report schema would refuse it."""
    from plugins.blackbox.community import sharing
    finding = {"identifier": "dep:npm:evil@1.0.0", "category": "dependency", "severity": "critical",
               "source": "public", "fields": {"ecosystem": "npm", "package_name": "evil", "package_version": "1.0.0",
                                              "kind": "malware", "advisory_id": "MAL-2026-1", "reason": "advisory:MAL-2026-1",
                                              "answered_by": detection.ANSWERED_BY_FALLBACK}}
    assert "answered_by" not in sharing.shareable_fields(finding)
    assert sharing._schema_decision(finding) == (True, "ok")


def test_an_unreachable_node_is_never_shown_as_live(monkeypatch):
    """Bench A 2026-10-10: the meter said "node offline" while the line still showed the last ✓."""
    from plugins.blackbox import ruleset
    scope = live.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset({"g"}))
    monkeypatch.setattr(ruleset, "peek", lambda cfg: compiler.Ruleset(verified_scope=scope))
    monkeypatch.setattr(ruleset.live.HEALTH, "read", lambda: _health(False))
    monkeypatch.setattr(ruleset, "verified_progress", lambda cg: None)
    monkeypatch.setattr(sync_meter, "read_recovery_backlog", lambda home, cg: None)
    cfg = SimpleNamespace(context_graph_id="cg", dkg_url="http://127.0.0.1:9320", dkg_home="/tmp/x")
    meter = sync_meter.read_sync_meter(cfg, node_reachable=False, verified_rules=1)
    assert meter.state == "unavailable" and meter.lookups["state"] == "unknown"
    assert meter.lookups["label"] == "Node not answering"
