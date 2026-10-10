"""Community Curation C10 — what operators and reporters see.

One read model (``community.trust_panel``) answers "who curates, who is
trusted, what is confirmed, is anything wrong"; the dashboard serves it
(``GET /api/trust``) and `blackbox status` prints it. A reporter sees its
progress toward the trusted list from the public record. The operator's alarms
about the community authority each fire on their condition and not otherwise.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path

import pytest
from _community_rows import GRAPH, Reporter, signed_row
from test_blackbox_authority import CFG, CITED, TODAY, VM_GRAPH, Side
from test_blackbox_curator_view import _entry
from test_blackbox_trust_store import Store

from plugins.blackbox import community
from plugins.blackbox.community import CommunityRead, ReadState
from plugins.blackbox.community.report_cli import report_tracking
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements.curator_statements import CuratorRecord
from plugins.blackbox.dashboard import trust_routes
from plugins.blackbox.community.trust.trust_store import TrustStore
from plugins.blackbox.kernel import health, signing
from plugins.blackbox.kernel.health import community_authority as ca
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

IP = "ioc:ip:203.0.113.7"
PAGE = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "dashboard" / "static" / "index.html"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


def _network(monkeypatch):
    """Both authorities trusted; the verified one lists a partner, the community one lists alice,
    confirms IP with evidence and has ONE of its three keys heartbeating."""
    ours, theirs = Side(GRAPH), Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", ours.root_hex)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", theirs.root_hex)
    alice, acme, newcomer = Reporter("0xa"), Reporter("0xacme"), Reporter("0xnew")
    beating = sorted(ours.manifest.curator_keys)[0]
    signer = next(key for key in ours.curators if signing.public_key_hex(key) == beating)
    heartbeat = cv.curator_statements.sign_statement(Kind.HEARTBEAT, "curator", sequence=1, fields={"key": beating}, key=signer,
                                                     manifest=ours.manifest, graph=GRAPH, day=date.fromisoformat(TODAY))
    beat_row = {"r": cv.curator_statements.statement_subject(Kind.HEARTBEAT, "curator", 1), "identifier": "curator",
                "signedStatement": heartbeat.to_text()}
    node = Store(
        verified=[theirs.manifest_row(), theirs.row(Kind.COUNTED_AUTHORS, f"author:{acme.author}",
                                                    _entry(acme.author, **{"expires": "2027-01-01"}) | {"class": "partner", "org": "acme"})],
        community=[ours.manifest_row(), ours.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author, expires="2026-12-01")),
                   ours.row(Kind.CONFIRMATION, IP, CITED), beat_row],
        reports=[signed_row(IP, alice), signed_row(IP, newcomer), signed_row("ioc:ip:203.0.113.8", newcomer)])
    return node, community.read_verified_reports(node, CFG), (alice, acme, beating)


# ------------------------------------------------------------------ the read model


def test_the_panel_says_who_curates_who_is_trusted_and_what_is_confirmed(monkeypatch):
    _, read, (alice, acme, beating) = _network(monkeypatch)
    panel = community.trust_panel(read, TODAY)
    verified, ours = panel["authorities"]
    assert panel["available"] and (verified["authority"], ours["authority"]) == ("verified", "community")
    assert (verified["trusted"], verified["state"], verified["keys"], verified["threshold"]) == (True, "ok", 3, 2)
    assert all(beat["silent"] and beat["day"] == "" for beat in verified["heartbeats"])          # they never beat here
    assert (ours["trusted"], ours["state"], ours["keys"], ours["threshold"], ours["version"]) == (True, "ok", 3, 2, 1)
    assert [(beat["key"], beat["day"], beat["silent"]) for beat in ours["heartbeats"] if not beat["silent"]] == [(beating, TODAY, False)]
    assert {r["key"]: (r["listed_by"], r["author_class"], r["org"]) for r in panel["reporters"]} == {
        alice.author: ("community", "established", ""), acme.author: ("verified", "partner", "acme")}
    assert panel["confirmed"] == [{"identifier": IP, "evidence": CITED["evidence"], "day": TODAY, "curators": 2, "reporters": 2}]
    assert (panel["held_raising"], panel["lookup_incomplete"]) == (0, False)


def test_a_heartbeat_is_silent_after_48_hours():
    manifest = Side(GRAPH).manifest
    key = manifest.curator_keys[0]
    for age, silent in ((0, False), (2, False), (3, True)):
        view = cv.CuratorView(manifest=manifest, heartbeats={key: (date.fromisoformat(TODAY) - timedelta(days=age)).isoformat()})
        read = CommunityRead(ReadState.ROWS, curator=cv.CuratorView(community=view))
        beat = community.trust_panel(read, TODAY)["authorities"][1]["heartbeats"][0]
        assert (beat["key"], beat["silent"]) == (key, silent), age


def test_a_confirmation_the_verified_authority_overruled_is_not_shown_as_confirmed(monkeypatch):
    ours, theirs = Side(GRAPH), Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", ours.root_hex)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", theirs.root_hex)
    other, rejected = "ioc:ip:203.0.113.9", "ioc:ip:203.0.113.10"
    alice = Reporter("0xa")
    node = Store(verified=[theirs.manifest_row()], reports=[signed_row(IP, alice), signed_row(other, alice), signed_row(rejected, alice)],
                 community=[ours.manifest_row(), ours.row(Kind.CONFIRMATION, IP, CITED), ours.row(Kind.CONFIRMATION, other, CITED),
                            ours.row(Kind.REJECTION, rejected, {"reason": "benign"}),          # the community curators' own rejection
                            theirs.row(Kind.REJECTION, IP, {"reason": "benign"}, graph=GRAPH)])
    read = community.read_verified_reports(node, CFG)
    assert read.curator.community.verdicts[IP].kind is Kind.CONFIRMATION                        # they did confirm it
    assert [entry["identifier"] for entry in community.trust_panel(read, TODAY)["confirmed"]] == [other]


def test_an_unreadable_graph_is_unavailable_never_nothing_trusted():
    for read in (None, CommunityRead(ReadState.UNAVAILABLE, reason="a page failed")):
        panel = community.trust_panel(read)
        assert not panel["available"] and panel["authorities"] == [] and panel["reason"]
    assert community.trust_status_lines(community.trust_panel(None)) == ["  trust:             unavailable (not read yet)"]


def test_no_authority_on_the_network_is_said_plainly():
    panel = community.trust_panel(CommunityRead(ReadState.ROWS), TODAY)
    assert [(a["trusted"], a["state"]) for a in panel["authorities"]] == [(False, "none"), (False, "none")]
    lines = community.trust_status_lines(panel)
    assert lines[0] == "  verified trust:    no curators trusted on this network"
    assert lines[1] == "  community trust:   no curators trusted on this network"


def test_manifest_states_and_the_readers_own_limits_reach_the_panel():
    manifest = Side(GRAPH).manifest
    ours = cv.CuratorView(manifest=manifest, manifest_state="stale", manifest_state_day="2026-09-30",
                          manifest_expires_day="2026-09-30", held_raising=4, lookup_incomplete=True)
    panel = community.trust_panel(CommunityRead(ReadState.ROWS, curator=cv.CuratorView(community=ours)), TODAY)
    facts = panel["authorities"][1]
    assert (facts["state"], facts["state_day"], facts["expires"]) == ("stale", "2026-09-30", "2026-09-30")
    assert (panel["held_raising"], panel["lookup_incomplete"]) == (4, True)
    conflict = community.trust_panel(CommunityRead(ReadState.ROWS, curator=cv.CuratorView(
        community=cv.CuratorView(manifest_conflict=True))), TODAY)["authorities"][1]
    assert (conflict["trusted"], conflict["state"]) == (False, "conflict")


# ------------------------------------------------------------------ status lines


def test_status_prints_the_same_facts(monkeypatch):
    _, read, _ = _network(monkeypatch)
    lines = community.trust_status_lines(community.trust_panel(read, TODAY))
    assert lines == [
        "  verified trust:    2 of 3 curator keys sign (manifest v1) · 0 of 3 alive",
        "  community trust:   2 of 3 curator keys sign (manifest v1) · 1 of 3 alive",
        "  trusted reporters: 2 (1 listed by the community curators)",
        "  confirmed pool:    1 threat(s) confirmed by the community curators",
    ]


def test_blackbox_status_prints_the_trust_lines_beside_the_health_items(monkeypatch, capsys):
    from plugins.blackbox import cli
    _, read, _ = _network(monkeypatch)
    monkeypatch.setattr(cli.community, "read_verified_reports", lambda client, cfg: read)
    rs = type("Rs", (), {"synced_at": 1.0, "counts": lambda self: {"injection": 5}, "community_paused": False, "kill_list": {}})()
    cli._print_health(CFG, rs, object(), True)
    printed = capsys.readouterr().out.splitlines()
    assert "  community trust:   2 of 3 curator keys sign (manifest v1) · 1 of 3 alive" in printed
    assert "  confirmed pool:    1 threat(s) confirmed by the community curators" in printed
    assert all(line[:21].strip().endswith(":") for line in printed if line.strip())      # every value starts in one column
    cli._print_health(CFG, rs, object(), False)                                          # the node is down: said, not guessed
    assert "  trust:             unavailable (not read yet)" in capsys.readouterr().out.splitlines()
    cli._print_health(replace(CFG, community_graph_id=""), rs, object(), True)
    assert "trust" not in capsys.readouterr().out


# ------------------------------------------------------------------ the endpoint


def test_the_endpoint_serves_each_fact(monkeypatch):
    _, read, (alice, acme, beating) = _network(monkeypatch)
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: CFG)
    payload = trust_routes.trust_payload(lambda cfg: read)
    assert payload["configured"] and payload["available"] and (payload["reporters_total"], payload["confirmed_total"]) == (2, 1)
    ours = payload["authorities"][1]
    assert (ours["authority"], ours["trusted"], ours["threshold"], ours["keys"]) == ("community", True, 2, 3)
    assert {"key": beating[:16], "day": TODAY, "silent": False} in ours["heartbeats"]
    assert {r["key"] for r in payload["reporters"]} == {alice.author[:16], acme.author[:16]}                # shortened keys only
    assert payload["confirmed"][0]["identifier"] == IP and payload["confirmed"][0]["evidence"] == CITED["evidence"]


def test_the_endpoint_sanitizes_every_string_that_came_from_someone_else(monkeypatch):
    hostile = "acme\x1b[31m‮<script>alert(1)</script>" + "x" * 400
    panel = community.trust_panel(CommunityRead(ReadState.ROWS), TODAY)
    panel["reporters"] = [{"key": "a" * 64, "address": hostile, "author_class": hostile, "org": hostile, "expires": hostile,
                           "listed_by": "community"}]
    panel["confirmed"] = [{"identifier": "ioc:url:https://evil.example/\x1b[2J" + "y" * 900, "day": hostile, "curators": 2, "reporters": 1,
                           "evidence": "registry-action:https://evil.example/takedown‮"}]
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: CFG)
    monkeypatch.setattr(community, "trust_panel", lambda read: panel)
    payload = trust_routes.trust_payload(lambda cfg: None)
    reporter, entry = payload["reporters"][0], payload["confirmed"][0]
    served = [reporter["address"], reporter["class"], reporter["org"], reporter["expires"], entry["identifier"], entry["evidence"], entry["when"]]
    assert all("\x1b" not in value and "‮" not in value for value in served)
    assert (len(reporter["address"]), len(reporter["org"]), len(reporter["class"]), len(reporter["expires"])) == (64, 64, 16, 16)
    assert len(entry["identifier"]) <= 512 and "evil[.]example" in entry["evidence"] and "hxxps" in entry["evidence"]   # defanged
    assert reporter["key"] == "a" * 16


def test_the_endpoint_says_unconfigured_and_unavailable(monkeypatch):
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: replace(CFG, community_graph_id=""))
    assert trust_routes.trust_payload(lambda cfg: None) == {"configured": False}
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: CFG)
    assert trust_routes.trust_payload(lambda cfg: None) == {"configured": True, "available": False, "reason": "not read yet"}


def test_the_route_is_served_and_the_page_asks_for_it(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from plugins.blackbox.dashboard import community_routes
    _, read, _ = _network(monkeypatch)
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: CFG)
    app = FastAPI()
    community_routes.register_community_routes(app, community_read=lambda cfg: read)
    response = TestClient(app, base_url="http://127.0.0.1").get("/api/trust")
    assert response.status_code == 200 and response.json()["confirmed_total"] == 1
    # The dashboard's Community graph section (and its Trust pane) was removed at Amos's direction
    # (2026-10-10); /api/trust stays for `blackbox status` parity and other clients.
    assert 'id="community-panel"' not in PAGE.read_text(encoding="utf-8")


# ------------------------------------------------------------------ a reporter's progress


def _reporter_read(confirmed, first_day, *, manifest=True):
    """A read in which `own` has six reports, the first on *first_day*, *confirmed* of them confirmed."""
    own = "f" * 64
    reports = tuple(community.VerifiedReport(subject=f"s{n}", identifier=f"ioc:ip:198.51.100.{n}", author=own,
                                             reporter="0x" + "f" * 40, severity="high", day=first_day if n == 0 else TODAY)
                    for n in range(6))
    verdicts = {f"ioc:ip:198.51.100.{n}": CuratorRecord(kind=Kind.CONFIRMATION, identifier=f"ioc:ip:198.51.100.{n}", sequence=1,
                                                         day=TODAY, fields=(("evidence", "advisory:MAL-1"),), signers=frozenset({"a" * 64, "b" * 64}))
                for n in range(confirmed)}
    ours = cv.CuratorView(manifest=Side(GRAPH).manifest if manifest else None, verdicts=verdicts)
    return own, CommunityRead(ReadState.ROWS, reports=reports, curator=cv.CuratorView(verdicts=verdicts, community=ours))


@pytest.mark.parametrize("confirmed, days, line", [
    (0, 0, "confirmed 0 of 5 · day 0 of 14"),
    (4, 13, "confirmed 4 of 5 · day 13 of 14"),
    (5, 13, "confirmed 5 of 5 · day 13 of 14"),
    (4, 14, "confirmed 4 of 5 · day 14 of 14"),
    (5, 14, "confirmed 5 of 5 · day 14 of 14 — both are met on the public record"),
    (6, 40, "confirmed 5 of 5 · day 14 of 14 — both are met on the public record"),
])
def test_standing_counts_confirmed_reports_and_days_at_the_boundaries(confirmed, days, line):
    own, read = _reporter_read(confirmed, (date.fromisoformat(TODAY) - timedelta(days=days)).isoformat())
    assert report_tracking.graduation_progress(own, read, TODAY) == (confirmed, days)
    lines = report_tracking.standing_lines(own, read, TODAY)
    assert "PROBATION" in lines[0] and line in lines[1]
    assert ("both are met" in lines[1]) == (confirmed >= 5 and days >= 14)


def test_a_trusted_reporter_sees_its_listing_and_no_progress_line_and_no_authority_is_said_plainly():
    own, read = _reporter_read(2, TODAY)
    listed = replace(read, curator=replace(read.curator, counted={own: cv.CountedAuthor(
        key=own, address="0x" + "f" * 40, author_class="established", org="", expires="2026-12-01")}))
    lines = report_tracking.standing_lines(own, listed, TODAY)
    assert "COUNTED (established) until 2026-12-01" in lines[0] and not any("Toward the trusted list" in line for line in lines)
    own, nobody = _reporter_read(0, TODAY, manifest=False)
    assert "no curator key manifest is trusted" in report_tracking.standing_lines(own, nobody, TODAY)[0]


# ------------------------------------------------------------------ the operator's alarms


HEALTHY = ca.CommunityAuthorityInputs(trusted=True, keys=3, silent_keys=0, last_heartbeat=TODAY, today=TODAY)


@pytest.mark.parametrize("change, klass, needle", [
    ({"lookup_incomplete": True}, "info", "trust lookup was cut short"),
    ({"held_raising": 3}, "info", "3 community confirmation(s) or listing(s) held by this node's daily cap"),
    ({"silent_keys": 3, "last_heartbeat": "2026-09-20"}, "info", "the community curators are silent since 2026-09-20"),
    ({"silent_keys": 3, "last_heartbeat": ""}, "info", "the community curators are silent (no heartbeat seen yet)"),
    ({"silent_keys": 1}, "info", "community curator heartbeat missing for 1 of 3 key(s)"),
    ({"manifest_state": "stale", "manifest_state_day": "2026-09-30"}, "info", "community curator key manifest STALE since 2026-09-30"),
    ({"manifest_state": "pending", "manifest_state_day": "2026-10-05"}, "info", "takes effect on 2026-10-05"),
    ({"manifest_expires_day": "2026-10-20"}, "info", "community curator key manifest expires on 2026-10-20"),
    ({"manifest_conflict": True}, "security", "community curator key manifest CONFLICT"),
])
def test_each_alarm_fires_on_its_condition_with_a_class_and_a_what_to_do(change, klass, needle):
    assert ca.alarms(HEALTHY) == []                                       # and not otherwise
    fired = ca.alarms(replace(HEALTHY, **change))
    assert len(fired) == 1 and fired[0][0] == klass and needle in fired[0][1] and fired[0][2]


def test_a_key_counts_as_silent_only_after_the_48_hour_window():
    manifest = Side(GRAPH).manifest
    fresh, edge, old = manifest.curator_keys
    def day(age):
        return (date.fromisoformat(TODAY) - timedelta(days=age)).isoformat()
    inputs = ca.gather(cv.CuratorView(manifest=manifest, heartbeats={fresh: day(0), edge: day(2), old: day(3)}), TODAY)
    assert (inputs.trusted, inputs.keys, inputs.silent_keys, inputs.last_heartbeat) == (True, 3, 1, TODAY)
    assert ca.gather(cv.CuratorView(manifest=manifest), TODAY).silent_keys == 3                # never beat: all silent
    assert ca.gather(None, TODAY) == ca.CommunityAuthorityInputs(today=TODAY)


def test_alarms_do_not_fire_outside_their_condition():
    assert ca.alarms(ca.CommunityAuthorityInputs(today=TODAY)) == []      # no community authority at all: nothing to say
    far = replace(HEALTHY, manifest_expires_day=(date.fromisoformat(TODAY) + timedelta(days=31)).isoformat())
    past = replace(HEALTHY, manifest_expires_day="2026-09-01")
    assert ca.alarms(far) == [] and ca.alarms(past) == []
    stale = ca.alarms(replace(HEALTHY, manifest_state="stale", manifest_state_day="2026-09-30", manifest_expires_day="2026-09-30"))
    assert len(stale) == 1                                                # stale is said once, not as "expires" too
    untrusted = ca.alarms(ca.CommunityAuthorityInputs(trusted=False, keys=3, silent_keys=3, today=TODAY))
    assert untrusted == []                                                # silence of curators nobody trusts is not an alarm


def test_the_alarms_reach_the_operators_health_from_a_real_read(monkeypatch):
    node, read, _ = _network(monkeypatch)
    rs = type("Rs", (), {"synced_at": 1.0, "counts": lambda self: {"injection": 5}, "community_paused": False, "kill_list": {}})()
    items = health.operator_health(health.gather(CFG, rs, True, read, {}, 2.0))
    messages = [item.message for item in items]
    assert "community curator heartbeat missing for 2 of 3 key(s)" in messages
    assert not any("no trusted curator keys" in message for message in messages)
    assert all(item.klass is health.HealthClass.INFO for item in items if "community curator" in item.message)
    node.failing_statements = True                                        # the trust lookup now fails: the node keeps what it stored
    again = community.read_verified_reports(node, CFG)
    assert again.available and again.curator.community.lookup_incomplete and again.curator.verdict(IP) is Kind.CONFIRMATION
    after = [item.message for item in health.operator_health(health.gather(CFG, rs, True, again, {}, 2.0))]
    assert any("trust lookup was cut short" in message for message in after)


def test_only_a_community_authority_still_counts_as_trusted_curators(monkeypatch):
    ours = Side(GRAPH)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", ours.root_hex)
    read = community.read_verified_reports(Store(community=[ours.manifest_row()], reports=[signed_row(IP, Reporter("0xa"))]), CFG)
    rs = type("Rs", (), {"synced_at": 1.0, "counts": lambda self: {"injection": 5}, "community_paused": False, "kill_list": {}})()
    messages = [item.message for item in health.operator_health(health.gather(CFG, rs, True, read, {}, 2.0))]
    assert not any("no trusted curator keys" in message for message in messages)
    assert "the community curators are silent (no heartbeat seen yet)" in messages
    TrustStore().forget()                                                  # a node that never saw that manifest
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS")
    nobody = community.read_verified_reports(Store(reports=[signed_row(IP, Reporter("0xa"))]), CFG)
    assert any("no trusted curator keys" in item.message for item in health.operator_health(health.gather(CFG, rs, True, nobody, {}, 2.0)))
