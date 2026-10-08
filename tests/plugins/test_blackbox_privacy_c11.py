"""Community Curation C11 — the privacy documents, consent asked again, and erasure across the new stores.

* The reporter terms changed (the community curators), so a consent given to
  the old text is not in force: sharing stops, the operator is told why in
  every place it could look, and retractions still work.
* The three documents name the community authority and what it decides.
* Erasure on a curator node covers every store this build added that holds
  anything about a reporter; every file the new code writes is classified.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path

import pytest
from _community_rows import GRAPH, Reporter
from test_blackbox_curate_community import Curators, _listing
from test_blackbox_curator_service import FOUND, PKG, Service

from plugins.blackbox.community import consent as consent_module
from plugins.blackbox.community import sharing
from plugins.blackbox.community.report_cli import report_rights, submission_gate
from plugins.blackbox.curate.parser import add_curate_parser
from plugins.blackbox.kernel import health
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

CFG = BlackboxConfig(report=True, community_graph_id=GRAPH)
DOCS = Path(consent_module.TERMS_PATH).parent
FINDING = {"identifier": "dep:npm:evil-pkg@1.0.0", "category": "dependency", "severity": "high", "source": "public",
           "fields": {"ecosystem": "npm", "package_name": "evil-pkg", "package_version": "1.0.0", "kind": "malware",
                      "reason": "install-hook"}}
OLD_TERMS = "# Agent Blackbox — Reporter Terms\n\nVersion: 1.0 (draft)\n\nThe old text.\n"


@pytest.fixture
def consented_to_old_terms(real_consent, monkeypatch, tmp_path):
    """An operator who consented to version 1.0; the shipped terms are now 1.1."""
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    shipped = real_consent.terms_text
    monkeypatch.setattr(real_consent, "terms_text", lambda: OLD_TERMS)
    assert real_consent.record().terms_version == "1.0"
    monkeypatch.setattr(real_consent, "terms_text", shipped)
    return real_consent


# ------------------------------------------------------------------ consent is asked again, and says why


def test_a_consent_to_the_old_terms_is_not_in_force_and_every_gate_says_why(consented_to_old_terms, capsys):
    consent = consented_to_old_terms
    assert not consent.in_force()
    why = consent.why_not()
    assert "the reporter terms changed since you consented to version 1.0" in why and "now version 1.1" in why
    ok, reason = sharing.CommunitySharePolicy(CFG).decide(FINDING, "0x" + "a" * 40)
    assert not ok and reason == why                                                   # automatic sharing stops
    assert submission_gate.refusal_for(CFG, reduction=False) == 2 and why in capsys.readouterr().out   # manual reports stop
    assert submission_gate.refusal_for(CFG, reduction=True) is None                       # retractions and disputes still go


def test_the_consent_prompt_says_why_it_asks_again_and_what_changed(consented_to_old_terms, capsys):
    assert report_rights.record_consent() == 0
    out = capsys.readouterr().out
    asked, changed, full = out.index("You are asked again because"), out.index("## What changed in version 1.1"), out.index("Version: 1.1")
    assert asked < changed < full and "community graph now has its OWN curators" in out
    assert consented_to_old_terms.in_force() and consented_to_old_terms.why_not() == ""
    report_rights.record_consent()
    assert "You are asked again" not in capsys.readouterr().out                       # a current consent is not re-explained


@pytest.mark.parametrize("state, needle", [("never", "no sharing consent is recorded"), ("withdrawn", "sharing consent was withdrawn on")])
def test_never_given_and_withdrawn_are_said_plainly(real_consent, monkeypatch, tmp_path, state, needle):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    if state == "withdrawn":
        real_consent.record(), real_consent.withdraw()
    assert needle in real_consent.why_not()
    monkeypatch.setattr(real_consent, "terms_text", lambda: "")
    assert "terms are missing" in real_consent.why_not()


def test_an_operator_with_sharing_on_and_stale_consent_sees_an_action_item(consented_to_old_terms):
    rs = type("Rs", (), {"synced_at": 1.0, "counts": lambda self: {"injection": 5}, "community_paused": False, "kill_list": {}})()
    why = consented_to_old_terms.why_not()
    items = health.operator_health(health.gather(CFG, rs, True, None, {}, 2.0, sharing_consent_problem=why))
    stopped = [item for item in items if item.message.startswith("community sharing is on but stopped")]
    assert len(stopped) == 1 and stopped[0].klass is health.HealthClass.ACTION and "--consent" in stopped[0].what_to_do
    off = BlackboxConfig(report=False, community_graph_id=GRAPH)                      # sharing off: nothing is stopped
    assert not any("stopped" in item.message for item in health.operator_health(health.gather(off, rs, True, None, {}, 2.0,
                                                                                              sharing_consent_problem=why)))


def test_status_and_the_dashboard_pass_the_consent_state_to_health():
    for path in ("plugins/blackbox/cli.py", "plugins/blackbox/dashboard/community_routes.py"):
        assert "sharing_consent_problem=community.consent.why_not()" in Path(path).read_text(encoding="utf-8"), path


# ------------------------------------------------------------------ the documents


def test_the_terms_name_both_curator_groups_and_what_a_listing_publishes():
    terms = consent_module.terms_text()
    assert consent_module.terms_version(terms) == "1.1" and consent_module.changes_section(terms).startswith("## What changed in version 1.1")
    for phrase in ("COMMUNITY curators", "never block", "at most 90 days", "index", "wallet address", "is not changed",
                   "signed statements", "always a person's decision"):
        assert phrase in terms, phrase
    assert "privacy@umanitek.ai (joint controllers" not in terms                      # contacts live in the controller map


def test_the_controller_map_and_the_dpia_carry_the_community_authority_and_the_open_name():
    controllers = (DOCS / "CONTROLLER_MAP.md").read_text(encoding="utf-8")
    dpia = (DOCS / "DPIA.md").read_text(encoding="utf-8")
    assert "Version: 1.1" in controllers and "Community curators' operator" in controllers and "decision 15" in controllers
    assert "Version: 1.3" in dpia and "community_trust.json" in dpia and "Export bundle" in dpia and "art. 22" in dpia
    checklist = dpia.split("## 8. Compliant-by-default checklist", 1)[1]
    rows = re.findall(r"^\| (?!Item|---)(.+?) \| (\w[\w ,]*?) \|", checklist, re.M)
    assert len(rows) == 10 and {state for _, state in rows} <= {"done", "partly", "not applicable", "done, one name open"}


# ------------------------------------------------------------------ erasure and export cover the new stores


#: Every file the Community Curation build writes on a node, and how the rights treat it. A new
#: file the build writes fails this test until it is classified here and in the DPIA (§2).
CLASSIFIED = {
    "community_trust.json": "public curator statements this reader verified; current-only, pruned",
    "curate/reputation.json": "ledger entries: pseudonymous; erasure removes the entry",
    "curate/reputation_salts.json": "the sealed index: erasure removes the salt",
    "curate/reputation_index.key": "the index key: names nobody",
    "curate/published_statements.json": "statements kept alive: erasure ends keep-alive of those about the reporter",
    "curate/policy_consent.json": "the operator's policy acceptance: names no reporter",
    "curate/service_budget.json": "today's counts: names no reporter",
    "curate/consent.jsonl": "the record of published acts (accountability): codes and summaries",
    "curate/proposals/*.json": "the record of proposed and published statements (accountability)",
    "curate/inbox_cursor.json": "a message position: names nobody",
    "curate/curator_key.pem": "this curator's own key",
    "curate/community_root_key.pem": "the SANDBOX community root key (never on a pinned network)",
}


def _written(home: Path):
    for path in home.rglob("*"):
        if path.is_file():
            relative = str(path.relative_to(home))
            yield re.sub(r"^curate/proposals/[^/]+\.json$", "curate/proposals/*.json", relative)


def test_every_file_the_curation_build_writes_is_classified(tmp_path, monkeypatch):
    service = Service(tmp_path, monkeypatch)
    service.report(PKG)
    service.answers[PKG] = FOUND
    service.beat("A"), service.beat("B")
    homes = [service.team.a.home, service.team.b.home, service.team.c.home, service.team.reader.home]
    written = {name for home in homes for name in _written(home)}
    curation = {name for name in written if name.startswith("curate/") or name == "community_trust.json"}
    assert curation - set(CLASSIFIED) == set(), curation - set(CLASSIFIED)
    assert {"curate/reputation.json", "curate/reputation_salts.json", "community_trust.json"} <= curation


def test_a_curator_erasure_leaves_nothing_that_links_the_reporter_except_the_record_of_published_acts(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _listing(alice))
    with team.b:                                                                     # B published the listing: it keeps it alive
        from plugins.blackbox.community import reputation
        reputation.ReputationLedger().record(alice.author, reputation.Outcome(date.today().isoformat(), True))
        parser = argparse.ArgumentParser()
        add_curate_parser(parser.add_subparsers(), compiled_ruleset=None)
        args = parser.parse_args(["curate", "graduate", "--erase", alice.author])
        assert args.func(args) == 0
        assert reputation.ReputationLedger().keys() == [] and reputation.ReputationLedger().standing(alice.author).confirmed == 0
        from plugins.blackbox.curate.upkeep import published
        assert [entry for entry in published.store().all() if alice.author in json.dumps(entry.as_json())] == []
        home = team.b.home
        linking = sorted(str(path.relative_to(home)) for path in home.rglob("*")
                         if path.is_file() and alice.author in path.read_text(encoding="utf-8", errors="ignore"))
    kept = {re.sub(r"^curate/proposals/[^/]+\.json$", "curate/proposals/*.json", name) for name in linking}
    # only the record of what was published (accountability) and the public statements this reader verified
    assert kept <= {"curate/consent.jsonl", "curate/proposals/*.json", "reports_log.jsonl", "community_trust.json"}, linking


def test_the_explanation_never_disagrees_with_the_gate(monkeypatch, tmp_path):
    """Whatever decides that consent is in force (here the suite's stand-in), the explanation follows it."""
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setattr(consent_module, "in_force", lambda: True)
    assert consent_module.current() is None and consent_module.why_not() == ""
    monkeypatch.setattr(consent_module, "in_force", lambda: False)
    assert consent_module.why_not() != ""
