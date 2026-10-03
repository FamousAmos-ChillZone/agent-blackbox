"""Community Curation C9 — the curator service's beat.

Three curator machines, a reader and reporters share one in-memory network
(``_machines``); reports are built by the product's own writer. Each curator
machine runs its own :class:`Beat` with its OWN advisory lookup, so a test can
make one node find an advisory and another not.

The item's done-when: a malicious dependency reported by a trusted reporter is
CONFIRMED on a reader with no human command, and every human-only action is
refused by the service.
"""

from __future__ import annotations

import dataclasses
import json
import time
from datetime import date, timedelta

import pytest
from _community_rows import GRAPH, Reporter
from _machines import SWM, share_report
from test_blackbox_curate_community import CFG, EVIDENCE, Curators, _listing

from plugins.blackbox.community import read_curator_view, reputation
from plugins.blackbox.curate import keys, service, transport, verbs
from plugins.blackbox.curate.ladder import outcomes
from plugins.blackbox.curate.proposal import Proposal, ProposalState, ProposalStore
from plugins.blackbox.curate.service import Beat, Lookup, OwnCheck, PolicyConsent, policy
from plugins.blackbox.curate.service import budget as service_budget
from plugins.blackbox.detection import osv
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

PKG = "dep:npm:evil-pkg@1.0.0"
IP = "ioc:ip:203.0.113.7"
TODAY = date.today().isoformat()
FOUND = OwnCheck(Lookup.FOUND, "MAL-2026-1")
CLEAN, UNAVAILABLE = OwnCheck(Lookup.CLEAN), OwnCheck(Lookup.UNAVAILABLE)
DAY = 86_400


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(outcomes.osv, "lookup", lambda ecosystem, name, version: None)        # no network in the crediting step
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)


class Corroborated:
    """A compiled tier in which every threat it is given is CORROBORATED by counted reporters."""

    def __init__(self, *identifiers):
        self.community = {identifier: {"identifier": identifier, "stage": "corroborated", "enforcement": "flag", "counted": "8",
                                       "reporterCount": 8, "stageReason": "corroborated", "reportReason": "typosquat",
                                       "unlistedReporters": "0"} for identifier in identifiers}

    def iter_rules(self):
        return []


class Service:
    """Curators A, B, C (policy accepted unless told otherwise), each with its own beat and its own lookup."""

    def __init__(self, tmp_path, monkeypatch, *, accepted="ABC"):
        self.team = Curators(tmp_path, monkeypatch)
        self.machines = {m.name: m for m in (self.team.a, self.team.b, self.team.c)}
        self.alice = Reporter("0xa")
        self.team.two_key(Kind.COUNTED_AUTHORS, f"author:{self.alice.author}", _listing(self.alice))   # a person listed alice
        self.answers = {}        # (machine name, identifier) or identifier -> OwnCheck
        self.compiled = {}       # machine name -> a compiled tier to use instead of the real one
        for name in accepted:
            self.accept(name)

    def accept(self, name):
        with self.machines[name]:
            PolicyConsent().accept(service.policy_text(), key_hex=self.team.keys[name], day=TODAY)

    def report(self, identifier, reporter=None, **kw):
        share_report(self.team.reader.node, identifier, reporter or self.alice, **kw)

    def ctx(self, machine, interest):
        ctx = self.team.ctx(machine, interest=interest)
        compiled = self.compiled.get(machine.name)
        if compiled is None:
            compiled = compiler.Ruleset()
            community_tier.apply_community_tier(compiled, machine.node, CFG, None)
        return dataclasses.replace(ctx, compiled=compiled)

    def beat(self, name, *, peers=None, clock=time.time):
        machine = self.machines[name]
        others = [other for other in self.machines if other != name] if peers is None else peers

        def lookup(identifier):
            default = CLEAN if identifier.startswith("dep:") and not identifier.endswith("@*") else OwnCheck(Lookup.NOT_APPLICABLE)
            return self.answers.get((name, identifier), self.answers.get(identifier, default))

        with machine:
            return Beat(lambda interest: self.ctx(machine, interest), peers=others, lookup=lookup, clock=clock).run()

    def view(self, *interest):
        """What a plain reader sees about *interest* (and alice)."""
        with self.team.reader:
            return read_curator_view(self.team.reader.node, CFG, interest=[*interest, f"author:{self.alice.author}"])

    def verdict(self, identifier):
        view = self.view(identifier)
        return view.community.verdicts.get(identifier), view

    def inbox(self, name):
        return len(self.team.net.inbox.get(name, []))

    def proposals(self, name):
        with self.machines[name]:
            return ProposalStore().all()

    def statements(self, kind):
        """The asset names of the curator statements of one kind on the shared graph."""
        return [name for (_, name) in self.team.net.assets.get((GRAPH, SWM), {}) if name.startswith(f"curator-{kind}-")]


@pytest.fixture
def svc(tmp_path, monkeypatch):
    return Service(tmp_path, monkeypatch)


# ------------------------------------------------------------------ the done-when


def test_a_malicious_dependency_is_confirmed_on_a_reader_with_no_human_command(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND                                            # every node finds the advisory ITSELF
    first = svc.beat("A")
    assert first.may_sign and first.heartbeat == "published" and len(first.proposed) == 1 and first.errors == ()
    assert svc.verdict(PKG)[0] is None                                  # one signature publishes nothing
    second = svc.beat("B")
    assert second.received == 1 and len(second.cosigned) == 1 and second.errors == ()
    record, view = svc.verdict(PKG)
    assert record.kind is Kind.CONFIRMATION and record.field("evidence") == "advisory:MAL-2026-1" and len(record.signers) == 2
    assert view.verdict(PKG) is Kind.CONFIRMATION and set(view.community.heartbeats) == {svc.team.keys["A"], svc.team.keys["B"]}
    again = svc.beat("A")                                               # nothing left to do, and nothing repeated
    assert again.proposed == () and again.heartbeat == "not due" and again.credited == 1
    assert len(svc.statements("confirmation")) == 1 and len(svc.statements("heartbeat")) == 2


def test_the_reader_then_flags_the_package(svc):
    svc.report(PKG, Reporter("0xnew"))                                  # only an UNLISTED reporter and alice's listing…
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    svc.beat("A"), svc.beat("B")
    with svc.team.reader:
        tier = compiler.Ruleset()
        community_tier.apply_community_tier(tier, svc.team.reader.node, CFG, None)
    assert (tier.community[PKG]["stage"], tier.community[PKG]["enforcement"]) == ("corroborated", "flag")
    assert "confirmed by the curator" in tier.community[PKG]["stageReason"]


def test_every_statement_the_service_signs_is_recorded_as_standing_consent(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND

    def consents():
        with svc.machines["B"]:
            lines = (keys.curate_home() / "consent.jsonl").read_text(encoding="utf-8").splitlines()
        return [json.loads(line)["why"] for line in lines if json.loads(line)["event"] == "consent"]

    before = len(consents())                                             # the person's own consents during the setup
    svc.beat("A"), svc.beat("B")
    reasons = consents()[before:]
    assert any(why.startswith("standing consent: confirm: this node found MAL-2026-1") for why in reasons)
    assert any(why.startswith("standing consent: heartbeat: ") for why in reasons) and len(reasons) == 2
    assert all(why.startswith("standing consent: ") and service.policy_hash()[:8] in why for why in reasons)


# ------------------------------------------------------------------ what is NOT confirmed


@pytest.mark.parametrize("what", ["another version", "a vulnerability advisory only", "the lookup failed", "a whole package"])
def test_the_first_node_does_not_propose_without_its_own_malicious_package_advisory(svc, what):
    identifier = "dep:npm:evil-pkg@*" if what == "a whole package" else PKG
    svc.report(identifier)
    svc.answers["dep:npm:evil-pkg@1.0.1"] = FOUND                       # the advisory names ANOTHER version
    if what == "the lookup failed":
        svc.answers[PKG] = UNAVAILABLE
    report = svc.beat("A")
    assert report.proposed == () and svc.statements("confirmation") == []
    assert any(item.subject == identifier for item in report.human)


def test_a_vulnerability_advisory_is_not_evidence_of_malware():
    vulnerability = lambda eco, name, version: ("found", {"advisory_id": "GHSA-aaaa-bbbb-cccc", "severity": "high", "kind": "vulnerability"})  # noqa: E731
    malware = lambda eco, name, version: ("found", {"advisory_id": "MAL-2026-1", "severity": "critical", "kind": "malware"})  # noqa: E731
    assert service.own_check(PKG, vulnerability) == CLEAN
    assert service.own_check(PKG, malware) == FOUND and service.own_check(PKG, malware).evidence == "advisory:MAL-2026-1"
    assert service.own_check(PKG, lambda *a: ("clean", None)) == CLEAN
    assert service.own_check(PKG, lambda *a: ("unavailable", None)) == UNAVAILABLE
    for identifier in ("dep:npm:evil-pkg@*", IP, "skill:evil@1.0.0", "ioc:domain:evil.example"):
        assert service.own_check(identifier, malware).status is Lookup.NOT_APPLICABLE


def test_the_public_source_tells_nothing_found_from_could_not_ask(monkeypatch):
    answers = {"evil-pkg": {"vulns": [{"id": "GHSA-x"}, {"id": "MAL-2026-1"}]}, "clean-pkg": {}, "down": None}
    monkeypatch.setattr(osv, "_query", lambda eco, name, version: answers[name])
    assert osv.advisory_status("npm", "evil-pkg", "1.0.0") == ("found", {"advisory_id": "MAL-2026-1", "severity": "high", "kind": "malware"})
    assert osv.advisory_status("npm", "clean-pkg", "1.0.0") == ("clean", None)
    assert osv.advisory_status("npm", "down", "1.0.0") == ("unavailable", None)
    assert osv.advisory_status("npm", "evil-pkg", "") == ("unavailable", None)
    assert osv.advisory_status("no-such-ecosystem", "evil-pkg", "1.0.0") == ("unavailable", None)


@pytest.mark.parametrize("what", ["its lookup failed", "it found nothing", "it found another advisory"])
def test_a_proposal_the_second_node_cannot_reproduce_is_not_co_signed_and_waits_for_a_person(svc, what):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    svc.answers[("B", PKG)] = {"its lookup failed": UNAVAILABLE, "it found nothing": CLEAN,
                               "it found another advisory": OwnCheck(Lookup.FOUND, "MAL-2026-9")}[what]
    proposed = svc.beat("A").proposed
    report = svc.beat("B")
    assert report.cosigned == () and svc.statements("confirmation") == [] and svc.verdict(PKG)[0] is None
    assert [item.subject for item in report.human if item.subject == proposed[0]] == [proposed[0]]
    assert [p.state for p in svc.proposals("B") if p.id == proposed[0]] == [ProposalState.PROPOSED]      # left for a person
    assert [len(p.parsed().signatures) for p in svc.proposals("B") if p.id == proposed[0]] == [1]        # and not co-signed


# ------------------------------------------------------------------ standing consent


def test_without_the_accepted_policy_the_service_signs_nothing(tmp_path, monkeypatch):
    svc = Service(tmp_path, monkeypatch, accepted="")
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    def state():
        signed = [(p.id, len(p.parsed().signatures)) for p in svc.proposals("A")]            # every signature this machine holds
        return dict(svc.team.net.assets[(GRAPH, SWM)]), signed, svc.inbox("B")

    before = state()
    report = svc.beat("A")
    assert not report.may_sign and "not accepted" in report.why_not and report.heartbeat == "not signed"
    assert report.proposed == () and report.published == ()
    assert state() == before                                             # nothing signed, nothing written, nothing sent
    assert any("the policy allows the service to do this" in item.why for item in report.human)   # a person can still do it
    svc.accept("A")
    assert len(svc.beat("A").proposed) == 1


def test_a_changed_policy_text_stops_the_service_until_it_is_accepted_again(svc, monkeypatch):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    monkeypatch.setattr(policy, "SERVICE_LISTINGS_PER_DAY", 7)           # the policy text changes
    report = svc.beat("A")
    assert not report.may_sign and report.proposed == () and svc.statements("heartbeat") == []
    svc.accept("A")
    assert len(svc.beat("A").proposed) == 1


def test_a_machine_whose_key_is_not_a_curator_key_signs_nothing(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    reader = svc.team.reader
    with reader:
        PolicyConsent().accept(service.policy_text(), key_hex=keys.curator_key_store().public_key_hex(), day=TODAY)
        report = Beat(lambda interest: svc.ctx(reader, interest), peers=["A"], lookup=lambda identifier: FOUND).run()
    assert not report.may_sign and "not a curator key" in report.why_not and report.proposed == ()


# ------------------------------------------------------------------ what only a person may do


def _human_proposal(svc, kind, identifier, fields, evidence=""):
    """A PERSON on machine A proposes and sends it to B."""
    with svc.team.a:
        proposal = verbs.propose_statement(svc.team.ctx(svc.team.a, interest=[identifier]), ProposalStore(), kind=kind,
                                           identifier=identifier, fields=fields, evidence=evidence)
        verbs.send(svc.team.ctx(svc.team.a), proposal, "B")
    return proposal


@pytest.mark.parametrize("what", ["a rejection", "a partner grant", "a collapse", "a pause", "a confirmation of an indicator",
                                  "a confirmation citing a reproduction", "a listing its ledger does not call for"])
def test_the_service_never_co_signs_what_only_a_person_may_decide(svc, what):
    bob = Reporter("0xb")
    svc.report(PKG), svc.report(IP)
    svc.answers[PKG] = FOUND
    kind, identifier, fields, evidence = {
        "a rejection": (Kind.REJECTION, PKG, {"reason": "benign"}, ""),
        "a partner grant": (Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob, **{"class": "partner", "org": "acme"}), ""),
        "a collapse": (Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob, org="one-operator"), ""),
        "a pause": (Kind.PAUSE, "curator", {"until": (date.today() + timedelta(days=3)).isoformat()}, ""),
        "a confirmation of an indicator": (Kind.CONFIRMATION, IP, {}, EVIDENCE),
        "a confirmation citing a reproduction": (Kind.CONFIRMATION, PKG, {}, "reproduced:" + "ab" * 32),
        "a listing its ledger does not call for": (Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob), ""),
    }[what]
    proposal = _human_proposal(svc, kind, identifier, fields, evidence)
    before = set(svc.team.net.assets[(GRAPH, SWM)])
    report = svc.beat("B", peers=[])
    assert proposal.id not in report.cosigned and proposal.id in [item.subject for item in report.human]
    written = {name for (_, name) in set(svc.team.net.assets[(GRAPH, SWM)]) - before}
    assert all(name.startswith(("curator-heartbeat-", "curator-in-review-")) for name in written), written
    assert [p.state for p in svc.proposals("B") if p.id == proposal.id] == [ProposalState.PROPOSED]


def test_a_person_can_still_approve_what_the_service_left(svc):
    svc.report(IP)
    proposal = _human_proposal(svc, Kind.CONFIRMATION, IP, {}, EVIDENCE)
    svc.beat("B", peers=[])
    with svc.team.b:
        _, outcome = verbs.approve(svc.team.ctx(svc.team.b, interest=[IP]), ProposalStore(), proposal.id, evidence=EVIDENCE,
                                   typed_code=None, yes=True)
    assert outcome.startswith("published") and svc.verdict(IP)[0].kind is Kind.CONFIRMATION


def test_messages_that_are_not_a_curators_proposal_are_dropped(svc):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    svc.report(PKG)
    genuine = _human_proposal(svc, Kind.REJECTION, PKG, {"reason": "benign"})
    outsider = Ed25519PrivateKey.generate()                              # gitleaks:allow — a throwaway test key
    with svc.team.a:
        manifest = svc.team.ctx(svc.team.a).manifest
    forged = signing.sign(outsider, statement_type=Kind.REJECTION.value, environment=manifest.environment, graph=GRAPH,
                          payload={"identifier": PKG, "day": TODAY, "reason": "benign"}, chain=manifest.chain,
                          root_epoch=manifest.root_epoch, sequence=9)
    wrong_id = dataclasses.replace(genuine, id="0" * 16)
    outsiders = Proposal.new(Kind.REJECTION.value, PKG, forged, GRAPH, checks={}).transition(ProposalState.PROPOSED)   # consistent, unsigned by a curator
    node = svc.team.reader.node
    for text in (transport.PROPOSAL_PREFIX + outsiders.to_json(),
                 transport.PROPOSAL_PREFIX + wrong_id.to_json(), transport.PROPOSAL_PREFIX + "{not json", "hello"):
        node.request("POST", "/api/chat", {"to": "B", "text": text})
    report = svc.beat("B", peers=[])
    assert (report.received, report.dropped) == (1, 2)                   # the two non-proposals are not even counted
    assert [p.id for p in svc.proposals("B") if p.kind == Kind.REJECTION.value] == [genuine.id]


# ------------------------------------------------------------------ nothing is left half-done


def test_a_beat_that_fails_halfway_leaves_nothing_half_published_and_the_next_beat_completes_it(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    proposed = svc.beat("A").proposed
    svc.team.b.node.refuse_shares = True                                 # B's node refuses every write
    broken = svc.beat("B")
    assert broken.cosigned == () and broken.errors and svc.statements("confirmation") == [] and svc.verdict(PKG)[0] is None
    assert [p.state for p in svc.proposals("B") if p.id == proposed[0]] == [ProposalState.APPROVED]     # signed, not published
    svc.team.b.node.refuse_shares = False
    mended = svc.beat("B")
    assert mended.cosigned == (proposed[0],) and mended.heartbeat == "published" and mended.errors == ()
    assert len(svc.statements("confirmation")) == 1 and svc.verdict(PKG)[0].kind is Kind.CONFIRMATION
    assert svc.beat("B").cosigned == ()                                  # and it is not published twice
    assert len(svc.statements("heartbeat")) == 2                         # A's and B's: B finished the one it had signed


def test_one_item_failing_never_stops_the_step_reaching_the_others(svc):
    """With the node refusing writes, EVERY proposal is co-signed and waits to be published — which
    ones a beat reaches must not depend on the order they are read in."""
    packages = [f"dep:npm:evil-{n}@1.0.0" for n in range(4)]
    for package in packages:
        svc.report(package)
        svc.answers[package] = FOUND
    proposed = set(svc.beat("A").proposed)
    svc.team.b.node.refuse_shares = True
    broken = svc.beat("B")
    assert len(proposed) == 4 and len(broken.errors) >= 4
    assert {p.id for p in svc.proposals("B") if p.state is ProposalState.APPROVED and p.id in proposed} == proposed
    svc.team.b.node.refuse_shares = False
    assert set(svc.beat("B").cosigned) == proposed and len(svc.statements("confirmation")) == 4


def test_the_beat_keeps_this_nodes_statements_alive_and_only_with_consent(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    svc.beat("A"), svc.beat("B")                                         # B published the confirmation
    assert svc.beat("B").kept_alive == 0                                 # the same keep-alive epoch: nothing due
    later = lambda: time.time() + 11 * DAY                               # noqa: E731 — the next epoch
    with svc.machines["B"]:
        PolicyConsent().withdraw()
    assert svc.beat("B", clock=later).kept_alive == 0                    # no standing consent: nothing is re-published
    svc.accept("B")
    assert svc.beat("B", clock=later).kept_alive >= 1


def test_a_proposal_that_reached_nobody_is_sent_again(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    start = svc.inbox("B")
    alone = svc.beat("A", peers=[])
    assert len(alone.proposed) == 1 and any("reached no other curator" in error for error in alone.errors)
    assert svc.inbox("B") == start
    again = svc.beat("A")
    assert again.proposed == () and svc.inbox("B") == start + 1          # the SAME proposal, now delivered
    assert svc.beat("A").errors == () and svc.inbox("B") == start + 1    # and not sent a third time
    assert len(svc.beat("B").cosigned) == 1


def test_a_half_signed_copy_on_the_graph_does_not_finish_this_nodes_proposal(svc):
    """Anyone can publish the first curator's single signature; the proposal is finished only when the statement has its quorum."""
    from plugins.blackbox.community.statements import curator_statements as cs
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    proposed = svc.beat("A").proposed
    with svc.machines["A"]:
        envelope = ProposalStore().get(proposed[0]).parsed()
    svc.team.reader.node.share_knowledge_asset(GRAPH, "half-signed", cs.statement_quads(envelope))
    svc.beat("A")
    assert [p.state for p in svc.proposals("A") if p.id == proposed[0]] == [ProposalState.PROPOSED]
    svc.beat("B"), svc.beat("A")                                         # B co-signs and publishes: now it is finished
    assert [p.state for p in svc.proposals("A") if p.id == proposed[0]] == [ProposalState.PUBLISHED]


def test_a_proposal_this_node_already_acted_on_is_not_reset_by_receiving_it_again(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    proposed = svc.beat("A").proposed
    svc.beat("B")
    with svc.team.a:
        verbs.send(svc.team.ctx(svc.team.a), ProposalStore().get(proposed[0]), "B")       # the same proposal arrives again
    report = svc.beat("B")
    assert report.received == 0 and report.cosigned == ()
    assert [p.state for p in svc.proposals("B") if p.id == proposed[0]] == [ProposalState.PUBLISHED]


# ------------------------------------------------------------------ the service's own daily limit


def test_the_service_signs_at_most_its_daily_limit_and_goes_on_the_next_day(svc, monkeypatch):
    monkeypatch.setattr(policy, "SERVICE_CONFIRMATIONS_PER_DAY", 2)
    svc.accept("A")                                                      # the limit is part of the policy text
    packages = [f"dep:npm:evil-{n}@1.0.0" for n in range(3)]
    for package in packages:
        svc.report(package)
        svc.answers[package] = FOUND
    today = svc.beat("A")
    assert len(today.proposed) == 2 and today.limited == 1
    assert svc.beat("A").proposed == ()
    tomorrow = svc.beat("A", clock=lambda: time.time() + DAY)
    assert len(tomorrow.proposed) == 1 and tomorrow.limited == 0


def test_a_co_signature_counts_against_the_daily_limit_too(svc, monkeypatch):
    monkeypatch.setattr(policy, "SERVICE_CONFIRMATIONS_PER_DAY", 2)
    svc.accept("A"), svc.accept("C")
    for n in range(3):
        svc.report(f"dep:npm:evil-{n}@1.0.0")
        svc.answers[f"dep:npm:evil-{n}@1.0.0"] = FOUND
    assert len(svc.beat("A", peers=["C"]).proposed) == 2
    report = svc.beat("C", peers=[])
    assert len(report.cosigned) == 2 and report.proposed == () and report.limited == 1     # the third waits for tomorrow


def test_the_budget_counts_per_day_and_per_kind(tmp_path):
    book = service_budget.ServiceBudget(tmp_path / "budget.json")
    assert book.left("confirm", TODAY) == policy.SERVICE_CONFIRMATIONS_PER_DAY and book.left("list", TODAY) == policy.SERVICE_LISTINGS_PER_DAY
    for _ in range(3):
        book.spend("confirm", TODAY)
    book.spend("list", TODAY)
    assert book.left("confirm", TODAY) == policy.SERVICE_CONFIRMATIONS_PER_DAY - 3
    assert book.left("list", TODAY) == policy.SERVICE_LISTINGS_PER_DAY - 1
    assert book.left("confirm", "2099-01-01") == policy.SERVICE_CONFIRMATIONS_PER_DAY      # another day starts from zero
    (tmp_path / "budget.json").write_text("not json", encoding="utf-8")
    assert book.left("confirm", TODAY) == policy.SERVICE_CONFIRMATIONS_PER_DAY


# ------------------------------------------------------------------ the clock: acknowledge, defer, lapse


def test_a_threat_only_a_person_can_decide_is_acknowledged_once(svc):
    svc.report(IP)
    first = svc.beat("A")
    assert first.published == (f"in-review {IP}",) and [item.subject for item in first.human] == [IP]
    assert svc.verdict(IP)[0].kind is Kind.IN_REVIEW
    second = svc.beat("A")
    assert second.published == () and [item.subject for item in second.human] == [IP] and len(svc.statements("in-review")) == 1


def test_a_corroborated_dependency_with_no_evidence_is_deferred_by_one_key_and_lapses_after_thirty_days(svc):
    svc.compiled["A"] = Corroborated(PKG)
    assert svc.beat("A").published == (f"deferral {PKG}",)               # one key is enough: it never raises enforcement
    assert svc.verdict(PKG)[0].kind is Kind.DEFERRAL
    assert svc.beat("A").published == ()                                 # deferred once
    assert svc.beat("A", clock=lambda: time.time() + 30 * DAY).published == ()
    lapsed = svc.beat("A", clock=lambda: time.time() + 31 * DAY)
    assert f"deferral-lapsed {PKG}" in lapsed.published and svc.verdict(PKG)[0].kind is Kind.DEFERRAL_LAPSED
    after = svc.beat("A", clock=lambda: time.time() + 32 * DAY)
    assert not any(done.startswith("deferral") for done in after.published)          # a lapsed deferral is not deferred again


def test_a_failed_lookup_defers_nothing_and_an_indicator_is_never_deferred(svc):
    svc.compiled["A"] = Corroborated(PKG, IP)
    svc.answers[PKG] = UNAVAILABLE
    report = svc.beat("A")
    assert not any(done.startswith("deferral") for done in report.published) and svc.statements("deferral") == []
    assert {item.subject for item in report.human} == {PKG, IP}


def test_evidence_arriving_during_a_deferral_confirms_the_threat(svc):
    svc.compiled["A"] = svc.compiled["B"] = Corroborated(PKG)
    svc.beat("A")
    assert svc.verdict(PKG)[0].kind is Kind.DEFERRAL
    svc.answers[PKG] = FOUND                                             # the advisory is published later
    assert len(svc.beat("A").proposed) == 1 and len(svc.beat("B").cosigned) == 1
    assert svc.verdict(PKG)[0].kind is Kind.CONFIRMATION


# ------------------------------------------------------------------ the ladder


def _graduating(svc, names, reporter, *, days_ago=30):
    """On each named curator machine, *reporter* has five novel confirmed reports and a first report *days_ago* back."""
    first = (date.today() - timedelta(days=days_ago)).isoformat()
    for name in names:
        with svc.machines[name]:
            book = reputation.ReputationLedger()
            for _ in range(reputation.GRADUATION_MIN_NOVEL):
                book.record(reporter.author, reputation.Outcome(TODAY, True), novel=True, first_seen_day=first)


def test_a_graduation_both_ledgers_call_for_is_listed_with_no_human_command(svc):
    bob = Reporter("0xb")
    svc.report(IP, bob)
    _graduating(svc, "AB", bob)
    first = svc.beat("A")
    assert len(first.proposed) == 1 and svc.beat("A").proposed == ()     # one proposal in flight is enough
    assert len(svc.beat("B").cosigned) == 1
    view = svc.view(f"author:{bob.author}")
    assert bob.author in view.counted and view.counted[bob.author].author_class == "established"
    assert view.counted[bob.author].expires == (date.today() + timedelta(days=90)).isoformat()
    assert svc.beat("A").proposed == () and svc.beat("B").proposed == ()                # listed: nothing more to propose


def test_a_graduation_the_second_ledger_does_not_call_for_waits_for_a_person(svc):
    bob = Reporter("0xb")
    svc.report(IP, bob)
    _graduating(svc, "A", bob)                                           # only A's ledger says so
    proposed = svc.beat("A").proposed
    report = svc.beat("B")
    assert report.cosigned == () and proposed[0] in [item.subject for item in report.human]
    assert bob.author not in svc.view(f"author:{bob.author}").counted


def test_a_reporter_too_new_or_one_credit_short_is_not_proposed(svc):
    young, short = Reporter("0xyoung"), Reporter("0xshort")
    svc.report(IP, young), svc.report(IP, short)
    _graduating(svc, "A", young, days_ago=13)
    with svc.machines["A"]:
        for _ in range(reputation.GRADUATION_MIN_NOVEL - 1):
            reputation.ReputationLedger().record(short.author, reputation.Outcome(TODAY, True), novel=True,
                                                 first_seen_day=(date.today() - timedelta(days=30)).isoformat())
    assert svc.beat("A").proposed == ()


def test_a_listing_about_to_expire_is_renewed_and_one_far_from_expiry_is_not(tmp_path, monkeypatch):
    svc = Service(tmp_path, monkeypatch)                                 # alice's listing runs to 2026-12-31: not due
    assert svc.beat("A").proposed == ()
    carol = Reporter("0xc")
    soon = (date.today() + timedelta(days=10)).isoformat()
    svc.team.two_key(Kind.COUNTED_AUTHORS, f"author:{carol.author}", _listing(carol, expires=soon))
    assert len(svc.beat("A").proposed) == 1 and len(svc.beat("B").cosigned) == 1
    assert svc.view(f"author:{carol.author}").counted[carol.author].expires == (date.today() + timedelta(days=90)).isoformat()
    assert svc.beat("A").proposed == () and svc.beat("B").proposed == ()                # renewed: nothing more to propose


def test_a_reporter_under_the_reputation_floor_is_delisted_by_both_ledgers(svc):
    for name in "AB":
        with svc.machines[name]:
            book = reputation.ReputationLedger()
            outcomes.sync_bands(svc.team.ctx(svc.machines[name], interest=[f"author:{svc.alice.author}"]).own_view, book, TODAY)
            for _ in range(4):
                book.record(svc.alice.author, reputation.Outcome(TODAY, False))
    assert len(svc.beat("A").proposed) == 1 and len(svc.beat("B").cosigned) == 1
    view = svc.view()
    assert svc.alice.author not in view.counted and svc.alice.author in view.delisted


# ------------------------------------------------------------------ the command


def test_the_run_command_does_one_beat_and_says_what_happened(svc, capsys):
    svc.report(IP)
    machine = svc.machines["A"]
    with machine:
        code = service.run_command(lambda interest: svc.ctx(machine, interest), peers=["B", "C"], interval=300, once=True)
    printed = capsys.readouterr().out
    assert code == 0 and "beat: signing · heartbeat published" in printed and "1 for a person" in printed
    assert f"for a person: {IP}" in printed
