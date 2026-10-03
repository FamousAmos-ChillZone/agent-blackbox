"""Community Curation C9 — the automation policy and the standing consent.

The policy is one pure table: for an action and the facts THIS node
established itself, the service may sign or a person must. Every row of plan
section 07 is checked here exactly as written, and the standing consent is
bound to the policy's exact text.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.curate import keys, service, verbs
from plugins.blackbox.curate.service import Action, Facts, PolicyConsent, action_for, decide, policy
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

DEP = "dep:npm:evil-pkg@1.0.0"
FOUND = Facts(malicious_advisory="MAL-2026-1", evidence_cited="advisory:MAL-2026-1")


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


# ------------------------------------------------------------------ the table, row by row


@pytest.mark.parametrize("action", [Action.HEARTBEAT, Action.ACKNOWLEDGE, Action.KEEP_ALIVE])
def test_what_needs_no_judgement_is_always_the_services(action):
    assert decide(action, "curator", Facts()).automatic


@pytest.mark.parametrize("action", [Action.REJECT, Action.STRIKE, Action.GRANT_PARTNER, Action.PAUSE, Action.ROOT, Action.OTHER])
def test_a_persons_decisions_are_never_the_services_whatever_the_facts(action):
    everything = Facts(malicious_advisory="MAL-2026-1", evidence_cited="advisory:MAL-2026-1", corroborated=True,
                       lookup_clean=True, deferral_age_days=400, ledger_calls_for="delist")
    for facts in (Facts(), everything, Facts(ledger_calls_for="list")):
        decision = decide(action, DEP, facts)
        assert not decision.automatic and decision.reason


def test_a_dependency_is_confirmed_only_on_this_nodes_own_malicious_package_advisory_for_that_exact_version():
    assert decide(Action.CONFIRM, DEP, FOUND).automatic
    refused = {
        "this node found nothing (or its lookup failed)": (DEP, Facts(evidence_cited="advisory:MAL-2026-1")),
        "this node found nothing and the statement cites an empty advisory": (DEP, Facts(evidence_cited="advisory:")),
        "the statement cites another advisory": (DEP, Facts(malicious_advisory="MAL-2026-1", evidence_cited="advisory:MAL-2026-2")),
        "the statement cites a reproduction": (DEP, Facts(malicious_advisory="MAL-2026-1", evidence_cited="reproduced:" + "ab" * 32)),
        "a whole package": ("dep:npm:evil-pkg@*", FOUND),
        "a domain": ("ioc:domain:evil.example", FOUND),
        "a url": ("ioc:url:https://evil.example/x", FOUND),
        "a wallet": ("ioc:wallet:0x" + "a" * 40, FOUND),
        "a skill": ("skill:evil-skill@1.0.0", FOUND),
        "an injection pattern": ("injection:0123456789abcdef", FOUND),
    }
    for why, (identifier, facts) in refused.items():
        assert not decide(Action.CONFIRM, identifier, facts).automatic, why


def test_deferring_is_a_clock_not_a_judgement():
    ready = Facts(corroborated=True, lookup_clean=True)
    assert decide(Action.DEFER, DEP, ready).automatic
    assert not decide(Action.DEFER, DEP, Facts(corroborated=True)).automatic            # the lookup did not answer: not "nothing found"
    assert not decide(Action.DEFER, DEP, Facts(lookup_clean=True)).automatic            # not corroborated
    assert not decide(Action.DEFER, "ioc:domain:evil.example", ready).automatic         # not a blockable kind
    assert decide(Action.LAPSE_DEFERRAL, DEP, Facts(deferral_age_days=31)).automatic
    assert not decide(Action.LAPSE_DEFERRAL, DEP, Facts(deferral_age_days=30)).automatic
    assert not decide(Action.LAPSE_DEFERRAL, DEP, Facts()).automatic                    # no deferral in force


def test_the_ladder_is_arithmetic_this_nodes_own_ledger_must_agree_with():
    author = "author:" + "a" * 64
    assert decide(Action.LIST, author, Facts(ledger_calls_for="list")).automatic
    assert decide(Action.DELIST, author, Facts(ledger_calls_for="delist")).automatic
    for action, facts in ((Action.LIST, Facts()), (Action.LIST, Facts(ledger_calls_for="delist")),
                          (Action.DELIST, Facts()), (Action.DELIST, Facts(ledger_calls_for="list"))):
        assert not decide(action, author, facts).automatic


def test_every_action_has_a_rule_and_every_decision_a_reason():
    for action in Action:
        decision = decide(action, DEP, Facts())
        assert decision.action is action and decision.reason


# ------------------------------------------------------------------ which action a statement is


LISTING = {"listed": "yes", "class": "established", "org": "", "expires": "2026-12-31", "address": "0x" + "a" * 40}


@pytest.mark.parametrize("kind, fields, action", [
    (Kind.HEARTBEAT, {"key": "a" * 64}, Action.HEARTBEAT),
    (Kind.IN_REVIEW, {}, Action.ACKNOWLEDGE),
    (Kind.CONFIRMATION, {"evidence": "advisory:MAL-2026-1"}, Action.CONFIRM),
    (Kind.DEFERRAL, {}, Action.DEFER),
    (Kind.DEFERRAL_LAPSED, {}, Action.LAPSE_DEFERRAL),
    (Kind.REJECTION, {"reason": "benign"}, Action.REJECT),
    (Kind.PAUSE, {"until": "2026-10-09"}, Action.PAUSE),
    (Kind.COUNTED_AUTHORS, LISTING, Action.LIST),
    (Kind.COUNTED_AUTHORS, {**LISTING, "listed": "no"}, Action.DELIST),
    (Kind.COUNTED_AUTHORS, {**LISTING, "class": "partner", "org": "acme"}, Action.GRANT_PARTNER),
    (Kind.COUNTED_AUTHORS, {**LISTING, "org": "one-operator"}, Action.OTHER),        # a collapse is a judgement
    (Kind.COUNTED_AUTHORS, {**LISTING, "listed": "no", "class": "partner", "org": "acme"}, Action.DELIST),
    (Kind.ATTESTATION, {"stage": "corroborated"}, Action.OTHER),
    (Kind.BACKLOG, {"lanes": "3", "until": "2026-10-09"}, Action.OTHER),
    (Kind.AWAY, {}, Action.OTHER),
    (Kind.REVOCATION, {"reason": "false-positive"}, Action.OTHER),
    (Kind.PROMOTION, {}, Action.OTHER),
])
def test_a_statement_maps_to_the_action_it_performs(kind, fields, action):
    assert action_for(kind.value, fields) is action


def test_root_signed_and_unknown_statements_are_never_routine():
    assert action_for("blackbox.key-manifest", {}) is Action.ROOT
    assert action_for("blackbox.kill-list", {}) is Action.OTHER and action_for("something-new", {}) is Action.OTHER
    assert {kind.value for kind in Kind} >= {k for k in policy._KIND_ACTIONS if k != "blackbox.key-manifest"}


# ------------------------------------------------------------------ the text and the consent bound to it


def test_the_policy_text_states_every_row_and_both_limits():
    text = service.policy_text()
    for what, who, _why in policy.POLICY_ROWS:
        assert what in text and who in text
    assert f"{policy.SERVICE_CONFIRMATIONS_PER_DAY} confirmations" in text and f"{policy.SERVICE_LISTINGS_PER_DAY} listings" in text


def test_the_services_own_limits_are_below_every_readers_cap():
    from plugins.blackbox.community.trust import raising_budget
    assert policy.SERVICE_CONFIRMATIONS_PER_DAY < raising_budget.CONFIRMATIONS_PER_DAY
    assert policy.SERVICE_LISTINGS_PER_DAY < raising_budget.LISTINGS_PER_DAY


def test_the_policy_text_is_pinned_so_a_change_is_a_deliberate_act():
    """Standing consent names this hash. Changing the table or a limit changes it and makes every
    curator operator accept again — update this value only together with the plan (section 07)."""
    assert service.policy_hash() == "2e74cdf4421ccd2c21851c4b48748352a42f64b566c569397dbddff840299a2f"


def test_consent_is_bound_to_the_exact_text_and_the_key():
    consent, text = PolicyConsent(), service.policy_text()
    assert not consent.accepted(text) and consent.acceptance() is None
    held = consent.accept(text, key_hex="a" * 64, day="2026-10-03")
    assert consent.accepted(text) and consent.accepted(text, "a" * 64) and held.day == "2026-10-03"
    assert not consent.accepted(text + " ")                              # one more character: not what was accepted
    assert not consent.accepted(text, "b" * 64)                          # another machine's key
    assert consent.withdraw() and not consent.accepted(text) and not consent.withdraw()


def test_a_changed_policy_stops_the_consent_until_it_is_accepted_again(monkeypatch):
    consent = PolicyConsent()
    consent.accept(service.policy_text(), key_hex="a" * 64, day="2026-10-03")
    monkeypatch.setattr(policy, "SERVICE_CONFIRMATIONS_PER_DAY", 75)
    assert not consent.accepted(service.policy_text())
    consent.accept(service.policy_text(), key_hex="a" * 64, day="2026-10-04")
    assert consent.accepted(service.policy_text())


def test_an_unreadable_consent_file_is_no_consent(tmp_path):
    path = tmp_path / "policy_consent.json"
    for content in ("", "not json", "[]", '{"policy_hash": "x"}'):
        path.write_text(content, encoding="utf-8")
        assert PolicyConsent(path).acceptance() is None and not PolicyConsent(path).accepted(service.policy_text())


# ------------------------------------------------------------------ the command


def test_the_policy_command_shows_accepts_by_typed_code_and_withdraws(capsys):
    code = service.policy_hash()[:8]
    assert service.policy_command(accept=False, withdraw=False, code=None) == 0
    shown = capsys.readouterr().out
    assert "NOT ACCEPTED" in shown and f"--accept --code {code}" in shown and "A PERSON" in shown
    for wrong in (None, "", "00000000"):
        with pytest.raises(verbs.VerbError, match="type the code"):
            service.policy_command(accept=True, withdraw=False, code=wrong)
    assert not PolicyConsent().accepted(service.policy_text())
    assert service.policy_command(accept=True, withdraw=False, code=code.upper()) == 0
    assert PolicyConsent().accepted(service.policy_text(), keys.curator_key_store().public_key_hex())
    service.policy_command(accept=False, withdraw=False, code=None)
    assert "ACCEPTED on" in capsys.readouterr().out
    assert service.policy_command(accept=False, withdraw=True, code=None) == 0
    assert not PolicyConsent().accepted(service.policy_text())
