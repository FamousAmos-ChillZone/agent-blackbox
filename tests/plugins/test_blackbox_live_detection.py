"""Detection asks the ruleset for public rules (DKG-lookup B4): the live lookup
answers first, compiled (community) rules fill the gaps, a lookup that could not
tell never hides the hits it did find, and callers without a live scope keep
today's dict behaviour."""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

import pytest

from plugins.blackbox import detection
from plugins.blackbox.ruleset import compiler, live


class FakeLookup:
    """Stands in for VerifiedLookup: answers from a dict, records the questions."""

    def __init__(self, rules: Dict[str, dict], outcome: str = live.HIT, reason: str = "") -> None:
        self.rules, self.outcome, self.reason = rules, outcome, reason
        self.dependency_questions: List[Sequence[Tuple[str, str, str]]] = []
        self.ioc_questions: List[Sequence[str]] = []

    def _answer(self, keys):
        found = {k: self.rules[k] for k in keys if k in self.rules}
        outcome = self.outcome if self.outcome == live.COULD_NOT_TELL else (live.HIT if found else live.CLEAN)
        return live.LookupAnswer(found, outcome, self.reason)

    def dependencies(self, candidates):
        self.dependency_questions.append(list(candidates))
        from plugins.blackbox.kernel import threat_ids
        return self._answer([threat_ids.dependency_key(e, n, v) for e, n, v in candidates])

    def iocs(self, identifiers):
        self.ioc_questions.append(list(identifiers))
        return self._answer(list(identifiers))


def _public_dep(key, **extra):
    eco, rest = key.split(":", 1)
    return {"identifier": f"dep:{key}", "source": "public", "severity": "critical", "kind": "malware",
            "name": rest, "ecosystem": eco, **extra}


@pytest.fixture
def live_rs(monkeypatch):
    """A ruleset whose live lookup is the fake; its compiled dicts hold only a community rule."""
    rs = compiler.Ruleset(
        dependency={"npm:community-pkg@*": {"identifier": "dep:npm:community-pkg@*", "source": "community",
                                            "severity": "high"}},
        ioc={"ioc:domain:community.example": {"identifier": "ioc:domain:community.example", "source": "community",
                                              "severity": "medium", "iocType": "domain"}},
    )
    lookup = FakeLookup({
        "npm:evil-pkg@1.2.3": _public_dep("npm:evil-pkg@1.2.3"),
        "pypi:bad-pkg@*": _public_dep("pypi:bad-pkg@*"),
        "npm:community-pkg@*": _public_dep("npm:community-pkg@*", severity="critical"),
        "ioc:domain:loader.example": {"identifier": "ioc:domain:loader.example", "source": "public",
                                      "severity": "high", "iocType": "domain", "value": "loader.example"},
    })
    monkeypatch.setattr(rs, "live_lookup", lambda: lookup)
    return rs, lookup


def test_a_pinned_install_is_asked_of_the_live_lookup_with_its_wildcard_too(live_rs):
    rs, lookup = live_rs
    findings = detection.detect_dependency("bash", {"command": "npm install evil-pkg@1.2.3"}, rs)
    assert [f.identifier for f in findings] == ["dep:npm:evil-pkg@1.2.3"] and findings[0].confirmed
    assert lookup.dependency_questions == [[("npm", "evil-pkg", "1.2.3"), ("npm", "evil-pkg", "*")]]


def test_an_unpinned_install_matches_a_whole_package_rule(live_rs):
    rs, _lookup = live_rs
    findings = detection.detect_dependency("bash", {"command": "pip install Bad_Pkg"}, rs)
    assert [f.identifier for f in findings] == ["dep:pypi:bad-pkg@*"]


def test_a_live_public_rule_beats_the_compiled_community_rule_for_the_same_key(live_rs):
    rs, _lookup = live_rs
    findings = detection.detect_dependency("bash", {"command": "npm install community-pkg"}, rs)
    assert findings[0].source == "public" and findings[0].confirmed and findings[0].severity == "critical"


def test_compiled_community_rules_still_flag_when_the_lookup_is_clean(live_rs):
    rs, lookup = live_rs
    lookup.rules.pop("npm:community-pkg@*")
    findings = detection.detect_dependency("bash", {"command": "npm install community-pkg"}, rs)
    assert [(f.source, f.confirmed) for f in findings] == [("community", False)]


def test_ioc_candidates_go_in_one_question_and_both_tiers_answer(live_rs):
    rs, lookup = live_rs
    findings = detection.detect_ioc("web_fetch", {"url": "https://loader.example/x and community.example"}, rs)
    assert {f.identifier: f.source for f in findings} == {
        "ioc:domain:loader.example": "public", "ioc:domain:community.example": "community"}
    assert len(lookup.ioc_questions) == 1 and "ioc:domain:loader.example" in lookup.ioc_questions[0]


def test_a_lookup_that_could_not_tell_still_reports_the_hits_it_found(live_rs):
    rs, lookup = live_rs
    lookup.outcome, lookup.reason = live.COULD_NOT_TELL, "timeout"
    answer = rs.dependency_rules([("npm", "evil-pkg", "1.2.3"), ("npm", "community-pkg", "*")])
    assert answer.outcome == live.COULD_NOT_TELL and answer.reason == "timeout"
    assert set(answer.rules) == {"npm:evil-pkg@1.2.3", "npm:community-pkg@*"}
    findings = detection.detect_dependency("bash", {"command": "npm install evil-pkg@1.2.3"}, rs)
    assert [f.identifier for f in findings] == ["dep:npm:evil-pkg@1.2.3"]


def test_osv_discovery_skips_installs_the_live_lookup_already_covers(live_rs):
    rs, _lookup = live_rs
    asked = []

    def osv_lookup(eco, name, version):
        asked.append((eco, name, version))
        return {"advisory_id": "GHSA-1", "severity": "high", "kind": "vulnerability"}

    findings = detection.discover_dependency_candidates(
        "bash", {"command": "npm install evil-pkg@1.2.3 other-pkg@2.0.0"}, rs, osv_lookup)
    assert asked == [("npm", "other-pkg", "2.0.0")]
    assert [f.identifier for f in findings] == ["dep:npm:other-pkg@2.0.0"]


def test_osv_discovery_keys_pypi_names_canonically(monkeypatch):
    """Foo_Bar==1.0 is the stored rule pypi:foo-bar@1.0 — it must not go to OSV again."""
    rs = compiler.Ruleset(dependency={"pypi:foo-bar@1.0": _public_dep("pypi:foo-bar@1.0")})
    asked = []
    detection.discover_dependency_candidates("bash", {"command": "pip install Foo_Bar==1.0"}, rs,
                                             lambda *a: asked.append(a) or None)
    assert asked == []


def test_a_ruleset_without_a_live_scope_answers_from_its_compiled_dicts():
    rs = compiler.Ruleset(dependency={"npm:evil-pkg@1.2.3": _public_dep("npm:evil-pkg@1.2.3")},
                          ioc={"ioc:ip:203.0.113.9": {"identifier": "ioc:ip:203.0.113.9", "source": "public",
                                                      "severity": "high", "iocType": "ip"}})
    assert rs.live_lookup() is None
    assert rs.dependency_rules([("npm", "evil-pkg", "1.2.3")]).outcome == live.HIT
    assert rs.dependency_rules([("npm", "fine-pkg", "1.0")]).outcome == live.CLEAN
    assert [f.identifier for f in detection.detect_ioc("bash", {"command": "curl 203.0.113.9"}, rs)] == [
        "ioc:ip:203.0.113.9"]


def test_a_bare_object_with_dicts_is_still_indexed_directly():
    from types import SimpleNamespace
    bare = SimpleNamespace(dependency={"npm:evil-pkg@1.2.3": _public_dep("npm:evil-pkg@1.2.3")}, ioc={})
    findings = detection.detect_dependency("bash", {"command": "npm install evil-pkg@1.2.3"}, bare)
    assert [f.identifier for f in findings] == ["dep:npm:evil-pkg@1.2.3"]
    assert detection.detect_ioc("bash", {"command": "curl 203.0.113.9"}, bare) == []
