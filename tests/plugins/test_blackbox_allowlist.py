"""Refine R9 — allowlist, warninglist, canaries (plan §06, look-alike rule inverted).

* The Public Suffix List gives the comparison key: registrable domain, or the
  full host under shared hosting; a bare suffix is not registrable.
* A byte-exact allowlisted name HOLDS (weight 0); a look-alike SUPPORTS the
  report and is tagged confusable-of:<name>; a version-pinned malware report
  on a popular package COUNTS while a name-level or vulnerability one is held.
* The tables are immutable after load and the home file extends the seed.
* Canaries are curator-private; a hit names the reporter for a strike.
* The stage machine applies all of it; the dossier shows the verdict.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.community import allowlist, stages
from plugins.blackbox.community.allowlist import tables as allow_tables
from plugins.blackbox.community.stages import Enforcement, Stage
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.curate import dossier
from plugins.blackbox.kernel import public_suffix

DAY = 86_400
NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    public_suffix.load.cache_clear()
    allow_tables.load.cache_clear()
    yield
    public_suffix.load.cache_clear()
    allow_tables.load.cache_clear()


# ------------------------------------------------------------------ the Public Suffix List


def test_the_vendored_list_parses_and_answers_registrable_domains():
    rules = public_suffix.load()
    assert rules.version and len(rules.rules) > 5000 and len(rules.private) > 1000
    assert public_suffix.registrable_domain("login.paypal.co.uk") == "paypal.co.uk"
    assert public_suffix.registrable_domain("co.uk") is None                       # a public suffix is not registrable
    assert public_suffix.public_suffix("a.b.ck") == "b.ck" and public_suffix.registrable_domain("www.ck") == "www.ck"   # wildcard + exception
    assert public_suffix.registrable_domain("evil.github.io") == "evil.github.io" and public_suffix.is_shared_hosting("evil.github.io")
    assert not public_suffix.is_shared_hosting("paypal.com")


def test_a_home_override_and_an_unreadable_list_fail_open(tmp_path, monkeypatch):
    home = tmp_path / "bbhome"
    home.mkdir(parents=True, exist_ok=True)
    (home / "public_suffix_list.dat").write_text("// VERSION: test\nexample\n*.wild\n!ok.wild\n", encoding="utf-8")
    public_suffix.load.cache_clear()
    assert public_suffix.load().version == "test" and public_suffix.registrable_domain("a.b.wild") == "a.b.wild"
    assert public_suffix.registrable_domain("x.ok.wild") == "ok.wild"              # the exception stops the wildcard
    monkeypatch.setattr(public_suffix, "_VENDORED", tmp_path / "missing.dat")
    (home / "public_suffix_list.dat").unlink()
    public_suffix.load.cache_clear()
    assert public_suffix.load().rules == frozenset() and public_suffix.registrable_domain("a.b.c") == "b.c"


# ------------------------------------------------------------------ verdicts


def test_byte_exact_holds_and_a_look_alike_supports():
    exact = allowlist.check("ioc:domain:paypal.com")
    assert exact.verdict is allowlist.AllowlistVerdict.HOLD_EXACT and exact.holds
    assert allowlist.check("ioc:url:https://login.paypal.com/signin").verdict is allowlist.AllowlistVerdict.HOLD_EXACT
    homograph = allowlist.check("ioc:domain:paypa1.com")
    assert (homograph.verdict, homograph.confusable_of, homograph.holds) == (allowlist.AllowlistVerdict.SUPPORT_CONFUSABLE, "paypal.com", False)
    assert allowlist.check("ioc:domain:rnicrosoft.com").confusable_of == "microsoft.com"
    assert allowlist.check("ioc:domain:unrelated.example").verdict is allowlist.AllowlistVerdict.NONE
    assert allowlist.check("ioc:domain:evil.github.io").verdict is allowlist.AllowlistVerdict.NONE   # shared hosting: URL granularity


def test_a_version_pinned_malware_report_on_a_popular_package_counts_but_name_level_or_vulnerability_is_held():
    assert allowlist.check("dep:npm:lodash@4.17.21", {"kind": "malware"}).verdict is allowlist.AllowlistVerdict.NONE
    assert allowlist.check("dep:npm:lodash@*", {"kind": "malware"}).verdict is allowlist.AllowlistVerdict.HOLD_WARNINGLIST
    assert allowlist.check("dep:npm:lodash@4.17.21", {"kind": "vulnerability"}).verdict is allowlist.AllowlistVerdict.HOLD_WARNINGLIST
    typo = allowlist.check("dep:npm:lodahs@1.0.0")
    assert typo.verdict is allowlist.AllowlistVerdict.SUPPORT_CONFUSABLE and typo.confusable_of == "lodash"
    assert allowlist.check("dep:npm:evil-pkg@1.0.0").verdict is allowlist.AllowlistVerdict.NONE
    assert allowlist.check("injection:prompt:abc").verdict is allowlist.AllowlistVerdict.NONE


def test_skeleton_and_edit_distance_rules():
    assert allowlist.skeleton("PayPa1") == "paypal" and allowlist.skeleton("rnicrosoft") == allowlist.skeleton("microsoft")
    assert allowlist.edit_distance("paypal", "paypa1") == 1 and allowlist.edit_distance("paypal", "something-else") > 2
    assert allowlist.confusable_of("paypal.com", {"paypal.com"}) is None            # never the name itself


def test_the_home_file_extends_the_seed_and_garbage_is_ignored(tmp_path):
    home = tmp_path / "bbhome"
    home.mkdir(parents=True, exist_ok=True)
    (home / "allowlist.json").write_text(json.dumps({"domains": ["MyBank.example"], "packages": ["npm:MyLib"]}), encoding="utf-8")
    allow_tables.load.cache_clear()
    loaded = allowlist.load()
    assert "mybank.example" in loaded.domains and "paypal.com" in loaded.domains and "npm:mylib" in loaded.packages
    assert allowlist.check("ioc:domain:www.mybank.example").verdict is allowlist.AllowlistVerdict.HOLD_EXACT
    (home / "allowlist.json").write_text("{nope", encoding="utf-8")
    allow_tables.load.cache_clear()
    assert allowlist.load().domains == allowlist.SEED_DOMAINS


# ------------------------------------------------------------------ in the stage machine


def _view(partners):
    counted = {k: cv.CountedAuthor(k, "0x" + k[:40], "partner", org, "2027-01-01") for k, org in partners}
    return cv.CuratorView(counted=counted)


def test_the_stage_machine_holds_exact_matches_and_supports_homographs():
    keys = [f"p{i:02d}".ljust(64, "0") for i in range(3)]
    view = _view([(k, f"org{i}") for i, k in enumerate(keys)])
    held = stages.stage_for("ioc:domain:paypal.com", keys, NOW - 10 * DAY, view, 0, None, NOW)
    assert (held.stage, held.enforcement) == (Stage.HELD, Enforcement.MONITOR) and "paypal.com" in held.reason
    supported = stages.stage_for("ioc:domain:paypa1.com", keys, NOW - 10 * DAY, view, 0, None, NOW)
    assert (supported.stage, supported.enforcement, supported.confusable_of) == (Stage.CORROBORATED, Enforcement.FLAG, "paypal.com")
    assert supported.as_fields()["confusableOf"] == "paypal.com" and "confusableOf" not in held.as_fields()
    noise = stages.stage_for("dep:npm:lodash@4.17.21", keys, NOW - 10 * DAY, view, 0, None, NOW, {"kind": "vulnerability"})
    assert noise.stage is Stage.HELD
    real = stages.stage_for("dep:npm:lodash@4.17.21", keys, NOW - 10 * DAY, view, 0, None, NOW, {"kind": "malware"})
    assert real.stage is Stage.CORROBORATED                                        # a hijacked popular package counts


# ------------------------------------------------------------------ canaries and the dossier


class _Report:
    def __init__(self, identifier, author):
        self.identifier, self.author = identifier, author


def test_canaries_are_private_and_name_the_reporter_for_a_strike(tmp_path):
    store = allowlist.CanaryStore(tmp_path / "canaries.json")
    store.plant("ioc:domain:never-used-7f3a.example")
    store.plant("ioc:domain:never-used-7f3a.example")
    assert store.planted() == ["ioc:domain:never-used-7f3a.example"]
    hits = store.hits([_Report("ioc:domain:never-used-7f3a.example", "k1"), _Report("ioc:domain:real.example", "k2"),
                       _Report("ioc:domain:never-used-7f3a.example", "k1")])
    assert hits == {"k1": ["ioc:domain:never-used-7f3a.example"]}
    assert store.remove("ioc:domain:never-used-7f3a.example") and not store.remove("ioc:domain:never-used-7f3a.example")
    assert allowlist.CanaryStore(tmp_path / "missing.json").hits([_Report("x", "k")]) == {}


def test_the_dossier_shows_the_allowlist_verdict():
    built = dossier.DossierBuilder("ioc:domain:paypa1.com", clock=lambda: NOW).allowlist(allowlist.check("ioc:domain:paypa1.com")).build()
    assert [s.name for s in built.sources] == ["allowlist"]
    assert built.sources[0].summary.startswith("support-confusable (confusable-of:paypal.com)")
