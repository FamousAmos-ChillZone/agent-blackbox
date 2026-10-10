"""Browsing the live tiers and asking "already verified?" without a compiled list (DKG-lookup B7)."""

from __future__ import annotations

import re
from typing import Dict, List

import pytest

from plugins.blackbox.dashboard import graph_pages
from plugins.blackbox.kernel.store import StoreAnswer, StoreClient
from plugins.blackbox.ruleset import compiler, live
from plugins.blackbox.ruleset.live import browse
from test_blackbox_live_lookup import CG, FOREIGN, GRAPHS, PART_A, PART_B, SCOPE, _dep, _ioc

TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
DP = "urn:defender:p:"


class BrowseStore(StoreClient):
    """Answers the browse module's three query shapes from the named-graph fixture."""

    def __init__(self, graphs: Dict[str, List[tuple]], *, fail: str = "") -> None:
        super().__init__("http://127.0.0.1:7878/query")
        self.graphs, self.fail, self.queries = graphs, fail, []

    def _subjects(self, sparql: str):
        kind = "dependency" if "DependencySignal" in sparql else "ioc"
        eco = re.search(r'<urn:defender:p:ecosystem> "([^"]*)"', sparql)
        needle = re.search(r'CONTAINS\(LCASE\(\?(?:pkg|val)\), "([^"]*)"\)', sparql)
        prefix = re.search(r'STRSTARTS\(STR\(\?g\), "([^"]*)"\)', sparql).group(1)
        out = []
        for graph, triples in self.graphs.items():
            if not graph.startswith(prefix):
                continue
            by_subject: Dict[str, Dict[str, str]] = {}
            for s, p, o in triples:
                by_subject.setdefault(s, {})[p] = o.strip('"')
            for subject, facts in by_subject.items():
                is_dep = facts.get(TYPE) == "urn:defender:DependencySignal"
                if (kind == "dependency") != is_dep:
                    continue
                text = facts.get(f"{DP}package") if is_dep else facts.get(f"{DP}value")
                if eco and facts.get(f"{DP}ecosystem") != eco.group(1):
                    continue
                if needle and needle.group(1) not in (text or "").lower():
                    continue
                out.append((graph, subject, facts.get(f"{DP}ecosystem", "")))
        return sorted(out, key=lambda x: x[1])

    def select(self, sparql: str, *, timeout=None) -> StoreAnswer:
        self.queries.append(sparql)
        if self.fail:
            return StoreAnswer(None, self.fail)
        if "VALUES (?g ?t)" in sparql:
            return self._bound_triples(sparql)
        subjects = self._subjects(sparql)
        if "GROUP BY ?eco" in sparql:
            totals: Dict[str, int] = {}
            for _g, _s, eco in subjects:
                totals[eco] = totals.get(eco, 0) + 1
            return StoreAnswer([{"g": "x", "eco": f'"{e}"', "n": f'"{n}"'} for e, n in totals.items()])
        if "OFFSET" not in sparql:                       # a search's one read: SELECT ?g ?t … LIMIT n
            cap = int(re.search(r"LIMIT (\d+)", sparql).group(1))
            return StoreAnswer([{"g": g, "t": s} for g, s, _e in subjects[:cap]])
        offset = int(re.search(r"OFFSET (\d+)", sparql).group(1))
        limit = int(re.search(r"OFFSET \d+ LIMIT (\d+)", sparql).group(1))
        return StoreAnswer([{"g": g, "t": s} for g, s, _e in subjects[offset:offset + limit]])

    def _bound_triples(self, sparql: str) -> StoreAnswer:
        pairs = set(re.findall(r"\(<([^>]+)> <([^>]+)>\)", sparql))
        return StoreAnswer([{"g": g, "t": s, "p": p, "o": o} for g, triples in self.graphs.items()
                            for s, p, o in triples if (g, s) in pairs])


SCOPE_WITH_COUNTS = live.VerifiedScope(**{**SCOPE.__dict__, "verified_counts": {   # the two browsable deps
    "dependency": 2, "ioc": 2, "dependency:npm": 2}})


def test_the_front_page_lists_dependencies_then_iocs_with_whole_result_totals():
    page = live.public_page(SCOPE_WITH_COUNTS, BrowseStore(GRAPHS), offset=0, limit=10)
    identifiers = [e["identifier"] for e in page.entries]
    assert identifiers[:2] == ["dep:npm:wallet-security-checker@2.0.3", "dep:npm:avnjs@*"]   # suppressed + revoked gone
    assert set(identifiers[2:]) == {"ioc:domain:loader.example", "ioc:ip:203.0.113.9"}
    assert page.known and page.total == 4 and page.kind_totals == {"dependency": 2, "ioc": 2}
    assert page.ecosystem_totals == {"npm": 2}        # the scope's refresh-time per-ecosystem count


def test_offset_and_limit_run_across_the_kinds():
    store = BrowseStore(GRAPHS)
    page = live.public_page(SCOPE_WITH_COUNTS, store, offset=1, limit=2)
    assert [e["category"] for e in page.entries] == ["dependency", "ioc"]     # the window straddles the kinds
    assert page.total == 4 and not any("ORDER BY" in q for q in store.queries)


def test_filters_narrow_the_live_tiers_and_count_through_the_store():
    store = BrowseStore(GRAPHS)
    page = live.public_page(SCOPE_WITH_COUNTS, store, category="dependency", ecosystem="npm", needle="wallet", limit=10)
    assert [e["identifier"] for e in page.entries] == ["dep:npm:wallet-security-checker@2.0.3"]
    assert page.total == 1 and page.kind_totals == {"dependency": 1} and not page.capped
    assert any('"wallet"' in q and "LIMIT 11" in q for q in store.queries)    # one read, up to the page's end + 1
    assert live.public_page(SCOPE_WITH_COUNTS, BrowseStore(GRAPHS), category="injection").total == 0


def test_a_hostile_needle_stays_a_literal():
    store = BrowseStore(GRAPHS)
    live.public_page(SCOPE_WITH_COUNTS, store, needle='x" } } . ?t ?p ?o #', limit=5)
    assert all(q.count("GRAPH ?g") <= 2 and '\\"' in q for q in store.queries if "CONTAINS" in q)


def test_a_store_that_cannot_answer_is_not_an_empty_graph():
    page = live.public_page(SCOPE_WITH_COUNTS, BrowseStore(GRAPHS, fail="timeout"), needle="x", limit=5)
    assert not page.known and page.reason == "timeout" and page.entries == []


# ------------------------------------------------------------------ the dashboard merge


class _LiveRuleset(compiler.Ruleset):
    def __init__(self, store, **kw):
        super().__init__(**kw)
        self._store = store

    def live_browse(self, **filters):
        return live.public_page(SCOPE_WITH_COUNTS, self._store, **filters)


def test_the_public_page_puts_compiled_small_tiers_first_then_the_live_tiers():
    rs = _LiveRuleset(BrowseStore(GRAPHS), verified_scope=SCOPE_WITH_COUNTS)
    compiled = [{"identifier": "injection:one", "category": "injection", "severity": "high", "name": "One"}]
    response = graph_pages.public_tier_response(rs, compiled, needle="", category="", ecosystem="", offset=0, limit=3)
    assert [t["identifier"] for t in response["threats"]] == ["injection:one", "dep:npm:wallet-security-checker@2.0.3",
                                                              "dep:npm:avnjs@*"]
    assert response["total"] == 5 and response["partial"] is True
    assert response["category_totals"] == {"injection": 1, "dependency": 2, "ioc": 2}
    assert response["ecosystem_totals"] == {"npm": 2} and "live_unavailable" not in response
    later = graph_pages.public_tier_response(rs, compiled, needle="", category="", ecosystem="", offset=3, limit=10)
    assert [t["category"] for t in later["threats"]] == ["ioc", "ioc"] and later["partial"] is False


def test_the_public_page_says_when_the_live_tiers_are_unavailable():
    rs = _LiveRuleset(BrowseStore(GRAPHS, fail="http 503"), verified_scope=SCOPE_WITH_COUNTS)
    response = graph_pages.public_tier_response(rs, [], needle="y", category="", ecosystem="", offset=0, limit=5)
    assert response["threats"] == [] and response["live_unavailable"] == "http 503"


def test_a_ruleset_without_a_scope_answers_from_the_compiled_entries_alone():
    compiled = [{"identifier": "dep:npm:a@1", "category": "dependency", "severity": "high", "name": "A"}]
    response = graph_pages.public_tier_response(compiler.Ruleset(), compiled, needle="", category="", ecosystem="",
                                                offset=0, limit=5)
    assert response == graph_pages.tier_response("public", compiled, 0, 5)


# ------------------------------------------------------------------ one rule, one identifier


def test_rule_for_falls_back_to_the_live_lookup_for_public_identifiers(monkeypatch):
    from test_blackbox_live_lookup import FakeStore
    rs = compiler.Ruleset(verified_scope=SCOPE)
    monkeypatch.setattr(rs, "live_lookup", lambda: live.VerifiedLookup(SCOPE, FakeStore(GRAPHS)))
    rule = graph_pages.rule_for(rs, "public", "dep:npm:wallet-security-checker@2.0.3")
    assert rule["subject"] == "urn:defender:signal:a1" and rule["severity"] == "critical"
    assert graph_pages.rule_for(rs, "public", "ioc:domain:loader.example")["subject"] == "urn:defender:signal:a3"
    assert graph_pages.rule_for(rs, "public", "dep:npm:react@18.3.1") == {}
    assert graph_pages.rule_for(rs, "community", "dep:npm:wallet-security-checker@2.0.3") == {}


# ------------------------------------------------------------------ already verified?


def test_verified_subset_combines_compiled_rules_and_live_lookups(monkeypatch):
    from test_blackbox_live_lookup import FakeStore
    rs = compiler.Ruleset(verified_scope=SCOPE, injection=[{"identifier": "injection:one", "source": "public"}])
    monkeypatch.setattr(rs, "live_lookup", lambda: live.VerifiedLookup(SCOPE, FakeStore(GRAPHS)))
    asked = ["injection:one", "injection:other", "dep:npm:wallet-security-checker@2.0.3", "dep:npm:react@18.3.1",
             "ioc:ip:203.0.113.9", "ioc:domain:google.com", "dep:npm:revoked-pkg@*"]
    assert rs.verified_subset(asked) == {"injection:one", "dep:npm:wallet-security-checker@2.0.3", "ioc:ip:203.0.113.9"}


def test_verified_subset_without_a_scope_uses_the_compiled_dicts_only():
    rs = compiler.Ruleset(dependency={"npm:a@1": {"identifier": "dep:npm:a@1", "source": "public"},
                                      "npm:c@1": {"identifier": "dep:npm:c@1", "source": "community"}})
    assert rs.verified_subset(["dep:npm:a@1", "dep:npm:c@1", "dep:npm:b@1"]) == {"dep:npm:a@1"}


def test_the_curate_helper_asks_for_a_known_universe():
    from plugins.blackbox.curate.context import verified_identifiers
    rs = compiler.Ruleset(dependency={"npm:a@1": {"identifier": "dep:npm:a@1", "source": "public"}})
    assert verified_identifiers(rs, {"dep:npm:a@1": {}, "dep:npm:z@1": {}}) == {"dep:npm:a@1"}
    assert verified_identifiers(None, ["dep:npm:a@1"]) == set()


def test_the_window_and_its_triples_are_two_queries_never_one_join():
    """Bench A 2026-10-10: the joined form ran > 120 s; the window is 0.04 s and the
    bound triple read an index lookup."""
    store = BrowseStore(GRAPHS)
    live.public_page(SCOPE_WITH_COUNTS, store, category="ioc", limit=5)
    window = [q for q in store.queries if "OFFSET" in q]
    triples = [q for q in store.queries if "VALUES (?g ?t)" in q]
    assert window and triples and not any("?p ?o" in q for q in window)
    assert all("OFFSET" not in q for q in triples)


def test_an_ecosystem_is_bound_as_a_literal_not_filtered():
    store = BrowseStore(GRAPHS)
    page = live.public_page(SCOPE_WITH_COUNTS, store, category="dependency", ecosystem="npm", limit=5)
    assert page.known and page.ecosystem_totals == {"npm": page.kind_totals["dependency"]}
    assert all("?eco =" not in q for q in store.queries)


def test_unsearched_pages_never_count_through_the_store():
    store = BrowseStore(GRAPHS)
    page = live.public_page(SCOPE_WITH_COUNTS, store, category="dependency", ecosystem="npm", limit=5)
    assert page.total == 2 and not any("COUNT" in q or "GROUP BY" in q for q in store.queries)


def test_a_search_reads_its_matches_once_and_says_when_there_are_more():
    store = BrowseStore(GRAPHS)
    page = live.public_page(SCOPE_WITH_COUNTS, store, category="dependency", needle="e", limit=1)
    assert page.capped and len(page.entries) == 1
    assert sum(1 for q in store.queries if "CONTAINS" in q) == 1      # count and window share the read


def test_plain_paging_stops_at_the_depth_cap():
    page = live.public_page(SCOPE_WITH_COUNTS, BrowseStore(GRAPHS), offset=browse.MAX_DEPTH, limit=10)
    assert not page.known and "search or filter" in page.reason
