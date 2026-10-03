"""Community Curation C3 — trust is looked up by identifier and kept by the reader.

The community graph is open: anyone can publish beside a curator's statement
(same subject, same asset name — bench 2026-10-03), shared memory forgets after
about 30 days, and a busy node answers "nothing". So:

* trust statements are fetched by EXACT LOOKUP on the identifiers the reader
  holds, never by an ordered scan;
* what was verified is kept in ``$BLACKBOX_HOME/community_trust.json`` and
  re-verified on every load — the state of record;
* a statement that is merely absent from a read stays; a listing ends on its
  signed expiry day or by a signed delisting, a verdict by a newer one.

Each test drives one attack or one rule. The fake node answers lookups the way
a triple store does (it filters on the VALUES the query names) and records
every query it is sent.
"""

from __future__ import annotations

import json
import re

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from test_blackbox_authority import CFG, CITED, Side, THREAT, TODAY, VM_GRAPH
from test_blackbox_curator_view import _entry

from plugins.blackbox.community import read_curator_view, read_verified_reports
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust import bounded_read, trust_store
from plugins.blackbox.kernel import sparql_text
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


@pytest.fixture
def community(monkeypatch):
    side = Side(GRAPH)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", side.root_hex)
    return side


class Store:
    """A node that answers like a triple store: a lookup returns only the rows
    whose identifier (or subject) the query's VALUES names. ``failing`` makes
    every community-graph query fail; ``slow_empty`` makes it answer empty
    after a timeout-length wait (the measured behaviour of a busy node)."""

    def __init__(self, community=(), reports=(), verified=()):
        self.rows = {GRAPH: list(community), VM_GRAPH: list(verified)}
        self.reports = list(reports)
        self.queries = []
        self.failing = False
        self.failing_statements = False   # only the curator-statement lookups fail
        self.slow_empty = None    # a Clock to advance, or None

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        self.queries.append((cg_id, sparql))
        if cg_id == GRAPH and (self.failing or (self.failing_statements and "g:CuratorStatement" in sparql)):
            return on_error
        if cg_id == GRAPH and self.slow_empty is not None:
            self.slow_empty.now += 10.4
            return []
        if "g:ThreatReport" in sparql:
            return list(self.reports) if cg_id == GRAPH and "COUNT" not in sparql else []
        rows = self.rows.get(cg_id, [])
        if "g:CuratorStatement" in sparql:
            wanted = set(re.findall(r'"((?:[^"\\]|\\.)*)"', sparql.split("VALUES ?identifier", 1)[1].split("}", 1)[0])) \
                if "VALUES ?identifier" in sparql else None
            return [r for r in rows if "curator:" in r["r"] and (wanted is None or r.get("identifier") in wanted)]
        if "VALUES ?r" in sparql:
            subjects = set(re.findall(r"<([^>]+)>", sparql.split("VALUES ?r", 1)[1].split("}", 1)[0]))
            return [r for r in rows if r["r"] in subjects]
        if "g:KeyManifest" in sparql:
            return [r for r in rows if "key-manifest" in r["r"]]
        return []


def _listing(side, reporter, **kw):
    fields = _entry(reporter.author, **{k: v for k, v in kw.items() if k in ("listed", "expires")})
    return side.row(Kind.COUNTED_AUTHORS, f"author:{reporter.author}", fields, sequence=kw.get("sequence", 1))


def _view(node, *reporters, threats=()):
    return read_curator_view(node, CFG, interest=[*(f"author:{r.author}" for r in reporters), *threats])


# ------------------------------------------------------------------ lookups, never scans


def test_trust_statements_are_looked_up_by_identifier_without_ordering(community):
    alice = Reporter("0xa")
    node = Store(community=[community.manifest_row(), _listing(community, alice)])
    assert alice.author in _view(node, alice, threats=[THREAT]).counted
    statement_queries = [q for graph, q in node.queries if graph == GRAPH and "g:CuratorStatement" in q]
    assert statement_queries and all("VALUES ?identifier" in q and "ORDER BY" not in q for q in statement_queries)
    asked = "".join(statement_queries)
    assert f'"author:{alice.author}"' in asked and f'"{THREAT}"' in asked and '"curator"' in asked
    assert all("ORDER BY" not in q for graph, q in node.queries if graph == GRAPH)   # manifests too


def test_a_reporter_nobody_asked_about_is_not_fetched(community):
    """A lookup, not a scan: the node is only asked about identifiers the reader holds."""
    alice, bob = Reporter("0xa"), Reporter("0xb")
    node = Store(community=[community.manifest_row(), _listing(community, alice), _listing(community, bob)])
    assert set(_view(node, alice).counted) == {alice.author}


def test_many_identifiers_are_asked_in_batches_and_capped(community):
    node = Store(community=[community.manifest_row()])
    read_curator_view(node, CFG, interest=[f"ioc:ip:10.0.{i // 250}.{i % 250}" for i in range(250)])
    statement_queries = [q for graph, q in node.queries if "g:CuratorStatement" in q]
    assert len(statement_queries) == 3                                   # 251 identifiers / 100 per query
    found = bounded_read.lookup_statements(Store(), GRAPH, (f"x:{i}" for i in range(bounded_read.MAX_IDENTIFIERS + 500)))
    assert found.complete and found.rows == ()


def test_an_identifier_is_escaped_before_it_enters_a_query():
    hostile = 'x" } ?s ?p ?o . # '
    assert sparql_text.sparql_string_literal(hostile) in bounded_read.statements_sparql([hostile])


def test_the_reader_asks_about_the_reporters_and_threats_it_holds(community):
    alice = Reporter("0xa")
    node = Store(community=[community.manifest_row(), _listing(community, alice)],
                 reports=[signed_row("ioc:ip:203.0.113.7", alice)])
    read = read_verified_reports(node, CFG)
    assert alice.author in read.curator.counted                          # the listing was found through the report's signer
    asked = "".join(q for _, q in node.queries if "g:CuratorStatement" in q)
    assert f'"author:{alice.author}"' in asked and '"ioc:ip:203.0.113.7"' in asked


# ------------------------------------------------------------------ junk beside the genuine statement


def test_junk_carrying_a_genuine_identifier_is_dropped_and_the_genuine_statement_honoured(community):
    """KI-250: a second node can publish under the same subject and identifier."""
    alice = Reporter("0xa")
    genuine = _listing(community, alice)
    impostor = Side(GRAPH)                                                # other keys, same identifier, same subject
    forged = dict(_listing(impostor, alice, listed="no", sequence=9), r=genuine["r"])
    garbage = {"r": genuine["r"], "identifier": genuine["identifier"], "signedStatement": "not an envelope"}
    node = Store(community=[community.manifest_row(), forged, garbage, genuine])
    view = _view(node, alice)
    assert set(view.counted) == {alice.author} and not view.delisted


def test_a_flooded_lookup_is_incomplete_and_changes_nothing_already_verified(community):
    """KI-241: a lookup that reaches its row limit proves nothing about what is missing."""
    alice = Reporter("0xa")
    node = Store(community=[community.manifest_row(), _listing(community, alice)])
    assert alice.author in _view(node, alice).counted                    # verified once, now stored
    junk = [{"r": f"urn:guardian:curator:junk:{i}", "identifier": f"author:{alice.author}", "signedStatement": f"junk-{i}"}
            for i in range(bounded_read.LOOKUP_ROW_LIMIT)]
    flooded = Store(community=[community.manifest_row(), *junk])          # the genuine row is crowded out
    assert not bounded_read.lookup_statements(flooded, GRAPH, [f"author:{alice.author}"]).complete
    view = _view(flooded, alice)
    assert alice.author in view.counted and not view.unavailable


# ------------------------------------------------------------------ the store is the state of record


def test_a_listing_survives_its_disappearance_from_the_network_until_its_signed_expiry(monkeypatch, community):
    alice = Reporter("0xa")
    node = Store(community=[community.manifest_row(), _listing(community, alice, expires="2026-12-31")])
    assert alice.author in _view(node, alice).counted
    gone = Store()                                                        # shared memory forgot everything
    assert alice.author in _view(gone, alice).counted
    monkeypatch.setattr(cv, "_today", lambda: "2027-01-01")
    assert alice.author not in _view(gone, alice).counted                 # the signed expiry day ends it


def test_a_rejection_outlives_its_network_copy(community):
    """KI-251: a rejection that lapsed from shared memory must not let the reports count again."""
    node = Store(community=[community.manifest_row(), community.row(Kind.REJECTION, THREAT, {"reason": "benign"})])
    assert _view(node, threats=[THREAT]).rejected(THREAT)
    assert _view(Store(), threats=[THREAT]).rejected(THREAT)


def test_an_old_listing_replayed_after_a_delisting_is_ignored(community):
    alice = Reporter("0xa")
    listing = _listing(community, alice, sequence=1)
    delisting = _listing(community, alice, listed="no", sequence=2)
    assert alice.author not in _view(Store(community=[community.manifest_row(), listing, delisting]), alice).counted
    replay = Store(community=[community.manifest_row(), listing])         # only the OLD statement is on the network now
    view = _view(replay, alice)
    assert alice.author not in view.counted and alice.author in view.delisted


def test_a_node_that_times_out_with_empty_answers_changes_nothing(monkeypatch, community):
    """KI-262: the measured behaviour of a busy node — empty, after ten seconds."""
    from test_blackbox_trust_read import Clock
    clock = Clock()
    monkeypatch.setattr(sparql_text.time, "monotonic", clock)
    alice = Reporter("0xa")
    node = Store(community=[community.manifest_row(), _listing(community, alice)])
    before = _view(node, alice)
    busy = Store()
    busy.slow_empty = clock
    after = _view(busy, alice)
    assert after.counted == before.counted and not after.unavailable


def test_first_contact_that_cannot_look_is_unavailable_not_empty(community):
    """KI-244: with nothing stored, a failed lookup means "unknown", so readers keep last good."""
    node = Store(community=[community.manifest_row()])
    node.failing = True
    assert read_curator_view(node, CFG).unavailable


def test_a_known_manifest_with_unreadable_statements_is_unavailable_on_first_contact(community):
    """The manifest is found, the statement lookup fails and nothing is stored: this node does not
    know what the curators said, which is not the same as "they said nothing"."""
    alice = Reporter("0xa")
    node = Store(community=[community.manifest_row(), _listing(community, alice)])
    node.failing_statements = True
    view = _view(node, alice)
    assert view.unavailable and not view.counted
    node.failing_statements = False
    assert alice.author in _view(node, alice).counted                     # and it recovers on the next good read


def test_the_stored_file_is_verified_again_on_every_load(tmp_path, community):
    alice, mallory = Reporter("0xa"), Reporter("0xb")
    node = Store(community=[community.manifest_row(), _listing(community, alice)])
    assert alice.author in _view(node, alice).counted
    path = tmp_path / "bbhome" / "community_trust.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    entry = data["graphs"][GRAPH]
    forged = dict(_listing(Side(GRAPH), mallory))                         # signed by keys no root vouches for
    entry["statements"].append({"r": forged["r"], "identifier": forged["identifier"], "signedStatement": forged["signedStatement"]})
    entry["statements"][0]["signedStatement"] = entry["statements"][0]["signedStatement"].replace('"listed":"yes"', '"listed":"no"')
    path.write_text(json.dumps(data), encoding="utf-8")
    view = _view(Store(), alice, mallory)
    assert mallory.author not in view.counted                             # a hand-added listing verifies under no manifest
    assert alice.author not in view.counted and not view.delisted         # the edited statement fails its signature: it adds nothing
    assert alice.author in _view(node, alice).counted                     # and the network restores the genuine one


def test_an_unwritable_or_unreadable_store_never_breaks_the_read(tmp_path, monkeypatch, community):
    """The fail-open path, run for real: the store file's place is taken by a directory."""
    alice = Reporter("0xa")
    home = tmp_path / "bbhome"
    (home / "community_trust.json").mkdir(parents=True)
    node = Store(community=[community.manifest_row(), _listing(community, alice)])
    assert alice.author in _view(node, alice).counted
    assert trust_store.TrustStore().load(GRAPH) == trust_store.StoredTrust()


def test_a_keep_alive_copy_of_a_statement_counts_once(community):
    away = community.row(Kind.AWAY, "curator", {"key": community.manifest.curator_keys[0], "from": "2026-10-02", "until": "2026-10-09"}, signers=1)
    node = Store(community=[community.manifest_row(), away, dict(away), dict(away)])
    view = read_curator_view(node, CFG)
    assert len(view.community.away) == 1
    assert len(trust_store.TrustStore().load(GRAPH).statements) == 1


def test_only_the_newest_statement_per_identifier_is_kept(community):
    alice = Reporter("0xa")
    rows = [community.manifest_row(), _listing(community, alice, sequence=1), _listing(community, alice, listed="no", sequence=2),
            _listing(community, alice, sequence=3)]
    assert alice.author in _view(Store(community=rows), alice).counted
    stored = trust_store.TrustStore().load(GRAPH)
    assert len(stored.statements) == 1 and stored.identifiers == [f"author:{alice.author}"]
    assert stored.baseline_until is not None and len(stored.admitted) == 1      # the listing, admitted in the baseline


def test_statements_signed_long_ago_are_pruned():
    side = Side(GRAPH)
    row = side.row(Kind.CONFIRMATION, THREAT, CITED)                          # signed 2026-10-02
    assert trust_store.current_statements([row], "2027-10-01")             # 364 days: kept
    assert trust_store.current_statements([row], "2028-06-01") == []       # past MAX_STATEMENT_AGE_DAYS


# ------------------------------------------------------------------ manifests


def test_a_manifest_rotation_is_found_by_its_exact_subject_when_the_type_lookup_is_flooded(community):
    import dataclasses

    from plugins.blackbox.kernel import signing
    from test_blackbox_curator_view import _manifest_row
    alice = Reporter("0xa")
    first = Store(community=[community.manifest_row()])
    assert _view(first, alice).community.manifest.version == 1            # v1 verified and stored
    new_keys = Side(GRAPH)
    v2 = dataclasses.replace(community.manifest, version=2,
                             curator_keys=tuple(sorted(signing.public_key_hex(k) for k in new_keys.curators)))
    v2_row = _manifest_row(v2, community.root)
    junk = [{"r": f"urn:guardian:key-manifest:junk:{i}", "signedStatement": f"junk-{i}"} for i in range(bounded_read.MANIFEST_ROW_LIMIT)]

    class Flooded(Store):
        def query(self, sparql, cg_id, view=None, on_error=None, **kw):
            if cg_id == GRAPH and "g:KeyManifest" in sparql and "VALUES ?r" not in sparql:
                self.queries.append((cg_id, sparql))
                return list(junk)                                          # the type lookup returns only junk, at its limit
            return super().query(sparql, cg_id, view=view, on_error=on_error, **kw)

    view = _view(Flooded(community=[v2_row]), alice)
    assert view.community.manifest == v2                                  # the rotated manifest, whole: version and curators


def test_the_next_manifest_subjects_follow_the_newest_known_one():
    assert bounded_read.next_manifest_subjects([])[:2] == ["urn:guardian:key-manifest:0:1", "urn:guardian:key-manifest:0:2"]
    probes = bounded_read.next_manifest_subjects([(1, 3), (1, 2)])
    assert probes[0] == "urn:guardian:key-manifest:1:4" and "urn:guardian:key-manifest:2:1" in probes
