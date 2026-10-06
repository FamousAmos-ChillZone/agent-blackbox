"""Verified partitions read as triples and rebuilt into rows (KI-288 / KI-289).

On DKG 10.0.21 the joined partition query exceeded the 30 s store deadline even
for one asset, so the rules froze at the first asset (exactly 1,000 IOC rules
while the node held 207,005). These tests pin that the triple reader rebuilds
the SAME rows the joined query produced (its SPARQL semantics), that each asset
is cached once read, that a node failure or the time budget only defers assets
to the next refresh, and that progress is recorded for `blackbox status`.
"""

import json

from _blackbox_loader import load_blackbox

pr = load_blackbox("ruleset.partitions.reader")   # rows_from_triples is re-exported there too
compiler = load_blackbox("ruleset.compiler")
fetching = load_blackbox("ruleset.fetching")
constants = load_blackbox("kernel.constants")

TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
DP = "urn:defender:p:"
G = "http://umanitek.ai/ontology/guardian/"
SCHEMA = "http://schema.org/"
PART = "did:dkg:context-graph:cg/_verifiable_memory/0xc/7"


def _ioc(subject, value="bad.example", ioc_type="domain", severity='"high"'):
    return [
        (subject, TYPE, "urn:defender:IocSignal"),
        (subject, f"{DP}value", f'"{value}"'),
        (subject, f"{DP}iocType", f'"{ioc_type}"'),
        (subject, f"{DP}severity", severity),
    ]


# ------------------------------------------------------------------ the row builder


def test_a_defender_signal_becomes_one_row_with_its_columns_and_no_identifier():
    rows = pr.rows_from_triples(PART, _ioc("urn:defender:signal:a"))

    assert rows == [{
        "sourceGraph": PART, "threat": "urn:defender:signal:a", "rdfType": "urn:defender:IocSignal",
        "iocValue": '"bad.example"', "category": '"domain"', "severity": '"high"',
    }]


def test_a_column_takes_the_first_predicates_values_and_never_mixes():
    """Two OPTIONALs on one variable do not union: dp:kind wins when present."""
    both = _ioc("urn:defender:signal:a") + [
        ("urn:defender:signal:a", f"{DP}kind", '"malware"'), ("urn:defender:signal:a", f"{G}kind", '"vulnerability"')]
    only_g = _ioc("urn:defender:signal:b") + [("urn:defender:signal:b", f"{G}kind", '"vulnerability"')]

    kinds = {row["threat"]: row["kind"] for row in pr.rows_from_triples(PART, both + only_g)}

    assert kinds == {"urn:defender:signal:a": '"malware"', "urn:defender:signal:b": '"vulnerability"'}


def test_an_identifier_threat_takes_the_second_branch_with_any_type():
    subject = "urn:guardian:threat:x"
    rows = pr.rows_from_triples(PART, [
        (subject, TYPE, f"{G}Threat"), (subject, f"{G}identifier", '"dep:npm:evil@1.0.0"'),
        (subject, f"{G}severity", '"critical"')])

    assert rows == [{"sourceGraph": PART, "threat": subject, "rdfType": f"{G}Threat",
                     "identifier": '"dep:npm:evil@1.0.0"', "severity": '"critical"'}]


def test_a_typed_signal_with_an_identifier_yields_both_branches():
    subject = "urn:defender:signal:a"
    rows = pr.rows_from_triples(PART, _ioc(subject) + [(subject, f"{G}identifier", '"ioc:domain:bad.example"')])

    assert sorted("identifier" in row for row in rows) == [False, True]


def test_subjects_that_are_not_threats_yield_no_rows():
    """Provenance and helper nodes in an asset carry neither a threat type nor an identifier."""
    assert pr.rows_from_triples(PART, [("urn:prov:activity:1", TYPE, "http://www.w3.org/ns/prov#Activity"),
                                       ("urn:prov:activity:1", f"{SCHEMA}name", '"publish"')]) == []


def test_a_multi_valued_column_multiplies_rows_in_a_stable_order():
    subject = "urn:defender:signal:a"
    triples = _ioc(subject) + [(subject, f"{SCHEMA}name", '"b"'), (subject, f"{SCHEMA}name", '"a"')]

    names = [row["name"] for row in pr.rows_from_triples(PART, triples)]

    assert names == ['"a"', '"b"']
    assert pr.rows_from_triples(PART, list(reversed(triples))) == pr.rows_from_triples(PART, triples)


def test_rebuilt_rows_compile_into_the_same_rules_as_joined_rows():
    """What matters downstream: the compiler sees rows of the shape it always got."""
    joined_shape = [{"sourceGraph": PART, "threat": "urn:defender:signal:a", "rdfType": "urn:defender:IocSignal",
                     "iocValue": '"bad.example"', "category": '"domain"', "severity": '"high"'}]
    rebuilt = pr.rows_from_triples(PART, _ioc("urn:defender:signal:a"))

    assert compiler.build_from_rows(rebuilt).ioc == compiler.build_from_rows(joined_shape).ioc
    assert "ioc:domain:bad.example" in compiler.build_from_rows(rebuilt).ioc


# ------------------------------------------------------------------ reading one partition


class _Node:
    """Answers the triple read and count queries from a triple list; can be told
    to fail, to answer "0 rows" (a restarting store), or to cut a read short."""

    def __init__(self, triples_by_partition, fail=(), page=None):
        self.triples = triples_by_partition
        self.fail = set(fail)
        self.page = page
        self.queries = []
        self.answers_empty = False
        self.drop_last = set()     # partitions whose read loses its last triple

    def query(self, sparql, _cg, view=None, on_error=None, **_kw):
        partition = sparql.split("GRAPH <", 1)[1].split(">", 1)[0]
        if partition in self.fail:
            return on_error
        if self.answers_empty:
            return []
        if "COUNT(*)" in sparql:
            return [{"n": f'"{len(self.triples.get(partition, []))}"^^<http://www.w3.org/2001/XMLSchema#integer>'}]   # as DKG 10.0.21 sends it
        self.queries.append(partition)
        if partition in self.drop_last:
            return [{"threat": s, "p": p, "o": o} for s, p, o in sorted(self.triples.get(partition, []))[:-1]]
        after = sparql.split('FILTER(STR(?threat) > "', 1)[1].split('"', 1)[0] if "FILTER(STR(?threat) >" in sparql else ""
        rows = sorted(t for t in self.triples.get(partition, []) if t[0] > after)
        limit = int(sparql.rsplit("LIMIT", 1)[1].split()[0])
        return [{"threat": s, "p": p, "o": o} for s, p, o in rows[:limit]]


def test_a_partition_is_read_whole_through_the_cursor_when_pages_are_full(monkeypatch):
    triples = [t for i in range(5) for t in _ioc(f"urn:defender:signal:{i}", value=f"x{i}.example")]
    monkeypatch.setattr(pr, "PAGE_TRIPLES", 6)   # 4 triples per threat: every page cuts one
    node = _Node({PART: triples})

    read = pr.read_partition_triples(node, "cg", PART)

    assert sorted(read) == sorted(triples)
    assert len(node.queries) > 1


def test_a_failed_page_reports_the_partition_as_unreadable():
    assert pr.read_partition_triples(_Node({PART: _ioc("urn:a")}, fail={PART}), "cg", PART) is None


# ------------------------------------------------------------------ the cache and the budget


def _partitions(n):
    return [f"did:dkg:context-graph:cg/_verifiable_memory/0xc/{i}" for i in range(n)]


def test_each_partition_is_read_once_then_served_from_disk(tmp_path):
    parts = _partitions(3)
    node = _Node({p: _ioc(f"urn:defender:signal:{i}", value=f"x{i}.example") for i, p in enumerate(parts)})
    cache = pr.PartitionCache(tmp_path)

    first = pr.verified_partition_rows(node, "cg", parts, cache=cache)
    second = pr.verified_partition_rows(node, "cg", parts, cache=cache)

    assert (first.compiled, first.read_now, second.read_now) == (3, 3, 0)
    assert node.queries == parts                       # never queried again
    assert second.rows == first.rows


def test_a_node_failure_defers_the_rest_and_keeps_what_is_cached(tmp_path):
    parts = _partitions(4)
    node = _Node({p: _ioc(f"urn:defender:signal:{i}", value=f"x{i}.example") for i, p in enumerate(parts)})
    cache = pr.PartitionCache(tmp_path)
    pr.verified_partition_rows(node, "cg", parts[:1], cache=cache)          # partition 0 cached earlier
    node.fail = {parts[1]}

    read = pr.verified_partition_rows(node, "cg", parts, cache=cache)

    assert read.compiled == 1 and read.total == 4
    assert "refused" in read.stopped_early
    assert node.queries.count(parts[2]) == 0            # stopped: the store needs its recovery window
    node.fail = set()
    assert pr.verified_partition_rows(node, "cg", parts, cache=cache).compiled == 4   # the next refresh catches up


def test_the_time_budget_defers_unread_partitions(tmp_path):
    parts = _partitions(3)
    node = _Node({p: _ioc(f"urn:defender:signal:{i}", value=f"x{i}.example") for i, p in enumerate(parts)})

    read = pr.verified_partition_rows(node, "cg", parts, cache=pr.PartitionCache(tmp_path), budget_seconds=0)

    assert read.compiled == 0 and "budget" in read.stopped_early


def test_partitions_the_node_no_longer_lists_are_pruned_from_disk(tmp_path):
    parts = _partitions(2)
    node = _Node({p: _ioc(f"urn:defender:signal:{i}", value=f"x{i}.example") for i, p in enumerate(parts)})
    cache = pr.PartitionCache(tmp_path)
    pr.verified_partition_rows(node, "cg", parts, cache=cache)

    pr.verified_partition_rows(node, "cg", parts[:1], cache=cache)

    assert cache.load(parts[0]) is not None and cache.load(parts[1]) is None


def test_a_corrupt_cache_file_is_read_again_not_trusted(tmp_path):
    cache = pr.PartitionCache(tmp_path)
    cache.store(PART, [{"threat": "urn:a"}])
    cache._path(PART).write_bytes(b"not gzip")

    assert cache.load(PART) is None


# ------------------------------------------------------------------ fetch_tier and progress


def test_fetch_tier_serves_every_readable_partition_and_records_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    parts = _partitions(2)
    node = _Node({p: _ioc(f"urn:defender:signal:{i}", value=f"x{i}.example") for i, p in enumerate(parts)})

    class Client(_Node):
        def query(self, sparql, cg, view=None, on_error=None, **kw):
            if "dkg:assertionGraph" in sparql:
                return [{"assertionGraph": p, "status": "confirmed"} for p in parts]
            if "GRAPH <did:dkg:context-graph:cg>" in sparql:
                return []                                   # the root data graph is empty
            return super().query(sparql, cg, view=view, on_error=on_error, **kw)

    rows = fetching.fetch_tier(Client(node.triples), "cg", constants.VIEW_VERIFIABLE_MEMORY)

    assert {r["iocValue"] for r in rows} == {'"x0.example"', '"x1.example"'}
    assert pr.progress("cg")["assets_compiled"] == 2
    assert pr.progress("another-graph") is None


def test_nothing_readable_and_nothing_cached_keeps_the_last_good_tier(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    parts = _partitions(1)

    class Client:
        def query(self, sparql, cg, view=None, on_error=None, **kw):
            if "dkg:assertionGraph" in sparql:
                return [{"assertionGraph": parts[0], "status": "confirmed"}]
            return on_error

    assert fetching.fetch_tier(Client(), "cg", constants.VIEW_VERIFIABLE_MEMORY) is None
    assert json.loads((tmp_path / "verified_partitions" / "progress.json").read_text())["assets_compiled"] == 0


# ------------------------------------------------------------------ catching up between refreshes


refresh_cycle = load_blackbox("ruleset.refresh_cycle")


class _Config:
    sync_interval = 3600


def _next_refresh_in(progress, tmp_path, monkeypatch):
    """Seconds until the scheduler wants the next refresh, given recorded progress."""
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(refresh_cycle.time, "time", lambda: 1_000_000.0)   # one clock for record and check
    if progress is not None:
        pr.record_progress("cg", pr.PartitionRead(rows=[], total=progress[1], compiled=progress[0],
                                                  read_now=0, stopped_early=""))
    rs = compiler.build_from_rows([])
    rs.context_graph_id = "cg"
    rs.synced_at = 1_000_000.0
    refresh_cycle._schedule_next_refresh(rs, _Config(), False)
    return rs.synced_at + _Config.sync_interval - 1_000_000.0


def test_a_partly_compiled_graph_is_refreshed_again_within_minutes(tmp_path, monkeypatch):
    """KI-288: 1 of 564 assets compiled must not wait a whole sync interval for the rest."""
    assert _next_refresh_in((1, 564), tmp_path, monkeypatch) == refresh_cycle._CATCHING_UP_RETRY_S


def test_a_fully_compiled_graph_that_stopped_growing_keeps_the_normal_interval(tmp_path, monkeypatch):
    monkeypatch.setattr(pr, "GROWTH_QUIET_SECONDS", 0)
    assert _next_refresh_in((564, 564), tmp_path, monkeypatch) == _Config.sync_interval


def _record(compiled, total):
    pr.record_progress("cg", pr.PartitionRead(total=total, compiled=compiled))


def test_a_node_still_receiving_the_graph_is_catching_up_though_all_it_lists_is_compiled(tmp_path, monkeypatch):
    """Bench native-a 2026-10-06: 5 of 5 listed assets compiled while 559 were still
    downloading, so the rules waited an hour behind a node that already held 288."""
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    clock = [1_000_000.0]
    monkeypatch.setattr(pr.time, "time", lambda: clock[0])
    _record(1, 1)
    clock[0] += 120
    _record(5, 5)                                   # grew: every listed asset compiled, yet more coming

    clock[0] += pr.GROWTH_QUIET_SECONDS - 1
    assert pr.catching_up("cg")


def test_a_pause_in_the_download_does_not_end_catching_up_early(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    clock = [1_000_000.0]
    monkeypatch.setattr(pr.time, "time", lambda: clock[0])
    _record(5, 5)
    for _ in range(3):                              # refreshes during a pause: the count stands still
        clock[0] += 120
        _record(5, 5)

    assert pr.catching_up("cg")
    clock[0] = 1_000_000.0 + pr.GROWTH_QUIET_SECONDS + 1
    assert not pr.catching_up("cg")                 # quiet for the whole window: done


def test_no_recorded_progress_keeps_the_normal_interval(tmp_path, monkeypatch):
    """A custom graph that never went through the partition reader is not 'catching up'."""
    assert _next_refresh_in(None, tmp_path, monkeypatch) == _Config.sync_interval


def test_progress_for_another_graph_is_not_catching_up(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    pr.record_progress("cg", pr.PartitionRead(total=564, compiled=1))

    assert pr.catching_up("cg") and not pr.catching_up("another-graph")


def test_last_good_rules_kept_through_a_failed_read_still_retry_soon_while_catching_up(tmp_path, monkeypatch):
    """A store deadline mid-catch-up keeps the last-good rules; it must not also reset the pace to hourly."""
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(refresh_cycle.time, "time", lambda: 1_000_000.0)
    _record(6, 290)

    kept = refresh_cycle._reuse_generation(compiler.build_from_rows([]), "cg", None, _Config())

    assert kept.synced_at + _Config.sync_interval - 1_000_000.0 == refresh_cycle._CATCHING_UP_RETRY_S



# ------------------------------------------------------------------ "could not tell" is never cached


def test_an_empty_answer_for_a_confirmed_asset_is_not_cached(tmp_path):
    """Bench native-c 2026-10-06: after its store restarted the node answered every query
    with 0 rows; caching that would drop the asset's threats from the rules for good."""
    parts = _partitions(1)
    node = _Node({parts[0]: _ioc("urn:defender:signal:0")})
    node.answers_empty = True
    cache = pr.PartitionCache(tmp_path)

    read = pr.verified_partition_rows(node, "cg", parts, cache=cache)

    assert read.compiled == 0 and "refused" in read.stopped_early
    assert cache.load(parts[0]) is None
    node.answers_empty = False
    assert pr.verified_partition_rows(node, "cg", parts, cache=cache).compiled == 1


def test_a_read_shorter_than_the_count_is_not_cached(tmp_path):
    parts = _partitions(1)
    node = _Node({parts[0]: _ioc("urn:defender:signal:0")})
    node.drop_last = {parts[0]}
    cache = pr.PartitionCache(tmp_path)

    assert pr.verified_partition_rows(node, "cg", parts, cache=cache).compiled == 0
    assert cache.load(parts[0]) is None


def test_an_empty_asset_listing_keeps_every_cached_asset(tmp_path):
    parts = _partitions(2)
    node = _Node({p: _ioc(f"urn:defender:signal:{i}", value=f"x{i}.example") for i, p in enumerate(parts)})
    cache = pr.PartitionCache(tmp_path)
    pr.verified_partition_rows(node, "cg", parts, cache=cache)

    pr.verified_partition_rows(node, "cg", [], cache=cache)          # a restarting node lists nothing

    assert all(cache.load(p) is not None for p in parts)
