"""Verified partitions read as triples and rebuilt into rows (KI-288 / KI-289).

On DKG 10.0.21 the joined partition query exceeded the 30 s store deadline even
for one asset, so the rules froze at the first asset (exactly 1,000 IOC rules
while the node held 207,005). These tests pin that the row builder rebuilds
the SAME rows the joined query produced (its SPARQL semantics) — the live lookups
run every store answer through it — and that refresh progress is recorded for
`blackbox status` (the per-asset reader itself was retired by DKG-lookup B6).
"""

import json

from _blackbox_loader import load_blackbox

pr = load_blackbox("ruleset.partitions.reader")
rows_builder = load_blackbox("ruleset.partitions.rows")
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
    rows = rows_builder.rows_from_triples(PART, _ioc("urn:defender:signal:a"))

    assert rows == [{
        "sourceGraph": PART, "threat": "urn:defender:signal:a", "rdfType": "urn:defender:IocSignal",
        "iocValue": '"bad.example"', "category": '"domain"', "severity": '"high"',
    }]


def test_a_column_takes_the_first_predicates_values_and_never_mixes():
    """Two OPTIONALs on one variable do not union: dp:kind wins when present."""
    both = _ioc("urn:defender:signal:a") + [
        ("urn:defender:signal:a", f"{DP}kind", '"malware"'), ("urn:defender:signal:a", f"{G}kind", '"vulnerability"')]
    only_g = _ioc("urn:defender:signal:b") + [("urn:defender:signal:b", f"{G}kind", '"vulnerability"')]

    kinds = {row["threat"]: row["kind"] for row in rows_builder.rows_from_triples(PART, both + only_g)}

    assert kinds == {"urn:defender:signal:a": '"malware"', "urn:defender:signal:b": '"vulnerability"'}


def test_an_identifier_threat_takes_the_second_branch_with_any_type():
    subject = "urn:guardian:threat:x"
    rows = rows_builder.rows_from_triples(PART, [
        (subject, TYPE, f"{G}Threat"), (subject, f"{G}identifier", '"dep:npm:evil@1.0.0"'),
        (subject, f"{G}severity", '"critical"')])

    assert rows == [{"sourceGraph": PART, "threat": subject, "rdfType": f"{G}Threat",
                     "identifier": '"dep:npm:evil@1.0.0"', "severity": '"critical"'}]


def test_a_typed_signal_with_an_identifier_yields_both_branches():
    subject = "urn:defender:signal:a"
    rows = rows_builder.rows_from_triples(PART, _ioc(subject) + [(subject, f"{G}identifier", '"ioc:domain:bad.example"')])

    assert sorted("identifier" in row for row in rows) == [False, True]


def test_subjects_that_are_not_threats_yield_no_rows():
    """Provenance and helper nodes in an asset carry neither a threat type nor an identifier."""
    assert rows_builder.rows_from_triples(PART, [("urn:prov:activity:1", TYPE, "http://www.w3.org/ns/prov#Activity"),
                                       ("urn:prov:activity:1", f"{SCHEMA}name", '"publish"')]) == []


def test_a_multi_valued_column_multiplies_rows_in_a_stable_order():
    subject = "urn:defender:signal:a"
    triples = _ioc(subject) + [(subject, f"{SCHEMA}name", '"b"'), (subject, f"{SCHEMA}name", '"a"')]

    names = [row["name"] for row in rows_builder.rows_from_triples(PART, triples)]

    assert names == ['"a"', '"b"']
    assert rows_builder.rows_from_triples(PART, list(reversed(triples))) == rows_builder.rows_from_triples(PART, triples)


def test_rebuilt_rows_compile_into_the_same_rules_as_joined_rows():
    """What matters downstream: the compiler sees rows of the shape it always got."""
    joined_shape = [{"sourceGraph": PART, "threat": "urn:defender:signal:a", "rdfType": "urn:defender:IocSignal",
                     "iocValue": '"bad.example"', "category": '"domain"', "severity": '"high"'}]
    rebuilt = rows_builder.rows_from_triples(PART, _ioc("urn:defender:signal:a"))

    assert compiler.build_from_rows(rebuilt).ioc == compiler.build_from_rows(joined_shape).ioc
    assert "ioc:domain:bad.example" in compiler.build_from_rows(rebuilt).ioc


# ------------------------------------------------------------------ fetch_tier and progress


def _partitions(n):
    return [f"did:dkg:context-graph:cg/_verifiable_memory/0xc/{i}" for i in range(n)]





def test_fetch_tier_records_every_confirmed_asset_as_in_scope(tmp_path, monkeypatch):
    """DKG-lookup B6: dependency / IOC rules are looked up live in every confirmed
    asset, so progress says every confirmed asset is compiled (no per-asset reads)."""
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    parts = _partitions(2)

    class Client:
        def query(self, sparql, cg, view=None, on_error=None, **kw):
            if "dkg:assertionGraph" in sparql:
                return [{"assertionGraph": p, "status": "confirmed"} for p in parts]
            return []                                       # small tiers and root graph empty

    assert fetching.fetch_tier(Client(), "cg", constants.VIEW_VERIFIABLE_MEMORY) == []
    assert pr.progress("cg")["assets_compiled"] == pr.progress("cg")["assets_total"] == 2
    assert pr.progress("another-graph") is None


def test_a_refused_small_tier_read_keeps_the_last_good_tier_and_records_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    parts = _partitions(1)

    class Client:
        def query(self, sparql, cg, view=None, on_error=None, **kw):
            if "dkg:assertionGraph" in sparql:
                return [{"assertionGraph": parts[0], "status": "confirmed"}]
            return on_error                                 # every lane refused

    assert fetching.fetch_tier(Client(), "cg", constants.VIEW_VERIFIABLE_MEMORY) is None
    assert pr.progress("cg") is None                        # could not tell: nothing recorded


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
    assert rs.synced_at == 1_000_000.0           # KI-304: the compile time is never moved for scheduling
    return rs.refresh_due(_Config.sync_interval) - 1_000_000.0


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

    assert kept.refresh_due(_Config.sync_interval) - 1_000_000.0 == refresh_cycle._CATCHING_UP_RETRY_S


def test_forgetting_cached_assets_removes_only_the_old_row_cache(tmp_path, monkeypatch):
    """DKG-lookup B6: the per-asset gzip cache goes; progress.json stays."""
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    root = tmp_path / "verified_partitions"
    root.mkdir()
    for name in ("a.json.gz", "b.json.gz"):
        (root / name).write_bytes(b"x")
    pr.record_progress("cg", pr.PartitionRead(total=2, compiled=2))
    assert pr.forget_cached_assets() == 2
    assert sorted(p.name for p in root.iterdir()) == ["progress.json"]
    assert pr.forget_cached_assets() == 0
