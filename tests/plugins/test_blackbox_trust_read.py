"""Community Curation C3 — reading from a graph anyone can write.

Bench finding 2026-10-03 (KI-262, KI-263): a DKG node answers a query that
TIMED OUT with an empty result and a normal success status, after 10-20
seconds; while a store ingests a flood, every query shape does this, on every
graph of that node. "The node returned no rows" is therefore not proof that
nothing is there. These tests pin the rules that follow:

* an empty answer that took as long as a timeout is a failed read;
* a page that goes empty that way mid-read fails the whole read;
* the pulse infers no change from it;
* the report tier is not cleared by one empty read: the emptiness must last.
"""

from __future__ import annotations

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row

from plugins.blackbox.community import ReadState, pulse, read_verified_reports
from plugins.blackbox.kernel import sparql_text
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import community_tier, compiler

CFG = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id="0x37b1Fdfd/agent-blackbox-vm")
VIEW = "shared-working-memory"
THREAT = "ioc:ip:203.0.113.7"


class Clock:
    """A monotonic clock the fake node advances while it "works"."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sparql_text.time, "monotonic", clock)
    return clock


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    pulse.PULSE.reset()


class SlowNode:
    """A node whose answers take *seconds* of clock time each. ``answers`` is
    the list of row lists it returns, in order (the last one repeats); an
    entry of ``FAIL`` returns the caller's error sentinel."""

    FAIL = object()

    def __init__(self, clock, answers, seconds=0.0):
        self.clock, self.answers, self.seconds, self.calls = clock, list(answers), seconds, 0

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        self.clock.now += self.seconds
        return on_error if answer is SlowNode.FAIL else list(answer)


# ------------------------------------------------------------------ one query


def test_a_prompt_empty_answer_is_empty_and_a_slow_empty_answer_is_a_failed_read(clock):
    assert sparql_text.query_rows(SlowNode(clock, [[]], seconds=0.2), "q", GRAPH, VIEW) == []
    assert sparql_text.query_rows(SlowNode(clock, [[]], seconds=10.2), "q", GRAPH, VIEW) is None


def test_a_slow_answer_with_rows_is_believed_and_a_failed_query_is_not(clock):
    rows = [{"r": "urn:x:1"}]
    assert sparql_text.query_rows(SlowNode(clock, [rows], seconds=19.0), "q", GRAPH, VIEW) == rows
    assert sparql_text.query_rows(SlowNode(clock, [SlowNode.FAIL]), "q", GRAPH, VIEW) is None


def test_the_threshold_sits_below_the_measured_timeout():
    assert 5.0 < sparql_text.SLOW_EMPTY_SECONDS < 10.0    # the bench saw 10.06-20.21 s; a real empty graph answers in < 1 s


# ------------------------------------------------------------------ paged reads


def test_a_page_that_goes_empty_after_a_timeout_fails_the_whole_read(clock):
    """The bench case: the first page of 5,000 rows arrived, the second came back empty
    after 30 s. A partial list must never pass as the graph's contents."""
    first = [{"r": f"urn:x:{i:05d}"} for i in range(5000)]

    class Node(SlowNode):
        def query(self, sparql, cg_id, view=None, on_error=None, **kw):
            self.seconds = 0.3 if self.calls == 0 else 30.0
            return super().query(sparql, cg_id, view=view, on_error=on_error, **kw)

    assert sparql_text.page_rows(Node(clock, [first, []]), GRAPH, VIEW, lambda after: "q") is None


def test_a_prompt_short_read_still_returns_its_rows(clock):
    rows = [{"r": "urn:x:1"}, {"r": "urn:x:2"}]
    assert sparql_text.page_rows(SlowNode(clock, [rows], seconds=0.1), GRAPH, VIEW, lambda after: "q") == rows


# ------------------------------------------------------------------ the pulse and the report read


def test_the_pulse_infers_no_change_from_a_timed_out_probe(clock):
    assert pulse.fingerprint(SlowNode(clock, [[]], seconds=10.3), CFG) is None      # looks like an empty graph; is not believed
    assert pulse.fingerprint(SlowNode(clock, [[]], seconds=0.1), CFG) == ""         # a prompt empty answer is an empty graph


def test_a_timed_out_report_read_is_unavailable_even_on_a_subscribed_synced_node(clock):
    read = read_verified_reports(SlowNode(clock, [[]], seconds=10.2), CFG)
    assert read.state is ReadState.UNAVAILABLE and not read.available


def test_the_pulse_counts_key_manifests_so_a_new_manifest_is_noticed():
    assert "g:KeyManifest" in pulse._FINGERPRINT_SPARQL and "g:CuratorStatement" in pulse._FINGERPRINT_SPARQL


# ------------------------------------------------------------------ the report tier needs a second witness


class Reports:
    """A prompt node: subscribed, synced, serving *rows* as its reports and nothing else."""

    def __init__(self, rows=()):
        self.rows = list(rows)

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        return list(self.rows) if "g:ThreatReport" in sparql and "COUNT" not in sparql else []


def _generation(node, prior, monkeypatch, now):
    monkeypatch.setattr(community_tier.time, "time", lambda: now)
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, node, CFG, prior)
    return rs


def test_one_empty_read_does_not_clear_the_tier_and_a_lasting_one_does(monkeypatch):
    """KI-262: an unlisted reporter's threat (nothing would carry it) survives empty reads until
    the emptiness has lasted EMPTY_READ_WITNESS_SECONDS, and keeps its first-seen time."""
    start = 1_800_000_000.0
    first = _generation(Reports([signed_row(THREAT, Reporter("0xa"))]), None, monkeypatch, start)
    seen = first.community[THREAT]["firstSeen"]

    empty_once = _generation(Reports(), first, monkeypatch, start + 60)
    assert THREAT in empty_once.community and empty_once.community_empty_since == start + 60
    still = _generation(Reports(), empty_once, monkeypatch, start + 60 + community_tier.EMPTY_READ_WITNESS_SECONDS - 1)
    assert THREAT in still.community and still.community[THREAT]["firstSeen"] == seen

    lasted = _generation(Reports(), still, monkeypatch, start + 60 + community_tier.EMPTY_READ_WITNESS_SECONDS)
    assert lasted.community == {}


def test_a_read_with_reports_ends_the_empty_spell(monkeypatch):
    start = 1_800_000_000.0
    rows = [signed_row(THREAT, Reporter("0xa"))]
    first = _generation(Reports(rows), None, monkeypatch, start)
    empty = _generation(Reports(), first, monkeypatch, start + 60)
    back = _generation(Reports(rows), empty, monkeypatch, start + 120)
    assert back.community_empty_since == 0.0 and THREAT in back.community
    empty_again = _generation(Reports(), back, monkeypatch, start + 4000)
    assert THREAT in empty_again.community                      # the clock restarted: not yet believed


def test_the_empty_spell_survives_the_disk_cache(monkeypatch, tmp_path):
    from plugins.blackbox.ruleset import disk_cache
    rs = compiler.Ruleset()
    rs.community_empty_since = 1_800_000_060.0
    assert disk_cache._deserialize(disk_cache._serialize(rs)).community_empty_since == 1_800_000_060.0
