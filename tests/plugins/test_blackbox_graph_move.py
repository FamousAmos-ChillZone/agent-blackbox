"""One graph (2026-10-16): this node's live reports move into the verified graph, once.

Until 2026-10-16 the community had a graph of its own. A report's signature names
the graph it was shared to, so a report this node shared there does not verify in
the verified graph's shared memory as it is. On update, keep-alive signs each of
this node's live reports again for the verified graph — the same statement: type,
payload and day; only the graph changes — and shares it there once, paced so the
readers' per-author daily budget never holds it back. A refused share still queued
for the old graph moves the same way.
"""

from __future__ import annotations

from datetime import datetime, UTC

import pytest

from _community_rows import GRAPH, NETWORK, Reporter
from plugins.blackbox import audit
from plugins.blackbox.community import keep_alive, report_builder, share_retry
from plugins.blackbox.community.keep_alive import LiveReportStore, copy_name, current_epoch, graph_move
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.community.sighting import vocab as sighting_vocab
from plugins.blackbox.community.verification import ReportVerifier
from plugins.blackbox.kernel import constants, rdf_terms, reporter_key, signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgError

OLD = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-community"   # the retired community graph
CFG = BlackboxConfig(report=True, context_graph_id=GRAPH)
NOW = 1_800_000_000.0
DAY = 86_400.0
EPOCH = current_epoch(NOW, CFG.community_keepalive_epoch_days)
TODAY = datetime.fromtimestamp(NOW, UTC).date().isoformat()


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


@pytest.fixture
def me():
    """This node: the reporter key the signer resolves from the Blackbox home."""
    return Reporter("0x" + "a" * 40, reporter_key.ReporterKeyStore().load_or_create())


class _Node:
    """Takes shares (and registers the report sub-graph); can refuse every write."""

    def __init__(self, refuse=False, network=NETWORK):
        self.shared = []
        self.refuse, self.network = refuse, network

    def status(self):
        return {"networkId": self.network}

    def request(self, method, path, body=None, timeout=None):
        return {"created": (body or {}).get("subGraphName")}

    def share_knowledge_asset(self, cg_id, name, quads, **kw):
        if self.refuse:
            raise DkgError("CONTEXT_GRAPH_NOT_FOUND")
        self.shared.append((cg_id, name, list(quads)))
        return {"state": "succeeded"}


def _report(reporter, identifier="ioc:domain:moved.example", *, graph=OLD, environment=NETWORK):
    signer = ReportSigner(private_key=reporter.key, environment=environment, graph=graph)
    return report_builder.build_report_quads(identifier=identifier, category="ioc", severity="high",
                                             reporter_address=reporter.address, ioc_type="domain",
                                             ioc_context="in-tool-output", signer=signer)


def _signed(quads):
    return rdf_terms.literal_text(next(q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED))


def _store(*entries):
    store = LiveReportStore(clock=lambda: NOW)
    for name, quads in entries:
        store.remember(graph=OLD, name=name, identifier="ioc:domain:moved.example", subject=quads[0]["subject"],
                       severity="high", quads=quads, epoch=keep_alive.Epoch(EPOCH))   # already copied there this epoch
    return store


def test_a_live_report_from_the_retired_graph_moves_once_signed_for_the_verified_graph(me):
    old = _report(me)
    store = _store(("report-a", old))
    node = _Node()
    assert keep_alive.publish_due_copies(node, CFG, store, now=NOW) == 1
    (graph, name, moved), = node.shared
    assert (graph, name) == (GRAPH, copy_name("report-a", EPOCH))
    assert ReportVerifier(NETWORK, GRAPH).verify_signed(_signed(old)) is None          # the old signature names the old graph
    report = ReportVerifier(NETWORK, GRAPH).verify_signed(_signed(moved))
    assert report is not None and report.author == me.author
    before, after = signing.from_text(_signed(old)), signing.from_text(_signed(moved))
    assert (after.payload, after.statement_type, after.schema_version) == (before.payload, before.statement_type,
                                                                           before.schema_version)   # its day included
    digest = next(q["object"] for q in moved if q["predicate"] == sighting_vocab.RECORD_DIGEST_PRED)
    assert rdf_terms.literal_text(digest) == "sha256:" + signing.content_id(after)   # the integrity quads follow it
    (entry,) = store.all()
    assert (entry.graph, entry.moved_day, entry.last_epoch, list(entry.quads)) == (GRAPH, TODAY, EPOCH, moved)
    assert [row["outcome"] for row in audit.read_share_ledger()] == [graph_move.OUTCOME_MOVED]
    # Once: the same epoch sends nothing more, and the next epoch's copy goes to the verified graph.
    assert keep_alive.publish_due_copies(node, CFG, store, now=NOW + 60) == 0 and len(node.shared) == 1
    keep_alive.publish_due_copies(node, CFG, store, now=NOW + 10 * DAY)
    assert node.shared[-1][0] == GRAPH and node.shared[-1][2] == moved


def test_the_move_is_paced_per_day_inside_the_readers_budget(monkeypatch, me):
    monkeypatch.setattr(graph_move, "MAX_MOVED_PER_DAY", 2)
    store = _store(*((f"report-{n}", _report(me, f"ioc:domain:moved-{n}.example")) for n in range(3)))
    node = _Node()
    keep_alive.publish_due_copies(node, CFG, store, now=NOW)
    keep_alive.publish_due_copies(node, CFG, store, now=NOW + 3600)                    # the same UTC day: nothing more
    assert len(node.shared) == 2 and [r.graph for r in store.all()].count(OLD) == 1
    keep_alive.publish_due_copies(node, CFG, store, now=NOW + DAY)
    assert len(node.shared) == 3 and {r.graph for r in store.all()} == {GRAPH}


def test_a_report_this_node_did_not_sign_here_is_dropped_never_signed_again(me):
    someone_else = Reporter("0x" + "b" * 40)
    store = _store(("report-theirs", _report(someone_else)),
                   ("report-other-network", _report(me, "ioc:domain:testnet.example", environment="another-network")))
    node = _Node()
    assert keep_alive.publish_due_copies(node, CFG, store, now=NOW) == 0
    assert node.shared == [] and store.all() == []


def test_a_refused_move_ends_the_beat_and_is_tried_again(me):
    store = _store(("report-a", _report(me)))
    assert keep_alive.publish_due_copies(_Node(refuse=True), CFG, store, now=NOW) == 0
    assert [r.graph for r in store.all()] == [OLD]
    node = _Node()
    assert keep_alive.publish_due_copies(node, CFG, store, now=NOW + 60) == 1 and node.shared[0][0] == GRAPH


def test_nothing_moves_while_sharing_is_off(me):
    store = _store(("report-a", _report(me)))
    node = _Node()
    assert keep_alive.publish_due_copies(node, BlackboxConfig(report=False, context_graph_id=GRAPH), store, now=NOW) == 0
    assert node.shared == [] and [r.graph for r in store.all()] == [OLD]


def test_a_refused_share_queued_for_the_retired_graph_is_signed_again_and_sent_to_the_verified_graph(me):
    old = _report(me)
    queue = share_retry.ShareRetryQueue(clock=lambda: NOW + 3600)
    share_retry.queue_failed_share(graph=OLD, name="report-q", identifier="ioc:domain:moved.example", category="ioc",
                                   severity="high", subject=old[0]["subject"], quads=old, error="refused",
                                   queue=queue, now=NOW)
    node = _Node()
    assert share_retry.retry_due_shares(node, CFG, queue) == 1
    (graph, name, sent), = node.shared
    assert (graph, name) == (GRAPH, "report-q") and ReportVerifier(NETWORK, GRAPH).verify_signed(_signed(sent)) is not None
    assert queue.pending() == []
    (kept,) = LiveReportStore().all()
    assert (kept.graph, list(kept.quads)) == (GRAPH, sent)                              # kept alive where it now lives


def test_a_queued_share_this_node_cannot_sign_again_is_dropped(me):
    theirs = _report(Reporter("0x" + "c" * 40))
    queue = share_retry.ShareRetryQueue(clock=lambda: NOW + 3600)
    share_retry.queue_failed_share(graph=OLD, name="report-x", identifier="ioc:domain:moved.example", category="ioc",
                                   severity="high", subject=theirs[0]["subject"], quads=theirs, error="refused",
                                   queue=queue, now=NOW)
    node = _Node()
    assert share_retry.retry_due_shares(node, CFG, queue) == 0
    assert node.shared == [] and queue.pending() == []


def test_signing_again_changes_only_the_graph_and_needs_the_same_key_and_network(me):
    old = _report(me)
    signer = ReportSigner(private_key=me.key, environment=NETWORK, graph=GRAPH)
    moved = report_builder.rebind_quads(old, signer)
    assert [q for q in moved if q["predicate"] not in (constants.SIGNED_STATEMENT_PRED, sighting_vocab.RECORD_DIGEST_PRED)] == \
        [q for q in old if q["predicate"] not in (constants.SIGNED_STATEMENT_PRED, sighting_vocab.RECORD_DIGEST_PRED)]
    assert signing.from_text(_signed(moved)).graph == GRAPH
    assert report_builder.rebind_quads(old, ReportSigner(private_key=Reporter("0x" + "d" * 40).key, environment=NETWORK,
                                                         graph=GRAPH)) is None          # another key: never ours to sign
    assert report_builder.rebind_quads(old, ReportSigner(private_key=me.key, environment="mainnet", graph=GRAPH)) is None
    assert report_builder.rebind_quads([q for q in old if q["predicate"] != constants.SIGNED_STATEMENT_PRED], signer) is None


def test_a_literal_term_reads_back_as_the_text_it_was_written_from():
    for text in ("plain", 'a "quoted" word', "back\\slash", "line\nbreak\ttab\rreturn", '{"k":"\\u00e9"}'):
        assert rdf_terms.literal_text(rdf_terms.literal(text)) == text
    assert rdf_terms.literal_text("urn:x:an-iri") is None
    assert rdf_terms.literal_text(rdf_terms.datetime_literal()) is None
