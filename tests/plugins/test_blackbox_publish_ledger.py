"""PublishLedger (trust-and-threat-lab P1, §03.4 / F-035): the per-batch state machine.

Every legal move works, every illegal one raises, a 207 is reconciled and never
re-submitted, the file replays to the same state, and the console metrics come
from the ledger alone.
"""

from __future__ import annotations

import calendar
import itertools
import os
import stat
from decimal import Decimal

import pytest

from plugins.blackbox.curate.publishing.errors import PublishLedgerError
from plugins.blackbox.curate.publishing.ledger import (
    _TRANSITIONS,
    MAX_BATCH_ENTRIES,
    BatchEntry,
    PublishLedger,
    PublishState,
)

S = PublishState
UAL = "did:dkg:otp:2043/0xabc/1"
ENTRIES = (BatchEntry("npm:evil@1.0.0", "dependency"), BatchEntry("evil.example", "ioc"))
#: The shortest route from QUEUED to each state.
ROUTE = {
    S.QUEUED: (),
    S.SEALED: (S.SEALED,),
    S.SUBMITTED: (S.SEALED, S.SUBMITTED),
    S.MINTED: (S.SEALED, S.SUBMITTED, S.MINTED),
    S.BOUND: (S.SEALED, S.SUBMITTED, S.BOUND),
    S.SEEN: (S.SEALED, S.SUBMITTED, S.BOUND, S.SEEN),
    S.WRITTEN_OFF: (S.SEALED, S.SUBMITTED, S.MINTED, S.WRITTEN_OFF),
}


class Clock:
    def __init__(self, start: float = 1_790_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def _move_fields(previous: PublishState, target: PublishState) -> dict:
    """What a correct caller passes for this move (cost only where money is spent)."""
    if previous is S.SUBMITTED and target in (S.MINTED, S.BOUND):
        return {"ual": UAL, "cost_trac": "0.5", "cost_bytes": 1000, "note": "why"}
    return {"note": "why"}


def _walk(ledger: PublishLedger, batch_id: str, target: PublishState) -> None:
    ledger.queue(batch_id, ENTRIES)
    previous = S.QUEUED
    for state in ROUTE[target]:
        ledger.advance(batch_id, state, **_move_fields(previous, state))
        previous = state


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def ledger(tmp_path, clock) -> PublishLedger:
    return PublishLedger(tmp_path / "publish_ledger.jsonl", clock=clock)


LEGAL = [(source, target) for source, targets in _TRANSITIONS.items() for target in sorted(targets, key=lambda s: s.value)]
ILLEGAL = [pair for pair in itertools.product(S, S) if pair[1] not in _TRANSITIONS[pair[0]]]


def test_the_table_covers_every_state_and_ends_in_two_terminals():
    assert set(_TRANSITIONS) == set(S)
    assert {state for state, targets in _TRANSITIONS.items() if not targets} == {S.SEEN, S.WRITTEN_OFF}
    assert len(LEGAL) == 8


@pytest.mark.parametrize("source,target", LEGAL, ids=lambda s: s.name)
def test_every_legal_transition_is_recorded(ledger, source, target):
    _walk(ledger, "b-1", source)
    record = ledger.advance("b-1", target, **_move_fields(source, target))
    assert record.state is target
    assert ledger.get("b-1") == record
    assert record.entries == ENTRIES


@pytest.mark.parametrize("source,target", ILLEGAL, ids=lambda s: s.name)
def test_every_illegal_transition_raises_and_writes_nothing(ledger, source, target):
    _walk(ledger, "b-1", source)
    before = ledger.transitions()
    with pytest.raises(PublishLedgerError, match="not allowed"):
        ledger.advance("b-1", target, ual=UAL, note="why")
    assert ledger.transitions() == before


def test_a_batch_must_be_queued_before_it_moves(ledger):
    with pytest.raises(PublishLedgerError, match="QUEUED first"):
        ledger.advance("never-queued", S.SEALED)


# --- a 207 is reconciled, never re-minted -----------------------------------------------------

def test_a_207_can_never_be_submitted_again(ledger):
    _walk(ledger, "b-1", S.MINTED)
    with pytest.raises(PublishLedgerError, match="not allowed"):
        ledger.advance("b-1", S.SUBMITTED)
    with pytest.raises(PublishLedgerError, match="not allowed"):
        ledger.advance("b-1", S.SEALED, note="retry")
    submits = [step for step in ledger.transitions() if step.record.state is S.SUBMITTED]
    assert len(submits) == 1


def test_a_207_reconciles_to_its_existing_ual_with_the_cost_kept(ledger):
    _walk(ledger, "b-1", S.MINTED)
    record = ledger.reconcile_minted("b-1", readable_ual=UAL)
    assert (record.state, record.ual, record.cost_trac, record.cost_bytes) == (S.BOUND, UAL, Decimal("0.5"), 1000)


def test_a_207_cannot_be_bound_to_a_different_ual(ledger):
    _walk(ledger, "b-1", S.MINTED)
    with pytest.raises(PublishLedgerError, match="keeps its UAL"):
        ledger.reconcile_minted("b-1", readable_ual="did:dkg:otp:2043/0xabc/999")


def test_a_207_that_cannot_be_bound_is_written_off_with_its_cost_and_reason(ledger):
    _walk(ledger, "b-1", S.MINTED)
    with pytest.raises(PublishLedgerError, match="must say why"):
        ledger.reconcile_minted("b-1", readable_ual=None)
    record = ledger.reconcile_minted("b-1", readable_ual=None, note="asset never readable after 3 checks")
    assert (record.state, record.cost_trac, record.note) == (
        S.WRITTEN_OFF, Decimal("0.5"), "asset never readable after 3 checks")
    with pytest.raises(PublishLedgerError, match="not allowed"):
        ledger.advance("b-1", S.SUBMITTED)


def test_only_a_minted_batch_is_reconciled(ledger):
    _walk(ledger, "b-1", S.SUBMITTED)
    with pytest.raises(PublishLedgerError, match="only a 207"):
        ledger.reconcile_minted("b-1", readable_ual=UAL)


# --- field rules on the moves --------------------------------------------------------------------

def test_the_spending_moves_must_log_their_cost(ledger):
    _walk(ledger, "b-1", S.SUBMITTED)
    with pytest.raises(PublishLedgerError, match="log cost_trac"):
        ledger.advance("b-1", S.MINTED, ual=UAL)
    with pytest.raises(PublishLedgerError, match="not a float"):
        ledger.advance("b-1", S.MINTED, ual=UAL, cost_trac=0.5, cost_bytes=10)
    with pytest.raises(PublishLedgerError, match="≥ 0"):
        ledger.advance("b-1", S.MINTED, ual=UAL, cost_trac="-1", cost_bytes=10)


def test_the_cost_is_logged_once_and_never_rewritten(ledger):
    _walk(ledger, "b-1", S.BOUND)
    with pytest.raises(PublishLedgerError, match="logged once"):
        ledger.advance("b-1", S.SEEN, cost_trac="9")


def test_bound_needs_a_ual(ledger):
    _walk(ledger, "b-1", S.SUBMITTED)
    with pytest.raises(PublishLedgerError, match="needs the UAL"):
        ledger.advance("b-1", S.BOUND, cost_trac="1", cost_bytes=10)


def test_a_failed_submit_goes_back_to_sealed_only_with_a_reason(ledger):
    _walk(ledger, "b-1", S.SUBMITTED)
    with pytest.raises(PublishLedgerError, match="must say why"):
        ledger.advance("b-1", S.SEALED)
    assert ledger.advance("b-1", S.SEALED, note="HTTP 400 invalid quads").state is S.SEALED
    assert ledger.advance("b-1", S.SUBMITTED).state is S.SUBMITTED


@pytest.mark.parametrize("batch_id", ["", "-starts-with-dash", "has space", "x" * 129, None])
def test_a_bad_batch_id_is_refused(ledger, batch_id):
    with pytest.raises(PublishLedgerError, match="not a batch id"):
        ledger.queue(batch_id, ENTRIES)


def test_queue_refuses_a_repeat_id_an_empty_or_oversized_batch_and_duplicate_identifiers(ledger):
    ledger.queue("b-1", ENTRIES)
    with pytest.raises(PublishLedgerError, match="already in the ledger"):
        ledger.queue("b-1", ENTRIES)
    with pytest.raises(PublishLedgerError, match="entries"):
        ledger.queue("b-2", ())
    too_many = [BatchEntry(f"npm:pkg-{n}@1.0.0", "dependency") for n in range(MAX_BATCH_ENTRIES + 1)]
    with pytest.raises(PublishLedgerError, match="entries"):
        ledger.queue("b-3", too_many)
    with pytest.raises(PublishLedgerError, match="each identifier once"):
        ledger.queue("b-4", [ENTRIES[0], ENTRIES[0]])
    with pytest.raises(PublishLedgerError, match="identifier"):
        BatchEntry("", "ioc")


# --- the file -------------------------------------------------------------------------------------

def test_reload_from_disk_restores_every_batch(tmp_path, clock):
    path = tmp_path / "publish_ledger.jsonl"
    first = PublishLedger(path, clock=clock)
    for target in S:
        _walk(first, f"b-{target.value}", target)
    reloaded = PublishLedger(path, clock=clock)
    assert reloaded.batches() == first.batches()
    assert [record.state for record in reloaded.batches()] == list(S)
    minted = reloaded.get("b-minted")
    assert (minted.ual, minted.cost_trac, minted.cost_bytes, minted.entries) == (UAL, Decimal("0.5"), 1000, ENTRIES)
    with pytest.raises(PublishLedgerError, match="not allowed"):
        reloaded.advance("b-minted", S.SUBMITTED)


def test_the_file_is_append_only_and_private(ledger, tmp_path):
    path = tmp_path / "publish_ledger.jsonl"
    ledger.queue("b-1", ENTRIES)
    first_line = path.read_text(encoding="utf-8")
    ledger.advance("b-1", S.SEALED)
    assert path.read_text(encoding="utf-8").startswith(first_line)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_hand_written_illegal_line_stops_the_load(ledger, tmp_path):
    path = tmp_path / "publish_ledger.jsonl"
    _walk(ledger, "b-1", S.MINTED)
    with path.open("a", encoding="utf-8") as handle:  # a forged second submit
        handle.write('{"batch_id": "b-1", "state": "submitted", "at": 1, "note": ""}\n')
    with pytest.raises(PublishLedgerError, match=r"publish_ledger.jsonl:5: .*not allowed"):
        PublishLedger(path).batches()


def test_a_torn_line_stops_the_load_instead_of_being_skipped(ledger, tmp_path):
    path = tmp_path / "publish_ledger.jsonl"
    _walk(ledger, "b-1", S.SUBMITTED)
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"batch_id": "b-1", "state": "min')
    with pytest.raises(PublishLedgerError, match="unreadable"):
        ledger.get("b-1")
    with pytest.raises(PublishLedgerError):
        ledger.advance("b-1", S.SEALED, note="retry")


def test_the_default_path_is_the_curate_home(monkeypatch, tmp_path):
    from plugins.blackbox.curate import keys
    monkeypatch.setattr(keys, "curate_home", lambda: tmp_path / "curate")
    PublishLedger().queue("b-1", ENTRIES)
    assert (tmp_path / "curate" / "publish_ledger.jsonl").is_file()


# --- metrics (F-035) ---------------------------------------------------------------------------------

def test_metrics_on_an_empty_ledger(ledger):
    metrics = ledger.metrics()
    assert (metrics.seconds_since_last_success, metrics.failures, metrics.minted_207s, dict(metrics.monthly)) == (
        None, 0, 0, {})


def test_metrics_time_since_the_last_bound_or_seen_batch(ledger, clock):
    _walk(ledger, "b-1", S.SUBMITTED)
    assert ledger.metrics().seconds_since_last_success is None  # submitted is not success
    ledger.advance("b-1", S.BOUND, ual=UAL, cost_trac="1", cost_bytes=10)
    clock.now += 600
    assert ledger.metrics().seconds_since_last_success == 600
    ledger.advance("b-1", S.SEEN)
    clock.now += 60
    assert ledger.metrics().seconds_since_last_success == 60
    assert ledger.metrics(now=clock.now + 40).seconds_since_last_success == 100


def test_metrics_count_failed_submits_and_207s(ledger):
    _walk(ledger, "b-1", S.SUBMITTED)
    ledger.advance("b-1", S.SEALED, note="HTTP 502")
    ledger.advance("b-1", S.SUBMITTED)
    ledger.advance("b-1", S.SEALED, note="HTTP 400")
    _walk(ledger, "b-2", S.WRITTEN_OFF)
    _walk(ledger, "b-3", S.MINTED)
    ledger.reconcile_minted("b-3", readable_ual=UAL)
    _walk(ledger, "b-4", S.SEEN)
    metrics = ledger.metrics()
    assert (metrics.failures, metrics.minted_207s) == (2, 2)


def test_metrics_monthly_trac_and_bytes_count_each_spend_once_in_its_month(ledger, clock):
    clock.now = calendar.timegm((2026, 10, 31, 23, 0, 0))
    _walk(ledger, "b-1", S.SUBMITTED)
    ledger.advance("b-1", S.MINTED, ual=UAL, cost_trac="0.25", cost_bytes=300)
    clock.now = calendar.timegm((2026, 11, 1, 1, 0, 0))
    ledger.reconcile_minted("b-1", readable_ual=UAL)       # carries the cost; no second spend
    ledger.advance("b-1", S.SEEN)
    _walk(ledger, "b-2", S.SUBMITTED)
    ledger.advance("b-2", S.BOUND, ual="did:dkg:otp:2043/0xabc/2", cost_trac="1.10", cost_bytes=2000)
    _walk(ledger, "b-3", S.SUBMITTED)
    ledger.advance("b-3", S.MINTED, cost_trac="0.40", cost_bytes=700)  # a 207 with no UAL in the reply
    ledger.reconcile_minted("b-3", readable_ual=None, note="no UAL to bind")
    monthly = ledger.metrics().monthly
    assert set(monthly) == {"2026-10", "2026-11"}
    assert (monthly["2026-10"].trac, monthly["2026-10"].bytes) == (Decimal("0.25"), 300)
    assert (monthly["2026-11"].trac, monthly["2026-11"].bytes) == (Decimal("1.50"), 2700)


# --- two writers on one file (P1 review: an unlocked race paid twice and bricked the ledger) -----------

def _submit_from_a_fresh_ledger(path: str, barrier, results) -> None:
    ledger = PublishLedger(__import__("pathlib").Path(path))
    barrier.wait()
    try:
        ledger.advance("b-1", S.SUBMITTED)
        results.put("submitted")
    except PublishLedgerError:
        results.put("refused")


def test_two_ledgers_on_one_file_submit_a_batch_once(tmp_path):
    import queue
    import threading

    for attempt in range(50):
        path = tmp_path / f"race-{attempt}.jsonl"
        PublishLedger(path).queue("b-1", ENTRIES)
        PublishLedger(path).advance("b-1", S.SEALED)
        barrier, results = threading.Barrier(2), queue.Queue()
        threads = [threading.Thread(target=_submit_from_a_fresh_ledger, args=(str(path), barrier, results))
                   for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted([results.get(), results.get()]) == ["refused", "submitted"]
        assert PublishLedger(path).get("b-1").state is S.SUBMITTED  # the file still replays


@pytest.mark.skipif(os.name != "posix", reason="the cross-process lock is flock (curator nodes are POSIX)")
def test_two_processes_on_one_file_submit_a_batch_once(tmp_path):
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    for attempt in range(5):
        path = tmp_path / f"race-{attempt}.jsonl"
        PublishLedger(path).queue("b-1", ENTRIES)
        PublishLedger(path).advance("b-1", S.SEALED)
        barrier, results = context.Barrier(2), context.Queue()
        workers = [context.Process(target=_submit_from_a_fresh_ledger, args=(str(path), barrier, results))
                   for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
        assert sorted([results.get(timeout=5), results.get(timeout=5)]) == ["refused", "submitted"]
        assert PublishLedger(path).get("b-1").state is S.SUBMITTED
