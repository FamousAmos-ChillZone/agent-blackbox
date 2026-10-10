"""KI-335 — the dashboard's node-liveness check: debounced, and its outages logged.

On bb-swm-b (2026-10-10) one slow status check while the node sealed a share
made the page show "node offline" and blank the graph numbers, and nothing on
the machine recorded it. These tests hold the fix: one missed check never
flips the page, every change is logged, the steady state logs nothing, and
the no-op peer-id "switch" that buried the log is gone.
"""

from __future__ import annotations

import logging

import pytest

from plugins.blackbox.dashboard import node_probe
from plugins.blackbox.dashboard.node_probe import FAILURES_BEFORE_OFFLINE, NodeLiveness, RepeatGate
from plugins.blackbox.kernel import config as config_module
from plugins.blackbox.kernel import constants

LOGGER = node_probe.__name__
CFG = object()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class ScriptedCheck:
    """Answers from a script of (ok, seconds) pairs, advancing the clock by each check's duration."""

    def __init__(self, clock: Clock, script: list[tuple[bool, float]]) -> None:
        self.clock, self.script = clock, list(script)

    def __call__(self, cfg: object, timeout: float) -> bool:
        ok, seconds = self.script.pop(0)
        self.clock.now += seconds
        return ok


def _liveness(clock: Clock, script: list[tuple[bool, float]]) -> NodeLiveness:
    return NodeLiveness(ScriptedCheck(clock, script), ttl=15.0, timeout=5.0, clock=clock, start=lambda work: work())


def _messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == LOGGER]


def test_one_missed_check_on_an_answering_node_does_not_show_it_offline(caplog):
    clock = Clock()
    liveness = _liveness(clock, [(True, 0.03), (False, 5.0)])
    with caplog.at_level(logging.INFO, logger=LOGGER):
        assert liveness.check_now(CFG) is True
        assert liveness.check_now(CFG) is True
    assert any("1 of 2 misses" in m for m in _messages(caplog))


def test_the_page_shows_offline_only_after_enough_misses_in_a_row(caplog):
    clock = Clock()
    liveness = _liveness(clock, [(True, 0.03)] + [(False, 5.0)] * FAILURES_BEFORE_OFFLINE)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        liveness.check_now(CFG)
        results = [liveness.check_now(CFG) for _ in range(FAILURES_BEFORE_OFFLINE)]
    assert results[-1] is False and all(results[:-1])
    assert any("treated as offline" in m for m in _messages(caplog))


def test_a_miss_before_the_first_answer_reads_as_offline(caplog):
    liveness = _liveness(Clock(), [(False, 5.0)])
    with caplog.at_level(logging.INFO, logger=LOGGER):
        assert liveness.check_now(CFG) is False
    assert any("not answering at dashboard start" in m for m in _messages(caplog))


def test_coming_back_logs_how_long_the_node_was_offline(caplog):
    clock = Clock()
    liveness = _liveness(clock, [(True, 0.03), (False, 5.0), (False, 5.0), (True, 0.03)])
    with caplog.at_level(logging.INFO, logger=LOGGER):
        for _ in range(3):
            liveness.check_now(CFG)
        clock.now += 30
        assert liveness.check_now(CFG) is True
    back = [m for m in _messages(caplog) if "answering again after" in m]
    assert back and "35 s offline" in back[0]


def test_a_recovered_single_miss_is_recorded_as_never_shown(caplog):
    liveness = _liveness(Clock(), [(True, 0.03), (False, 5.0), (True, 0.03)])
    with caplog.at_level(logging.INFO, logger=LOGGER):
        for _ in range(3):
            liveness.check_now(CFG)
    assert any("never showed it offline" in m for m in _messages(caplog))


def test_steady_answering_writes_nothing_after_the_first_line(caplog):
    liveness = _liveness(Clock(), [(True, 0.03)] * 50)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        for _ in range(50):
            liveness.check_now(CFG)
    assert len(_messages(caplog)) == 1


def test_slow_answers_are_logged_once_per_repeat_window(caplog):
    clock = Clock()
    liveness = _liveness(clock, [(True, 3.0)] * 10)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        for _ in range(10):
            liveness.check_now(CFG)
    assert sum("status check slow" in m for m in _messages(caplog)) == 1


def test_a_long_outage_is_re_logged_on_the_repeat_window_not_every_check(caplog):
    clock = Clock()
    liveness = _liveness(clock, [(False, 5.0)] * 200)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        for _ in range(200):          # 200 checks x (5 s + 15 s) = 4000 s of outage
            liveness.check_now(CFG)
            clock.now += 15
    still = sum("still not answering" in m for m in _messages(caplog))
    assert 1 <= still <= 4000 // node_probe.REPEAT_LOG_SECONDS + 1


def test_a_check_that_raises_counts_as_a_miss():
    def broken(cfg: object, timeout: float) -> bool:
        raise RuntimeError("boom")

    liveness = NodeLiveness(broken, clock=Clock(), start=lambda work: work())
    assert liveness.check_now(CFG) is False


def test_reachable_never_runs_the_check_on_the_caller_and_rechecks_only_past_the_ttl():
    clock = Clock()
    started: list = []
    liveness = NodeLiveness(lambda cfg, timeout: True, ttl=15.0, clock=clock, start=started.append)
    assert liveness.reachable(CFG) is False and len(started) == 1   # cold: unknown, one check queued
    started.pop()()                                                 # the background check lands
    assert liveness.reachable(CFG) is True and not started          # fresh: no new check
    clock.now += 16
    assert liveness.reachable(CFG) is True and len(started) == 1


def test_repeat_gate_allows_a_key_once_per_interval():
    clock = Clock()
    gate = RepeatGate(interval=300.0, clock=clock)
    assert gate.due("x") and not gate.due("x") and gate.due("y")
    clock.now += 301
    assert gate.due("x")


def test_the_default_graph_peer_is_not_switched_to_itself(monkeypatch, caplog):
    monkeypatch.delenv("BLACKBOX_GRAPH_PEER_ID", raising=False)
    monkeypatch.setattr(config_module, "_blackbox_entry", lambda: {})
    with caplog.at_level(logging.INFO, logger=config_module.__name__):
        cfg = config_module.load_blackbox_config()
    assert cfg.graph_peer_id == constants.DEFAULT_GRAPH_PEER_ID
    assert not [r for r in caplog.records if "switching stale graph_peer_id" in r.getMessage()]


def test_a_truly_stale_graph_peer_is_still_replaced(monkeypatch):
    stale = sorted(constants.LEGACY_GRAPH_PEER_IDS - {constants.DEFAULT_GRAPH_PEER_ID})[0]
    monkeypatch.delenv("BLACKBOX_GRAPH_PEER_ID", raising=False)
    monkeypatch.setattr(config_module, "_blackbox_entry", lambda: {"graph_peer_id": stale})
    assert config_module.load_blackbox_config().graph_peer_id == constants.DEFAULT_GRAPH_PEER_ID
