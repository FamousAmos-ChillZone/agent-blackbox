"""A lookup that could not tell is recorded and surfaced, never silent (DKG-lookup B5)."""

from __future__ import annotations

import json

from plugins.blackbox.kernel import health as kernel_health
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.store import StoreAnswer, StoreClient
from plugins.blackbox.ruleset import compiler, live
from plugins.blackbox.ruleset.live import health as live_health


def test_the_first_failure_opens_a_degraded_state_and_writes_it(tmp_path):
    recorder = live.LookupHealth(tmp_path / "state.json")
    recorder.record(False, "timeout", now=1000.0)
    state = recorder.read()
    assert state.degraded and state.reason == "timeout" and state.since == 1000.0 and state.failures == 1
    assert json.loads((tmp_path / "state.json").read_text())["state"] == "degraded"


def test_repeat_failures_count_without_rewriting_the_file_every_time(tmp_path):
    recorder = live.LookupHealth(tmp_path / "state.json")
    recorder.record(False, "timeout", now=1000.0)
    first = (tmp_path / "state.json").stat().st_mtime_ns
    for i in range(5):
        recorder.record(False, "timeout", now=1001.0 + i)
    assert recorder.read().failures == 6
    assert (tmp_path / "state.json").stat().st_mtime_ns == first          # inside the write interval
    recorder.record(False, "timeout", now=1000.0 + live_health.WRITE_INTERVAL_SECONDS + 1)
    assert json.loads((tmp_path / "state.json").read_text())["failures"] == 7


def test_a_known_answer_closes_the_degraded_state(tmp_path):
    recorder = live.LookupHealth(tmp_path / "state.json")
    recorder.record(False, "http 500", now=1000.0)
    recorder.record(True, now=1010.0)
    assert recorder.read().state == live_health.OK and recorder.read().problem() == ""
    assert json.loads((tmp_path / "state.json").read_text())["state"] == "ok"


def test_another_process_reads_the_state_from_the_file(tmp_path):
    live.LookupHealth(tmp_path / "state.json").record(False, "timeout", now=1000.0)
    other = live.LookupHealth(tmp_path / "state.json")
    assert other.read().degraded and "timeout" in other.read().problem()
    assert live.LookupHealth(tmp_path / "missing.json").read().state == live_health.UNKNOWN


class _FailingStore(StoreClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:7878/query")

    def select(self, sparql, *, timeout=None):
        return StoreAnswer(None, "timeout")


def test_the_lookup_records_every_outcome_itself(tmp_path):
    recorder = live.LookupHealth(tmp_path / "state.json")
    scope = live.VerifiedScope(store_url="http://127.0.0.1:7878/query", assertion_graphs=frozenset({"g"}))
    answer = live.VerifiedLookup(scope, _FailingStore(), health=recorder).iocs(["ioc:domain:x.example"])
    assert answer.outcome == live.COULD_NOT_TELL and recorder.read().degraded
    not_ready = live.VerifiedLookup(live.VerifiedScope(), _FailingStore(), health=recorder)
    assert not_ready.iocs(["ioc:domain:x.example"]).reason == "verified scope not ready"
    assert recorder.read().failures == 2


def test_the_health_alarm_names_the_problem_as_an_action():
    inputs = kernel_health.gather(BlackboxConfig(), compiler.Ruleset(synced_at=1.0), True, None, {}, 2.0,
                                  verified_lookup_problem="timeout (3 lookup(s) over 2 min)")
    items = kernel_health.operator_health(inputs)
    alarm = [item for item in items if item.message.startswith("DEGRADED: verified rules cannot be looked up")]
    assert len(alarm) == 1 and alarm[0].klass is kernel_health.HealthClass.ACTION
    assert "timeout (3 lookup(s) over 2 min)" in alarm[0].message and kernel_health.red(alarm[0])
    assert not any(item.message.startswith("DEGRADED") for item in kernel_health.operator_health(
        kernel_health.gather(BlackboxConfig(), compiler.Ruleset(synced_at=1.0), True, None, {}, 2.0)))
