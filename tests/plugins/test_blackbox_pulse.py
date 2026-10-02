"""Refine R16 — the community pulse re-applies the community tier between refreshes (KI-202)."""

from __future__ import annotations

import threading
import time

import pytest

from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from plugins.blackbox import community, ruleset
from plugins.blackbox.community import pulse as pulse_module
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import community_tier, compiler, refresh_cycle
from plugins.blackbox.ruleset import pulse_beat

VM_GRAPH = "0x37b1Fdfd/agent-blackbox-vm"
THREAT = "ioc:domain:fresh.example"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    community.PULSE.reset()
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    yield
    community.PULSE.reset()


class _Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class _Graph:
    """A community graph whose report rows can grow between probes."""

    def __init__(self, reports=()):
        self.reports = list(reports)
        self.probes = 0

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "COUNT(DISTINCT ?r) AS ?n) (MAX" in sparql:
            self.probes += 1
            last = max((r["r"] for r in self.reports), default="")
            return [{"n": str(len(self.reports)), "last": last}]
        if "g:ThreatReport" in sparql and "?identifier" in sparql:
            served, self.reports = list(self.reports), self.reports    # the pager stops on a short page
            return served if not kw.get("_served") else []
        return []


# ------------------------------------------------------------------ the probe


def test_the_fingerprint_is_count_and_newest_subject_and_fails_open():
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    fp = pulse_module.fingerprint(graph, BlackboxConfig(community_graph_id=GRAPH))
    assert fp.startswith("1:urn:guardian:report:")
    assert pulse_module.fingerprint(graph, BlackboxConfig(community_graph_id="")) is None

    class _Down(_Graph):
        def query(self, *a, **kw):
            return kw.get("on_error")
    assert pulse_module.fingerprint(_Down(), BlackboxConfig(community_graph_id=GRAPH)) is None


def test_the_first_probe_is_a_baseline_and_only_a_different_graph_counts_as_changed():
    clock = _Clock()
    pulse = pulse_module.CommunityPulse(clock=clock)
    cfg = BlackboxConfig(community_graph_id=GRAPH)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    assert pulse.due(20) and not pulse.due(20)               # one slot per interval
    assert pulse.changed(graph, cfg) is False                 # baseline
    assert pulse.changed(graph, cfg) is False                 # same graph
    graph.reports.append(signed_row("ioc:domain:second.example", Reporter("0xb")))
    assert pulse.changed(graph, cfg) is True                  # a new report arrived
    assert pulse.changed(graph, cfg) is False                 # and is now the baseline
    clock.now += 20
    assert pulse.due(20) and not pulse.due(0)                 # 0 = off


def test_a_failed_probe_never_reports_a_change():
    pulse = pulse_module.CommunityPulse(clock=_Clock())
    cfg = BlackboxConfig(community_graph_id=GRAPH)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    assert pulse.changed(graph, cfg) is False

    class _Flaky(_Graph):
        def query(self, *a, **kw):
            return kw.get("on_error")
    assert pulse.changed(_Flaky(), cfg) is False
    graph.reports.append(signed_row("ioc:domain:second.example", Reporter("0xb")))
    assert pulse.changed(graph, cfg) is True                  # the baseline survived the failed probe


# ------------------------------------------------------------------ in the ruleset


def test_a_changed_graph_re_applies_the_community_tier_and_writes_it_through(monkeypatch):
    """The whole beat: probe → changed → reapply onto the cached generation → disk + memory."""
    cfg = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id=VM_GRAPH, community_poll_interval=20)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: graph)
    rs = compiler.Ruleset(context_graph_id=VM_GRAPH)
    rs.synced_at = time.time()
    refresh_cycle._memory.store(rs)
    community.PULSE.changed(graph, cfg)                       # baseline, as a full refresh would leave it
    graph.reports.append(signed_row("ioc:domain:second.example", Reporter("0xb")))
    assert pulse_beat.pulse(cfg) is True
    for _ in range(100):                                      # the beat runs in a background thread
        if THREAT in refresh_cycle.peek(cfg).community:
            break
        time.sleep(0.05)
    applied = refresh_cycle.peek(cfg).community
    assert THREAT in applied and "ioc:domain:second.example" in applied
    assert pulse_beat.pulse(cfg) is False                  # the interval has not passed


def test_a_process_that_starts_with_an_empty_tier_applies_the_reports_already_there(monkeypatch):
    """Bench finding 2026-10-02: B's dashboard baselined on A's report and never applied it — the
    first full refresh was an hour away. The first probe now applies when the cached tier is empty."""
    cfg = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id=VM_GRAPH, community_poll_interval=20)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])          # the report is ALREADY there
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: graph)
    rs = compiler.Ruleset(context_graph_id=VM_GRAPH)
    rs.synced_at = time.time()
    refresh_cycle._memory.store(rs)                                   # no community tier yet
    assert pulse_beat.pulse(cfg) is True                              # first beat = baseline probe
    for _ in range(100):
        if THREAT in refresh_cycle.peek(cfg).community:
            break
        time.sleep(0.05)
    assert THREAT in refresh_cycle.peek(cfg).community
    # and a tier that already holds something is NOT re-applied on a mere baseline
    community.PULSE.reset()
    graph2 = _Graph([signed_row("ioc:domain:other.example", Reporter("0xb"))])
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: graph2)
    community.PULSE._last_probe = 0.0
    assert pulse_beat.pulse(cfg) is True
    time.sleep(0.5)
    assert "ioc:domain:other.example" not in refresh_cycle.peek(cfg).community   # waits for a change or the refresh


def test_a_wedged_beat_does_not_stall_the_pulse_forever(monkeypatch):
    """A node call that never returns must not disable the pulse for the life of the process."""
    cfg = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id=VM_GRAPH, community_poll_interval=20)
    monkeypatch.setattr(pulse_beat, "_pulsing", True)
    monkeypatch.setattr(pulse_beat, "_pulsing_since", time.time())
    assert pulse_beat.pulse(cfg) is False                           # a live beat is respected
    community.PULSE._last_probe = 0.0
    monkeypatch.setattr(pulse_beat, "_pulsing_since", time.time() - pulse_beat.STUCK_BEAT_SECONDS - 1)
    started = threading.Event()
    monkeypatch.setattr(pulse_beat, "_background_pulse", lambda config: started.set())
    assert pulse_beat.pulse(cfg) is True                            # a wedged one is replaced
    assert started.wait(2)


def test_the_pulse_is_off_without_a_graph_or_with_interval_zero(monkeypatch):
    called = []
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: called.append(1))
    assert pulse_beat.pulse(BlackboxConfig(community_graph_id="", community_poll_interval=20)) is False
    assert pulse_beat.pulse(BlackboxConfig(community_graph_id=GRAPH, community_poll_interval=0)) is False
    assert called == []


def test_the_pulse_retries_refused_shares_on_its_beat(monkeypatch, tmp_path):
    from plugins.blackbox.community import share_retry
    cfg = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id=VM_GRAPH, community_poll_interval=20)
    drained = threading.Event()
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: _Graph())
    monkeypatch.setattr(community, "retry_due_shares", lambda client, cfg, queue=None: drained.set() or 0)
    assert pulse_beat.pulse(cfg) is True
    assert drained.wait(5)


def test_get_runs_the_pulse_instead_of_a_refresh_when_the_cache_is_fresh(monkeypatch):
    cfg = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id=VM_GRAPH, community_poll_interval=20, sync_interval=3600)
    rs = compiler.Ruleset(context_graph_id=VM_GRAPH)
    rs.synced_at = time.time()
    refresh_cycle._memory.store(rs)
    pulses = []
    monkeypatch.setattr(pulse_beat, "pulse", lambda config=None: pulses.append(config) or False)
    assert ruleset.get(cfg) is rs
    assert pulses == [cfg]
