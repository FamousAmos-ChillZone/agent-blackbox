"""The dashboard drives the community pulse with no browser open (KI-283).

The pulse (membership keep-alive, new community statements within ~20 s) ran
only when an agent acted or a browser polled /api/health; an idle node never
redialled the graph owner (KI-297) and saw community reports only hourly.
"""

from __future__ import annotations

import threading
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox.dashboard import community_routes
from plugins.blackbox.dashboard.pulse_driver import PulseDriver


def _wait_for(condition, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not condition():
        time.sleep(0.01)
    return condition()


def test_the_driver_beats_on_its_own_until_stopped(monkeypatch):
    monkeypatch.setattr("plugins.blackbox.dashboard.pulse_driver.MIN_INTERVAL_SECONDS", 0.01)
    beats = []
    driver = PulseDriver(beat=lambda: beats.append(1), interval=lambda: 0.01)
    driver.start()
    assert _wait_for(lambda: len(beats) >= 3)
    driver.stop()
    settled = len(beats)
    time.sleep(0.05)
    assert len(beats) == settled, "no beats after stop"


def test_a_failing_beat_does_not_stop_the_loop(monkeypatch):
    monkeypatch.setattr("plugins.blackbox.dashboard.pulse_driver.MIN_INTERVAL_SECONDS", 0.01)
    calls = []
    def beat():
        calls.append(1)
        raise RuntimeError("node unreachable")
    driver = PulseDriver(beat=beat, interval=lambda: 0.01)
    driver.start()
    assert _wait_for(lambda: len(calls) >= 2)
    driver.stop()


def test_interval_zero_means_no_beats():
    beats = []
    driver = PulseDriver(beat=lambda: beats.append(1), interval=lambda: 0)
    driver.start()
    time.sleep(0.05)
    driver.stop()
    assert beats == []


def test_the_dashboard_app_runs_the_pulse_for_its_lifetime(monkeypatch):
    """Wired for real: registering the community routes starts the driver with the
    app and stops it on shutdown — no /api/health request needed."""
    monkeypatch.setattr("plugins.blackbox.dashboard.pulse_driver.MIN_INTERVAL_SECONDS", 0.01)
    beat = threading.Event()
    app = FastAPI()
    community_routes.register_community_routes(
        app, community_read=lambda cfg: None,
        pulse_driver=PulseDriver(beat=beat.set, interval=lambda: 0.01))
    with TestClient(app):
        assert beat.wait(3.0), "the pulse beat with no request made"
