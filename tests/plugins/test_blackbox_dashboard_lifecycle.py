"""Dashboard startup/shutdown hooks without FastAPI's deprecated on_event."""

from __future__ import annotations

import warnings

from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox.dashboard.lifecycle import on_shutdown, on_startup


def test_hooks_run_on_start_and_stop_in_nested_order():
    app, calls = FastAPI(), []
    on_startup(app)(lambda: calls.append("start 1"))
    on_startup(app)(lambda: calls.append("start 2"))
    on_shutdown(app)(lambda: calls.append("stop"))
    with TestClient(app):
        assert calls == ["start 1", "start 2"]
    assert calls[-1] == "stop"


def test_registering_hooks_raises_no_deprecation_warning():
    app = FastAPI()
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        on_startup(app)(lambda: None)
        on_shutdown(app)(lambda: None)


def test_the_dashboard_app_starts_with_no_on_event_deprecation(monkeypatch):
    """The real create_app registers its hooks through lifecycle, not on_event."""
    from plugins.blackbox.dashboard import server
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        server.create_app()
    assert not [w for w in caught if "on_event is deprecated" in str(w.message)]
