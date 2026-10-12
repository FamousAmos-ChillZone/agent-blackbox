"""The shared browser boundary (kernel/browser_boundary, KI-028 / LES-006).

Exercises ``BrowserBoundary`` on a bare FastAPI app with both token-source
strategies: the dashboard's per-process token and a per-session lookup on a
MagicDNS host set (the curator key console's shape).
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from plugins.blackbox.kernel.browser_boundary import BrowserBoundary  # noqa: E402

LOOPBACK = {"127.0.0.1", "localhost", "[::1]"}
MAGIC_DNS = "curator-a.tail1234.ts.net"
PROCESS_TOKEN = "process-token-value"


def _app(allowed_hosts, token_for) -> fastapi.FastAPI:
    app = fastapi.FastAPI()
    BrowserBoundary(allowed_hosts, token_for).install(app)

    @app.get("/read")
    def read():
        return {"ok": True}

    @app.post("/change")
    def change():
        return {"changed": True}

    return app


@pytest.fixture()
def loopback_client():
    with TestClient(_app(LOOPBACK, lambda _request: PROCESS_TOKEN), base_url="http://127.0.0.1:9700") as client:
        yield client


def test_forged_host_refused():
    app = _app(LOOPBACK, lambda _request: PROCESS_TOKEN)
    with TestClient(app, base_url="http://attacker.example") as client:
        res = client.get("/read")
    assert res.status_code == 403
    assert res.json() == {"error": "forbidden host"}


def test_rebound_host_with_loopback_port_refused():
    app = _app(LOOPBACK, lambda _request: PROCESS_TOKEN)
    with TestClient(app, base_url="http://127.0.0.1.attacker.example:9700") as client:
        assert client.get("/read").status_code == 403


def test_foreign_origin_refused(loopback_client):
    res = loopback_client.post(
        "/change",
        headers={"Origin": "https://attacker.example", "X-Blackbox-Token": PROCESS_TOKEN},
    )
    assert res.status_code == 403
    assert res.json() == {"error": "forbidden origin"}


def test_missing_token_refused(loopback_client):
    res = loopback_client.post("/change")
    assert res.status_code == 403
    assert "token" in res.json()["error"]


def test_wrong_token_refused(loopback_client):
    res = loopback_client.post("/change", headers={"X-Blackbox-Token": "guess"})
    assert res.status_code == 403


def test_reads_need_no_token_and_local_origin_passes(loopback_client):
    res = loopback_client.get("/read", headers={"Origin": "http://localhost:9700"})
    assert res.status_code == 200


def test_process_token_passes(loopback_client):
    res = loopback_client.post("/change", headers={"X-Blackbox-Token": PROCESS_TOKEN})
    assert res.status_code == 200
    assert res.json() == {"changed": True}


def _session_lookup(sessions):
    """A per-session token source: the token bound to the request's cookie."""
    return lambda request: sessions.get(request.cookies.get("session", ""))


def test_magic_dns_host_with_per_session_token_accepted():
    sessions = {"sess-a": "token-a", "sess-b": "token-b"}
    app = _app({MAGIC_DNS}, _session_lookup(sessions))
    with TestClient(app, base_url=f"https://{MAGIC_DNS}") as client:
        client.cookies.set("session", "sess-a")
        res = client.post(
            "/change",
            headers={"Origin": f"https://{MAGIC_DNS}", "X-Blackbox-Token": "token-a"},
        )
    assert res.status_code == 200


def test_per_session_token_is_bound_to_its_session():
    sessions = {"sess-a": "token-a", "sess-b": "token-b"}
    app = _app({MAGIC_DNS}, _session_lookup(sessions))
    with TestClient(app, base_url=f"https://{MAGIC_DNS}") as client:
        client.cookies.set("session", "sess-a")
        assert client.post("/change", headers={"X-Blackbox-Token": "token-b"}).status_code == 403


def test_no_session_fails_closed_even_without_a_presented_token():
    app = _app({MAGIC_DNS}, _session_lookup({}))
    with TestClient(app, base_url=f"https://{MAGIC_DNS}") as client:
        assert client.post("/change").status_code == 403
        assert client.post("/change", headers={"X-Blackbox-Token": ""}).status_code == 403


def test_magic_dns_set_refuses_loopback_host():
    app = _app({MAGIC_DNS}, lambda _request: "token")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/read").status_code == 403


def test_allowlist_entries_match_case_insensitively():
    # A MagicDNS name copied from the Tailscale admin may carry capitals.
    app = _app({"Curator-A.Tail1234.TS.net"}, lambda _request: "token")
    with TestClient(app, base_url=f"https://{MAGIC_DNS}:8443") as client:
        assert client.get("/read").status_code == 200


def test_token_is_compared_in_constant_time(loopback_client, monkeypatch):
    import plugins.blackbox.kernel.browser_boundary as browser_boundary

    calls = []
    real = browser_boundary.secrets.compare_digest

    def spy(presented, expected):
        calls.append((presented, expected))
        return real(presented, expected)

    monkeypatch.setattr(browser_boundary.secrets, "compare_digest", spy)
    assert loopback_client.post("/change", headers={"X-Blackbox-Token": "guess"}).status_code == 403
    assert calls == [("guess", PROCESS_TOKEN)]
