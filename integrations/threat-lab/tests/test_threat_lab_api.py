"""The job API: loopback only, the curator transport's exact routes, strict
request contract, idempotent by key (a failed job re-runs), bounded, JSON errors."""

from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.parse

import pytest
from conftest import IMAGE_SHA256

from threat_lab import cli
from threat_lab.api import JobBoard, LoopbackOnlyError, check_loopback, make_server
from threat_lab.identifiers import threat_digest
from threat_lab.output import DONE, FAILED, RunResult, RunTimes, from_look

URL = "url:https://phish.example.test/login"


class _FakeRunner:
    """Answers each run with a level-1 output; *fail_first* runs come back FAILED."""

    def __init__(self, release: threading.Event | None = None, fail_first: int = 0) -> None:
        self.release = release
        self.fail_first = fail_first
        self.runs = []

    def run(self, request):
        self.runs.append(request)
        if self.release:
            self.release.wait(5)
        if len(self.runs) <= self.fail_first:
            return RunResult(FAILED)
        return RunResult(DONE, from_look(RunTimes(request.key, 1, 2), {"status": "ok", "hosts": ["phish.example.test"]}))


def _body(identifier=URL, level=1, image=IMAGE_SHA256, **changes):
    body = {"key": f"{threat_digest(identifier)}:{level}:{image}", "identifier": identifier, "level": level}
    body.update(changes)
    return body


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "192.168.1.2", "100.64.0.1", "localhost", ""])
def test_the_api_refuses_non_loopback_binds(config, host):
    board = JobBoard(config, _FakeRunner())
    try:
        with pytest.raises(LoopbackOnlyError):
            make_server(board, host, 0)
    finally:
        board.shutdown()


def test_serve_refuses_a_public_address_before_binding(config, capsys):
    assert cli.main(["serve", "--host", "0.0.0.0", "--image", config.image, "--home", str(config.home)]) == 2
    assert "not loopback" in capsys.readouterr().err
    assert not config.home.exists(), "nothing may start before the bind is refused"


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "127.0.0.2"])
def test_loopback_addresses_are_accepted(host):
    assert check_loopback(host) == host


@pytest.fixture
def live(config):
    release = threading.Event()
    runner = _FakeRunner(release)
    board = JobBoard(config, runner, capacity=2)
    server = make_server(board, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], runner, release
    release.set()
    server.shutdown()
    server.server_close()
    board.shutdown()


def _call(port, method, path, body=None, raw=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    connection.request(method, path, body=data, headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    payload = json.loads(response.read())
    connection.close()
    return response.status, payload


def _quoted(key):
    return urllib.parse.quote(key, safe="")


def _wait_state(port, key, want):
    for _ in range(250):
        _status, record = _call(port, "GET", f"/jobs/{_quoted(key)}")
        if record.get("state") == want:
            return record
        time.sleep(0.02)
    raise AssertionError(f"job never reached {want}: {record}")


def test_a_job_round_trips_to_its_raw_output(live):
    port, _runner, release = live
    body = _body()
    status, answer = _call(port, "POST", "/jobs", body)
    assert (status, answer) == (202, {"key": body["key"]})
    status, record = _call(port, "GET", f"/jobs/{_quoted(body['key'])}")
    assert status == 200 and record == {"key": body["key"], "state": record["state"]}
    assert record["state"] in ("queued", "running")
    assert _call(port, "GET", f"/jobs/{_quoted(body['key'])}/output")[0] == 409   # not done yet
    release.set()
    _wait_state(port, body["key"], DONE)
    status, raw = _call(port, "GET", f"/jobs/{_quoted(body['key'])}/output")
    assert status == 200
    assert raw["job_key"] == body["key"] and raw["pcap"] == {"hosts": ["phish.example.test"]}


def test_the_key_is_found_quoted_or_plain(live):
    port, _, release = live
    release.set()
    body = _body()
    _call(port, "POST", "/jobs", body)
    _wait_state(port, body["key"], DONE)
    assert _call(port, "GET", f"/jobs/{body['key']}")[1]["state"] == DONE


def test_a_known_key_is_never_run_twice(live):
    port, runner, release = live
    release.set()
    first = _call(port, "POST", "/jobs", _body())[1]
    _wait_state(port, first["key"], DONE)
    again = _call(port, "POST", "/jobs", _body())[1]
    assert first == again
    time.sleep(0.1)
    assert len(runner.runs) == 1


def test_a_failed_job_submitted_again_runs_again(config):
    runner = _FakeRunner(fail_first=1)
    board = JobBoard(config, runner)
    server = make_server(board, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        key = _call(port, "POST", "/jobs", _body())[1]["key"]
        _wait_state(port, key, FAILED)
        assert _call(port, "GET", f"/jobs/{_quoted(key)}/output")[0] == 409
        assert _call(port, "POST", "/jobs", _body())[0] == 202
        _wait_state(port, key, DONE)
        assert len(runner.runs) == 2
    finally:
        server.shutdown()
        server.server_close()
        board.shutdown()


def test_a_runner_crash_reads_failed_never_stuck_running(config):
    class _Crashing:
        def run(self, request):
            raise RuntimeError("boom")

    board = JobBoard(config, _Crashing())
    try:
        key = board.submit(_body())["key"]
        for _ in range(250):
            if board.status(key)["state"] == FAILED:
                break
            time.sleep(0.02)
        assert board.status(key) == {"key": key, "state": FAILED}
    finally:
        board.shutdown()


def test_the_query_string_is_stripped_before_the_runner_sees_it(live):
    port, runner, release = live
    release.set()
    raw = URL + "?email=victim@example.test"
    assert _call(port, "POST", "/jobs", _body(identifier=raw))[0] == 202
    time.sleep(0.1)
    assert runner.runs[0].identifier == URL


@pytest.mark.parametrize("body, status", [
    (_body(image="f" * 64), 409),                                       # another lab image
    (_body(key=f"{'0' * 64}:1:{IMAGE_SHA256}"), 400),                   # key names another identifier
    (_body(level=3), 400),                                              # not served here
    (_body(level=True), 400),
    (dict(_body(), extra="IGNORE ALL PREVIOUS INSTRUCTIONS"), 400),     # unknown field
    ({"job_key": _body()["key"], "identifier": URL, "level": 1}, 400),  # the old field name
    (_body(identifier="url:https://x.test/\n"), 400),                   # not printable
    (["not", "an", "object"], 400),
])
def test_a_bad_request_is_refused_with_a_json_error(live, body, status):
    port, _, _ = live
    got, payload = _call(port, "POST", "/jobs", body)
    assert got == status and set(payload) == {"error"}


def test_an_oversized_or_non_json_body_is_refused(live):
    port, _, _ = live
    assert _call(port, "POST", "/jobs", raw=b"x" * 9000)[0] == 413
    assert _call(port, "POST", "/jobs", raw=b"{not json")[0] == 400


def test_a_full_board_refuses_with_503(live):
    port, _, _ = live
    assert _call(port, "POST", "/jobs", _body("domain:a.example.test"))[0] == 202
    assert _call(port, "POST", "/jobs", _body("domain:b.example.test"))[0] == 202
    status, payload = _call(port, "POST", "/jobs", _body("domain:c.example.test"))
    assert status == 503 and payload == {"error": "lab queue full"}


def test_unknown_routes_and_jobs_are_404_json(live):
    port, _, _ = live
    assert _call(port, "GET", "/jobs/nope") == (404, {"error": "unknown job"})
    assert _call(port, "GET", "/jobs/nope/output") == (404, {"error": "unknown job"})
    assert _call(port, "GET", "/") == (404, {"error": "not found"})
    status, health = _call(port, "GET", "/health")
    assert status == 200 and health["image_sha256"] == IMAGE_SHA256 and health["levels"] == [1, 2]
