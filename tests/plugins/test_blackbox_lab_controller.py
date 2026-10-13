"""Lab transport and LabController (trust-and-threat-lab L2, proposal §03.5).

The transport is tested against real loopback sockets (a hung lab really
hangs); the controller against a scripted transport, a real job store and the
real signing choke point.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.curate.context import LAB_EVIDENCE_STATEMENT
from plugins.blackbox.curate.lab import controller as lab_controller
from plugins.blackbox.curate.lab import evidence_schema
from plugins.blackbox.curate.lab.controller import (LabController, ScaleStep, SignedEvidence,
                                                    lab_only_verdict_may_block, verify_signed_evidence)
from plugins.blackbox.curate.lab.jobs import LabJobState
from plugins.blackbox.curate.lab.transport import LabAnswer, LabOutcome, LabTransport
from plugins.blackbox.curate.queue import Lane
from plugins.blackbox.curate.watch import SigningLog
from plugins.blackbox.kernel import signing
from test_blackbox_curate import FakeNode, _ctx

LAB = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "curate" / "lab"
PEER = "12D3KooW" + "A" * 44
IMAGE = "a" * 64
PACKAGE = "dep:npm:evil-pkg@1.0.0"


# -- the transport against real loopback sockets -----------------------------------


@pytest.fixture
def lab_server():
    """A loopback HTTP lab whose answer per path is set by the test: (status, body bytes)."""
    answers = {}

    class Handler(BaseHTTPRequestHandler):
        def _answer(self):
            status, body = answers.get(self.path, (404, b"{}"))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _answer

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", answers
    server.shutdown()
    server.server_close()


def test_the_lab_answering_is_ok(lab_server):
    url, answers = lab_server
    answers["/jobs/k%3A1"] = (200, b'{"state": "running"}')
    answer = LabTransport(url).status("k:1")
    assert answer == LabAnswer(LabOutcome.OK, {"state": "running"})


@pytest.mark.parametrize("status", [400, 404, 409])
def test_a_lab_no_is_refused(lab_server, status):
    url, answers = lab_server
    answers["/jobs/k"] = (status, b"{}")
    assert LabTransport(url).status("k").outcome is LabOutcome.REFUSED


@pytest.mark.parametrize("status, body", [(429, b"{}"), (500, b"{}"), (503, b"{}"),
                                          (200, b"not json"), (200, b"[1, 2]")])
def test_a_busy_broken_or_garbled_lab_is_unavailable_never_refused(lab_server, status, body):
    url, answers = lab_server
    answers["/jobs/k"] = (status, body)
    assert LabTransport(url).status("k").outcome is LabOutcome.UNAVAILABLE


def test_a_lab_nobody_listens_on_is_unavailable():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]          # free once closed: nothing listens there
    assert LabTransport(f"http://127.0.0.1:{port}").status("k").outcome is LabOutcome.UNAVAILABLE


def test_a_hung_lab_hits_the_one_timeout_once():
    """The lab accepts the connection and never answers: one wait of the timeout,
    one connection (no hidden retry), an UNAVAILABLE answer."""
    connections = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def accept_and_hang():
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            connections.append(connection)        # held open, never answered

    threading.Thread(target=accept_and_hang, daemon=True).start()
    try:
        started = time.monotonic()
        answer = LabTransport(f"http://127.0.0.1:{listener.getsockname()[1]}", timeout=0.3).status("k")
        elapsed = time.monotonic() - started
    finally:
        listener.close()
        for connection in connections:
            connection.close()
    assert answer.outcome is LabOutcome.UNAVAILABLE
    assert 0.3 <= elapsed < 0.9
    assert len(connections) == 1


@pytest.fixture
def raw_lab():
    """A loopback lab that runs *behaviour(connection)* on each accepted connection
    after reading the request — for answers no well-behaved HTTP server gives."""
    listeners, connections = [], []

    def start(behaviour):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listeners.append(listener)

        def serve():
            while True:
                try:
                    connection, _ = listener.accept()
                except OSError:
                    return
                connections.append(connection)
                connection.recv(65_536)
                try:
                    behaviour(connection)
                except OSError:
                    pass                               # the client cut the line: expected

        threading.Thread(target=serve, daemon=True).start()
        return f"http://127.0.0.1:{listener.getsockname()[1]}"

    yield start
    for sock in listeners + connections:
        sock.close()


def _trickle(data, every=0.05):
    def behaviour(connection):
        for byte in data:
            connection.sendall(bytes([byte]))
            time.sleep(every)
    return behaviour


@pytest.mark.parametrize("data", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 60\r\n\r\n" + b" " * 60,   # the body trickles
    b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 60,                       # the headers trickle
], ids=["body", "headers"])
def test_a_trickling_lab_is_cut_off_at_the_one_timeout(raw_lab, data):
    """Each byte arrives well inside a per-read timeout, so only a hard deadline
    over the whole call stops it (the builder's per-read wait took ~4 s)."""
    started = time.monotonic()
    answer = LabTransport(raw_lab(_trickle(data)), timeout=0.3).status("k")
    assert answer.outcome is LabOutcome.UNAVAILABLE and answer.reason == "timeout"
    assert time.monotonic() - started < 0.9


@pytest.mark.parametrize("reply", [
    b"garbage\r\n\r\n",                                                  # not HTTP at all
    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}",                # cut short, yet parses
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":",  # chunked, cut short
], ids=["bad-status-line", "truncated", "truncated-chunked"])
def test_a_garbled_lab_is_unavailable_and_never_raises(raw_lab, reply):
    def behaviour(connection):
        connection.sendall(reply)
        connection.close()
    assert LabTransport(raw_lab(behaviour)).status("k").outcome is LabOutcome.UNAVAILABLE


def test_a_redirect_is_never_followed(raw_lab):
    """A lab that redirects could lead the request off this machine: never followed."""
    contacted = []

    def elsewhere(connection):
        contacted.append(True)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"state\": \"done\"}")

    target = raw_lab(elsewhere)

    def redirect(connection):
        connection.sendall(f"HTTP/1.1 302 Found\r\nLocation: {target}/jobs/k\r\n"
                           "Content-Length: 0\r\n\r\n".encode())

    answer = LabTransport(raw_lab(redirect)).status("k")
    assert answer.outcome is LabOutcome.UNAVAILABLE and answer.reason == "http 302"
    time.sleep(0.05)
    assert contacted == []


def test_an_oversized_answer_is_unavailable(lab_server, monkeypatch):
    url, answers = lab_server
    monkeypatch.setattr("plugins.blackbox.curate.lab.transport.MAX_ANSWER_BYTES", 16)
    answers["/jobs/k"] = (200, json.dumps({"state": "done", "pad": "x" * 32}).encode())
    assert LabTransport(url).status("k").outcome is LabOutcome.UNAVAILABLE


@pytest.mark.parametrize("url", ["http://10.0.0.5:7801", "http://lab.example.com", "ftp://127.0.0.1/", ""])
def test_only_a_loopback_lab_is_accepted(url):
    with pytest.raises(ValueError):
        LabTransport(url)


# -- the controller ------------------------------------------------------------------


class ScriptedLab:
    """A transport whose lab answers are scripted: ``state`` for every status call,
    ``submit_outcome`` for every submit; records each submit."""

    def __init__(self, state="running", submit_outcome=LabOutcome.OK):
        self.state, self.submit_outcome, self.submitted = state, submit_outcome, []

    def submit(self, job):
        self.submitted.append(job.key)
        return LabAnswer(self.submit_outcome, {"key": job.key} if self.submit_outcome is LabOutcome.OK else None)

    def status(self, key):
        if self.state is None:
            return LabAnswer(LabOutcome.UNAVAILABLE, reason="timeout")
        return LabAnswer(LabOutcome.OK, {"state": self.state})

    def output(self, key):
        return LabAnswer(LabOutcome.OK, {"hosts": ["evil.example"]})


def extract(job, raw):
    """A stand-in for the L3 extractor: raw output → typed Evidence for *job*."""
    return evidence_schema.validate_evidence({
        "job_key": job.key, "image_sha256": job.key.split(":")[2], "level": job.level,
        "started_at": 1_000, "finished_at": 1_020, "contacted_hosts": raw["hosts"], "file_fingerprints": [],
        "observations": [{"check": "network-contacted", "seen": True}], "notes": []})


class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def lab(tmp_path):
    """(controller factory, scripted lab, clock, signing log) on one lab folder."""
    scripted, clock = ScriptedLab(), Clock()
    log = SigningLog(tmp_path / "signing_log.jsonl")
    ctx = dataclasses.replace(_ctx(FakeNode(), None), signing_log=log)
    key = Ed25519PrivateKey.generate()

    def make():
        return LabController(ctx, key, scripted, extract, lab_dir=tmp_path / "lab", clock=clock)

    return make, scripted, clock, log


def _submit(controller, identifier=PACKAGE, level=2):
    return controller.submit(identifier, level=level, image_sha256=IMAGE, lane=Lane.GRADUATION, requested_by=PEER)


def test_a_finished_run_is_collected_signed_and_stored(lab, tmp_path):
    make, scripted, _clock, log = lab
    controller = make()
    record = _submit(controller)
    assert record.state is LabJobState.RUNNING and scripted.submitted == [record.job.key]

    scripted.state = "done"
    controller.poll()
    done = controller.store.get(record.job.key)
    assert done.state is LabJobState.DONE
    assert (tmp_path / "lab" / "evidence" / f"{done.evidence_sha256}.json").exists()

    signed = controller.evidence(record.job.key)
    assert signed is not None and signed.evidence.contacted_hosts == ("evil.example",)
    payload = signed.envelope.payload
    assert (payload["job_key"], payload["image_sha256"]) == (record.job.key, IMAGE)
    assert (payload["started_at"], payload["finished_at"], payload["signed_at"]) == ("1000", "1020", "1000000")
    (row,) = log.rows()                                         # signed through the choke point, logged
    assert (row.kind, row.digest) == (LAB_EVIDENCE_STATEMENT, signing.content_id(signed.envelope))


def test_signed_evidence_verifies_and_a_tampered_field_fails(lab):
    make, scripted, _clock, _log = lab
    controller = make()
    key = _submit(controller).job.key
    scripted.state = "done"
    controller.poll()
    signed = controller.evidence(key)
    lab_key = signed.envelope.signers[0]
    assert verify_signed_evidence(signed, environment="testnet", lab_key=lab_key) is False   # wrong network
    environment = signed.envelope.environment
    assert verify_signed_evidence(signed, environment=environment, lab_key=lab_key)
    assert not verify_signed_evidence(signed, environment=environment, lab_key="0" * 64)     # another key

    lied_evidence = dataclasses.replace(signed.evidence, contacted_hosts=("good.example",))
    assert not verify_signed_evidence(SignedEvidence(lied_evidence, signed.envelope),
                                      environment=environment, lab_key=lab_key)
    lied_payload = dataclasses.replace(signed.envelope, payload={**signed.envelope.payload, "finished_at": "9999"})
    assert not verify_signed_evidence(SignedEvidence(signed.evidence, lied_payload),
                                      environment=environment, lab_key=lab_key)


def test_a_tampered_evidence_file_is_not_served(lab, tmp_path):
    make, scripted, _clock, _log = lab
    controller = make()
    key = _submit(controller).job.key
    scripted.state = "done"
    controller.poll()
    path = tmp_path / "lab" / "evidence" / f"{controller.store.get(key).evidence_sha256}.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["contacted_hosts"] = ["good.example"]
    path.write_text(json.dumps(stored), encoding="utf-8")
    assert controller.evidence(key) is None


@pytest.mark.parametrize("identifier", [PACKAGE, "skill:evil-skill", "ioc:hash:" + "b" * 64])
def test_a_lab_only_block_tier_verdict_is_flag_tier_until_two_lab_hosts_agree(identifier):
    assert lab_only_verdict_may_block(identifier, []) is False
    assert lab_only_verdict_may_block(identifier, ["lab-1"]) is False              # no Lab 2 yet
    assert lab_only_verdict_may_block(identifier, ["lab-1", "lab-1"]) is False     # the same host twice
    assert lab_only_verdict_may_block(identifier, ["lab-1", "lab-2"]) is True


@pytest.mark.parametrize("identifier", ["ioc:domain:evil.example", "ioc:url:https://evil.example/x",
                                        "ioc:wallet:0x" + "1" * 40, "injection:abc", "unknown"])
def test_address_and_other_types_only_ever_flag_from_the_lab(identifier):
    assert lab_only_verdict_may_block(identifier, ["lab-1", "lab-2", "lab-3"]) is False


def test_a_third_retry_does_not_happen(lab):
    """A run that fails every time: the first run + 2 retries, then could-not-tell."""
    make, scripted, _clock, _log = lab
    scripted.state = "failed"
    controller = make()
    key = _submit(controller).job.key
    for _ in range(6):
        controller.poll()
    assert scripted.submitted == [key] * lab_controller.MAX_ATTEMPTS == [key] * 3
    assert controller.store.get(key).state is LabJobState.COULD_NOT_TELL


def test_the_run_count_survives_a_restart(lab):
    make, scripted, _clock, _log = lab
    scripted.state = "failed"
    key = _submit(make()).job.key
    make().poll()                                   # a fresh controller: retry 1
    make().poll()                                   # another: retry 2
    make().poll()                                   # used up
    assert scripted.submitted == [key] * 3
    assert make().store.get(key).state is LabJobState.COULD_NOT_TELL


def test_an_unreachable_lab_costs_no_run_and_a_refusing_one_is_a_definite_no(lab):
    make, scripted, _clock, _log = lab
    scripted.submit_outcome = LabOutcome.UNAVAILABLE
    controller = make()
    record = _submit(controller)
    for _ in range(5):
        controller.poll()
    assert controller.store.get(record.job.key).state is LabJobState.QUEUED      # waits; never dropped
    scripted.submit_outcome = LabOutcome.OK
    controller.poll()
    assert controller.store.get(record.job.key).state is LabJobState.RUNNING

    scripted.submit_outcome = LabOutcome.REFUSED
    refused = _submit(controller, identifier="dep:npm:other@1.0.0")
    assert refused.state is LabJobState.COULD_NOT_TELL


def test_a_job_a_poll_sent_meanwhile_is_not_sent_again_by_submit(lab):
    """submit admits outside the lock; a poll that sends the job in that gap must
    not make submit send it a second time (an extra run, then a RUNNING→RUNNING error)."""
    make, scripted, _clock, _log = lab
    controller = make()
    admit = controller.store.request

    def admit_then_poll(*args, **kwargs):
        record = admit(*args, **kwargs)
        controller.poll()                           # another beat thread wins the race
        return record

    controller.store.request = admit_then_poll
    record = _submit(controller)
    assert record.state is LabJobState.RUNNING
    assert scripted.submitted == [record.job.key]


def test_a_run_past_its_deadline_could_not_tell(lab):
    make, scripted, clock, _log = lab
    scripted.state = None                           # the lab stops answering
    controller = make()
    key = _submit(controller, level=4).job.key
    clock.now += 299
    controller.poll()
    assert controller.store.get(key).state is LabJobState.RUNNING
    clock.now += 2                                  # level 4: 5 minutes
    controller.poll()
    assert controller.store.get(key).state is LabJobState.COULD_NOT_TELL
    scripted.state = "done"
    controller.poll()
    assert controller.store.get(key).state is LabJobState.COULD_NOT_TELL       # final


def test_metrics_are_computed_from_the_store(lab):
    make, scripted, clock, _log = lab
    controller = make()
    assert controller.metrics() == lab_controller.LabMetrics(0, 0, 0.0)
    first = _submit(controller, identifier="dep:npm:a@1.0.0").job.key
    clock.now += 60                                                             # inside level 2's deadline
    _submit(controller, identifier="dep:npm:b@1.0.0")
    scripted.submit_outcome = LabOutcome.UNAVAILABLE
    _submit(controller, identifier="dep:npm:c@1.0.0")                          # stays queued
    clock.now += 30
    scripted.state = "done"
    controller.poll()                                                           # a and b finish
    assert controller.store.get(first).state is LabJobState.DONE
    metrics = controller.metrics()
    assert (metrics.jobs_per_hour, metrics.queue_depth, metrics.oldest_job_age) == (2, 1, 30.0)
    clock.now += 3_600 + 1
    assert controller.metrics().jobs_per_hour == 0                              # older than an hour

    # The same numbers survive a restart: they come from the store, not the controller.
    assert make().metrics() == controller.metrics()


@pytest.mark.parametrize("oldest, sustained, step", [
    (3_000, 90_000, None),
    (3_700, 3_600, None),                            # over an hour, not yet for a day
    (3_700, 86_400, ScaleStep.ADD_WORKER),
    (4 * 3_600 + 1, 0, ScaleStep.ADD_LAB_HOST),
])
def test_the_scale_rule_thresholds(oldest, sustained, step):
    assert lab_controller.LabMetrics(10, 5, oldest).scale_step(sustained) is step


def test_the_lab_package_holds_no_source_credentials():
    """The controller holds no source API keys: nothing under curate/lab imports
    the sources package (where credentials.py lives)."""
    for path in sorted(LAB.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [alias.name for alias in node.names]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                continue
            assert not any("credentials" in name or "sources" in name.split(".") for name in names), path
