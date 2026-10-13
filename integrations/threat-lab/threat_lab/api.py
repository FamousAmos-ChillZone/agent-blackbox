"""The lab's job API — listening ONLY on loopback, where the curator's SSH tunnel
ends (proposal §03.5 topology). The lab is not on Tailscale and has no other
door; :func:`make_server` refuses any non-loopback address before binding.

The routes are exactly what the curator's ``LabTransport``
(``plugins/blackbox/curate/lab/transport.py``) calls; a test drives this server
with the real transport. JSON in and out; an error is ``{"error": "<reason>"}``,
never a trace::

    POST /jobs               {"key", "identifier", "level"} -> 202 {"key"}
    GET  /jobs/<key>         -> 200 {"key", "state"}   state: queued | running | done | failed
    GET  /jobs/<key>/output  -> 200 the raw output (threat_lab.output) once done
    GET  /health             -> 200 {"image_sha256", "levels", "open_jobs"}

* The key must be ``<sha256(query-stripped identifier)>:<level>:<this image's
  hash>``: a key for another image (409) or another identifier (400) is
  refused — the transport reads any 4xx but 429 as the lab's definite no.
* Idempotent by key: a known queued, running or done job is never run twice.
  A FAILED job submitted again runs again — that is how the curator retries.
* At most :data:`CAPACITY` open jobs; a full board answers 503, which the
  transport reads as "busy, ask later", never as no.
* ``/output`` of a job that is not done is 409; of an unknown job 404.
* The transport URL-quotes the key in the path (``:`` → ``%3A``); it is
  unquoted here before lookup.

Pattern: the :class:`JobBoard` is the bounded job table plus a worker pool
(Producer–Consumer); the HTTP handler is a thin Adapter over it.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import urllib.parse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from .config import LabConfig, LabConfigError
from .identifiers import MAX_IDENTIFIER_CHARS, strip_query, threat_digest
from .output import DONE, FAILED, QUEUED, RUNNING, RunResult
from .runner import JobRequest, LabRunner
from .schema import evidence_schema

logger = logging.getLogger("threat_lab.api")

#: Jobs waiting or running at once (the curator's store is bounded the same, §03.5).
CAPACITY = 500
#: Finished jobs remembered for collection; the oldest are forgotten first.
FINISHED_KEPT = 1000
#: Two workers (F-034): on Lab 1 240–720 jobs/h at 10–30 s a job; on Lab 2 one microVM per
#: worker, 2 at once on a 4-vCPU / 16 GB host. A job past the workers waits QUEUED.
WORKERS = 2
MAX_BODY_BYTES = 8192
_OUTPUT_SUFFIX = "/output"


class LoopbackOnlyError(LabConfigError):
    """The API was asked to listen somewhere other than loopback."""


class JobRefused(Exception):
    """A request the board will not take; ``status`` is the HTTP status."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass
class _Record:
    request: JobRequest
    state: str = QUEUED
    output: Optional[Dict[str, Any]] = None

    @property
    def is_open(self) -> bool:
        return self.state in (QUEUED, RUNNING)

    def to_status(self) -> Dict[str, Any]:
        return {"key": self.request.key, "state": self.state}


class JobBoard:
    """Accepts, runs and remembers jobs. One lock guards the table."""

    def __init__(self, config: LabConfig, runner: LabRunner, workers: int = WORKERS,
                 capacity: int = CAPACITY) -> None:
        self._config = config
        self._runner = runner
        self._capacity = capacity
        self._lock = threading.Lock()
        self._records: "OrderedDict[str, _Record]" = OrderedDict()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="threat-lab-job")

    @property
    def image_sha256(self) -> str:
        return self._config.image_sha256

    @property
    def levels(self) -> List[int]:
        return list(self._config.served_levels)

    def submit(self, body: Any) -> Dict[str, Any]:
        """Take the job in *body*; ``{"key"}``. Raises :class:`JobRefused`."""
        request = self._parse(body)
        with self._lock:
            known = self._records.get(request.key)
            if known and known.state != FAILED:
                return {"key": request.key}
            if self._open_jobs() >= self._capacity:
                raise JobRefused(503, "lab queue full")
            record = _Record(request)
            self._records[request.key] = record
            self._records.move_to_end(request.key)
            self._forget_oldest_finished()
        self._pool.submit(self._work, record)
        return {"key": request.key}

    def status(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get(key)
            return record.to_status() if record else None

    def output(self, key: str) -> Tuple[int, Dict[str, Any]]:
        """``(200, raw output)`` for a done job; 404 unknown; 409 not done."""
        with self._lock:
            record = self._records.get(key)
            if record is None:
                return 404, {"error": "unknown job"}
            if record.state != DONE or record.output is None:
                return 409, {"error": f"job is {record.state}, not done"}
            return 200, record.output

    def open_jobs(self) -> int:
        with self._lock:
            return self._open_jobs()

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _work(self, record: _Record) -> None:
        with self._lock:
            record.state = RUNNING
        try:
            result = self._runner.run(record.request)
        except Exception:  # a runner bug must not leave the job running forever
            logger.exception("job %s failed", record.request.key)
            result = RunResult(FAILED)
        with self._lock:
            record.output = result.output
            record.state = result.state

    def _parse(self, body: Any) -> JobRequest:
        if not isinstance(body, dict) or set(body) != {"key", "identifier", "level"}:
            raise JobRefused(400, "body is exactly {key, identifier, level}")
        key, identifier, level = body["key"], body["identifier"], body["level"]
        if isinstance(level, bool) or level not in self._config.served_levels:
            raise JobRefused(400, f"this lab serves levels {list(self._config.served_levels)}")
        if not isinstance(identifier, str) or not identifier.isprintable() \
                or not 0 < len(identifier) <= MAX_IDENTIFIER_CHARS:
            raise JobRefused(400, "identifier must be printable text, at most 2048 characters")
        if not evidence_schema.is_job_key(key):
            raise JobRefused(400, "key is not '<sha256>:<level>:<sha256>'")
        digest, key_level, image = key.split(":")
        if int(key_level) != level:
            raise JobRefused(400, "key level does not match level")
        if image != self._config.image_sha256:
            raise JobRefused(409, "key names another lab image")
        if digest != threat_digest(identifier):
            raise JobRefused(400, "key does not match the identifier")
        return JobRequest(key, strip_query(identifier), level)

    def _open_jobs(self) -> int:
        return sum(1 for record in self._records.values() if record.is_open)

    def _forget_oldest_finished(self) -> None:
        finished = [key for key, record in self._records.items() if not record.is_open]
        for key in finished[:max(0, len(finished) - FINISHED_KEPT)]:
            del self._records[key]


def check_loopback(host: str) -> str:
    """*host* if it is a loopback IP literal; otherwise :class:`LoopbackOnlyError`.
    A name (even ``localhost``) is refused: a name can resolve anywhere."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise LoopbackOnlyError(f"bind to a loopback IP address, not {host!r}") from None
    if not address.is_loopback:
        raise LoopbackOnlyError(f"{host} is not loopback: the lab API listens on the tunnel only")
    return host


def make_server(board: JobBoard, host: str, port: int) -> ThreadingHTTPServer:
    """A server bound to *host*:*port* — only after :func:`check_loopback` passes."""
    check_loopback(host)
    handler = type("LabHandler", (_Handler,), {"board": board})
    server_class = ThreadingHTTPServer
    if ":" in host:
        server_class = type("LabServer6", (ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    return server_class((host, port), handler)


class _Handler(BaseHTTPRequestHandler):
    board: JobBoard
    server_version = "threat-lab"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 (http.server's naming)
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            self._send(200, {"image_sha256": self.board.image_sha256, "levels": self.board.levels,
                             "open_jobs": self.board.open_jobs()})
        elif path.startswith("/jobs/") and path.endswith(_OUTPUT_SUFFIX):
            self._send(*self.board.output(_key_in(path[len("/jobs/"):-len(_OUTPUT_SUFFIX)])))
        elif path.startswith("/jobs/"):
            status = self.board.status(_key_in(path[len("/jobs/"):]))
            if status:
                self._send(200, status)
            else:
                self._send(404, {"error": "unknown job"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if urllib.parse.urlsplit(self.path).path != "/jobs":
            self._send(404, {"error": "not found"})
            return
        self._send(*self._submit())

    def _submit(self) -> Tuple[int, Dict[str, Any]]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return 400, {"error": "bad Content-Length"}
        if not 0 < length <= MAX_BODY_BYTES:
            return 413, {"error": f"body must be 1-{MAX_BODY_BYTES} bytes"}
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return 400, {"error": "body is not JSON"}
        try:
            return 202, self.board.submit(body)
        except JobRefused as refused:
            return refused.status, {"error": refused.reason}

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        logger.info("%s %s", self.address_string(), format % args)


def _key_in(quoted: str) -> str:
    """The job key from its URL-quoted path segment."""
    return urllib.parse.unquote(quoted)
