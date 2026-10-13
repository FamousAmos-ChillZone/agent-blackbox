"""One lab job, start to finish: sandbox(es), raw artifacts, the raw output.

Pattern: Template Method in plain functions — every level runs
start clock → probe(s) in fresh sandboxes → store raw → raw output
(:mod:`threat_lab.output`; the curator turns it into Evidence), differing only
in its probe steps:

* level 1 "look": one sandbox on the lab network (gVisor's default netstack);
* level 2 "read": a ``fetch`` sandbox with the network on that only downloads,
  then a ``read`` sandbox with ``--network=none`` and the download mounted
  read-only. Nothing downloaded is ever run.
* level 4 "run" (a Firecracker lab): one ``run`` step in a fresh microVM
  (:class:`~threat_lab.microvm.FirecrackerSandbox`) — install the package or
  run the skill with inert bait; its traffic recorded on the host.

Each job gets its own fresh work folder, deleted afterwards; each probe its own
container (``--rm``). A probe past the job's deadline is killed and the run
is done with the note ``deadline-reached`` alone; one killed by its memory cap
with ``resource-cap-reached`` alone — Evidence that answers no check, i.e.
could-not-tell (no retry: the same cap would cut it short again). A probe the
host egress policy caught scanning is killed and the run is done with
``scanning-killed`` alone: the kill is itself the observation (LR2). A probe
that gave no readable report is a broken lab: the run FAILED and the curator
runs it again (at most 3 runs a job, its rule).

Usage::

    runner = LabRunner(config, GVisorSandbox(config), ArtifactStore(config.artifacts_dir))
    runner = LabRunner(config, FirecrackerSandbox(config, egress), artifacts)   # a level-4 lab
    result = runner.run(JobRequest(key, identifier, level))     # RunResult: done + output, or failed
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from . import output
from .artifacts import ArtifactStore
from .config import LAB_LEVELS, LabConfig
from .output import DONE, FAILED, NoteCode, RunResult, RunTimes
from .identifiers import strip_query
from .sandbox import NO_NETWORK, Sandbox, SandboxResult, SandboxSpec

logger = logging.getLogger("threat_lab.runner")

_ARTIFACT_NAME = "artifact"


@dataclass(frozen=True)
class JobRequest:
    """What the curator asked: its job key, the identifier (query-stripped
    again here, whoever built the request) and the level."""

    key: str
    identifier: str
    level: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "identifier", strip_query(self.identifier))
        if self.level not in LAB_LEVELS:
            raise ValueError(f"lab levels are {LAB_LEVELS}")


class _CapReached(Exception):
    """A probe cut short by the deadline or a resource cap; carries the note."""

    def __init__(self, note: NoteCode) -> None:
        super().__init__(note.value)
        self.note = note


class _ProbeBroken(Exception):
    """A probe that exited without a readable report."""


class LabRunner:
    """Runs jobs. Thread-safe: each job has its own work folder and sandboxes."""

    def __init__(self, config: LabConfig, sandbox: Sandbox, artifacts: ArtifactStore,
                 clock: Callable[[], float] = time.time) -> None:
        self._config = config
        self._sandbox = sandbox
        self._artifacts = artifacts
        self._clock = clock

    def run(self, request: JobRequest) -> RunResult:
        if request.level not in self._config.served_levels:
            raise ValueError(f"this lab serves levels {self._config.served_levels}")
        started = self._clock()
        deadline = started + self._config.deadline_seconds[request.level]
        self._config.work_dir.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="job-", dir=self._config.work_dir))
        try:
            work.chmod(0o777)  # the probe runs as nobody and must write its download
            steps = {1: self._look, 2: self._read, 4: self._run}[request.level]
            result = RunResult(DONE, steps(request, work, started, deadline))
        except _CapReached as cap:
            if cap.note is NoteCode.SCANNING_KILLED:
                logger.warning("job %s level %s: the sandbox went over the egress caps and was killed",
                               request.key, request.level)
            result = RunResult(DONE, output.cap_reached(self._times(request, started), cap.note))
        except _ProbeBroken:
            result = RunResult(FAILED)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        logger.info("job %s level %s: %s", request.key, request.level, result.state)
        return result

    def _look(self, request: JobRequest, work: Path, started: float, deadline: float) -> dict[str, Any]:
        look = self._probe(("look", request.identifier), self._config.network, work, True, deadline)
        return output.from_look(self._times(request, started), look)

    def _read(self, request: JobRequest, work: Path, started: float, deadline: float) -> dict[str, Any]:
        fetch = self._probe(("fetch", request.identifier, f"/work/{_ARTIFACT_NAME}"),
                            self._config.network, work, True, deadline)
        download = work / _ARTIFACT_NAME
        if fetch.get("status") != "ok" or not download.is_file():
            return output.from_failed_fetch(self._times(request, started), fetch)
        self._artifacts.put(download.read_bytes())
        # From here on: no network, files read-only. The code is read, never run.
        read = self._probe(("read", f"/work/{_ARTIFACT_NAME}"), NO_NETWORK, work, False, deadline)
        return output.from_read(self._times(request, started), fetch, read)

    def _run(self, request: JobRequest, work: Path, started: float, deadline: float) -> dict[str, Any]:
        # The microVM's network is its own TAP on the lab bridge; the spec's network is unused.
        run = self._probe(("run", request.identifier), self._config.network, work, True, deadline)
        return output.from_run(self._times(request, started), run)

    def _probe(self, args: tuple, network: str, work: Path, writable: bool, deadline: float) -> dict[str, Any]:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise _CapReached(NoteCode.DEADLINE_REACHED)
        result = self._sandbox.run(SandboxSpec(args, network, work, writable, remaining))
        for recording in result.recordings:
            if recording:
                self._artifacts.put(recording)
        report = _report(result)
        self._artifacts.put(result.report)
        return report

    def _times(self, request: JobRequest, started: float) -> RunTimes:
        return RunTimes(request.key, int(started), max(int(started), int(self._clock())))


def _report(result: SandboxResult) -> dict[str, Any]:
    if result.timed_out:
        raise _CapReached(NoteCode.DEADLINE_REACHED)
    if result.scanning_killed:
        raise _CapReached(NoteCode.SCANNING_KILLED)
    if result.out_of_memory or result.oversized:
        raise _CapReached(NoteCode.RESOURCE_CAP_REACHED)
    report: Optional[Any] = None
    if result.exit_code == 0:
        try:
            report = json.loads(result.report)
        except ValueError:
            report = None
    if not isinstance(report, dict):
        raise _ProbeBroken()
    return report
