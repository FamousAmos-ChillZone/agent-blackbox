"""Probe reports → the raw output the curator reads at ``GET /jobs/<key>/output``
(proposal §03.5, F-015).

The lab NEVER builds Evidence. The curator's Evidence Extractor
(``plugins/blackbox/curate/lab/extractor.py``, deterministic code) is the one
place raw output becomes typed Evidence, so the lab can only report what it
saw, never decide what that means. This module writes the extractor's input
shape (its module doc is the contract)::

    {
      "job_key":     "<the job's key>",
      "started_at":  1760000000,                 # UTC epoch seconds
      "finished_at": 1760000012,
      "pcap":  {"hosts": [str]},                 # every host the probe connected to
      "files": {"artifact_sha256": str,          # level 2: the downloaded code
                "entries": [{"path": str, "sha256": str}]},   # files a reading rule fired on
      "notes": [str]                             # NoteCode values
    }

What each level writes, and what it leaves out on purpose:

* level 1 "look" — ``pcap`` (hosts looked up) and a status note
  (``page-unreachable``, ``tls-error``, ``inconclusive`` …). No section for
  registry or wallet details: no Check witnesses them, so they stay in the raw
  artifact.
* level 2 "read" — ``pcap`` (the download's hosts), ``files`` (the artifact
  plus every file an install-hook, obfuscation or IOC rule fired on) and notes
  (``obfuscated-script``, ``resource-cap-reached``). No ``processes`` section:
  nothing was run, so the lab cannot witness whether an install script WOULD
  run, and a section that cannot witness a check must not answer it (LES-011).
* level 4 "run" (a microVM) — ``pcap`` from the HOST's recording of the guest's
  TAP (``hosts``; ``bait_seen`` only when bait was seen leaving — never
  ``false``: TLS hides payloads, so not seeing bait is not "no bait sent") and
  ``processes`` (no ``pcap`` section when the host made no readable recording),
  the sample's own processes as the guest's root tracer saw
  them, each with its phase (``install`` / ``run``). An install that failed with
  nothing of the package's seen running is noted ``inconclusive`` and has no
  ``processes`` section: nothing was installed, so nothing was witnessed.
* a run cut short by a cap — notes only (``deadline-reached`` /
  ``resource-cap-reached``). The Evidence then answers no check: could-not-tell.
* a sandbox killed by the host egress policy — notes only (``scanning-killed``):
  the kill is the finding; what it was scanning stays in the host's log.

Notes are spelt from the shared ``NoteCode`` vocabulary and fingerprints are
checked with its ``is_sha256``, so the lab cannot write a value the extractor
would refuse (a refused output is re-run, never settled).

Usage::

    raw = output.from_look(RunTimes(key, started, finished), look_report)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .schema import evidence_schema

NoteCode = evidence_schema.NoteCode

#: The lab job states (``GET /jobs/<key>``), spelt as the curator's transport reads them.
QUEUED, RUNNING, DONE, FAILED = "queued", "running", "done", "failed"

#: Flagged-file entries written: the extractor keeps the artifact plus 49 and notes
#: the cap when it sees more, so one past its cap is all it needs to see.
MAX_ENTRIES = evidence_schema.MAX_FILE_FINGERPRINTS + 1
#: An archive path is attacker text the extractor never copies; cut it short.
MAX_PATH_CHARS = 200

#: A probe status other than ok, as a note.
_STATUS_NOTES = {
    "unreachable": NoteCode.PAGE_UNREACHABLE,
    "tls-error": NoteCode.TLS_ERROR,
    "too-large": NoteCode.RESOURCE_CAP_REACHED,
}
_FLAGGED_SECTIONS = ("install_hooks", "obfuscated", "suspicious_iocs")
#: Level 4: the process phases the extractor reads, and the caps on what is forwarded.
_PHASES = ("install", "run")
MAX_PROCESSES = 200
MAX_PROCESS_NAME_CHARS = 64


@dataclass(frozen=True)
class RunTimes:
    """The job key and UTC epoch seconds every output carries."""

    job_key: str
    started_at: int
    finished_at: int


@dataclass(frozen=True)
class RunResult:
    """A finished run: :data:`DONE` with its raw ``output``, or :data:`FAILED`
    (the lab broke; ``output`` is None and the curator runs the job again)."""

    state: str
    output: Optional[dict[str, Any]] = None


def from_look(times: RunTimes, look: Mapping[str, Any]) -> dict[str, Any]:
    """Level 1. An unsupported identifier contacted nothing and answers nothing."""
    status = look.get("status")
    if status == "unsupported":
        return _output(times, notes=[NoteCode.INCONCLUSIVE])
    return _output(times, hosts=_strings(look.get("hosts")), notes=_status_notes(status))


def from_read(times: RunTimes, fetch: Mapping[str, Any], read: Mapping[str, Any]) -> dict[str, Any]:
    """Level 2, the download read with the network off."""
    notes = [NoteCode.OBFUSCATED_SCRIPT] if read.get("obfuscated") else []
    if read.get("truncated"):
        notes.append(NoteCode.RESOURCE_CAP_REACHED)
    files: dict[str, Any] = {"entries": _flagged_entries(read)}
    if evidence_schema.is_sha256(read.get("artifact_sha256")):
        files["artifact_sha256"] = read["artifact_sha256"]
    return _output(times, hosts=_strings(fetch.get("hosts")), files=files, notes=notes)


def from_failed_fetch(times: RunTimes, fetch: Mapping[str, Any]) -> dict[str, Any]:
    """Level 2 when the download produced no code to read."""
    return _output(times, hosts=_strings(fetch.get("hosts")), notes=_status_notes(fetch.get("status")))


def from_run(times: RunTimes, run: Mapping[str, Any]) -> dict[str, Any]:
    """Level 4: the guest's report joined with the host's ``traffic`` record."""
    # No traffic record (the capture never started) answers nothing about the network:
    # an empty host list would read as a definite "contacted nothing" (LES-011).
    traffic = run.get("traffic") if isinstance(run.get("traffic"), Mapping) else None
    hosts = _strings(traffic.get("hosts")) if traffic is not None else None
    status = run.get("status")
    if status != "ok":
        return _output(times, hosts=hosts, notes=_status_notes(status))
    raw = _output(times, hosts=hosts)
    if traffic is not None and traffic.get("bait_seen") is True:
        raw["pcap"]["bait_seen"] = True
    raw["processes"] = _processes(run.get("processes"))
    return raw


def cap_reached(times: RunTimes, note: NoteCode) -> dict[str, Any]:
    """A run cut short by its deadline, a resource cap or an egress kill: the note, nothing else."""
    return _output(times, notes=[note])


def _output(times: RunTimes, hosts: Optional[list[str]] = None, files: Optional[dict[str, Any]] = None,
            notes: Sequence[NoteCode] = ()) -> dict[str, Any]:
    raw: dict[str, Any] = {"job_key": times.job_key, "started_at": times.started_at,
                           "finished_at": max(times.started_at, times.finished_at)}
    if hosts is not None:
        raw["pcap"] = {"hosts": list(dict.fromkeys(hosts))}
    if files is not None:
        raw["files"] = files
    raw["notes"] = list(dict.fromkeys(note.value for note in notes))
    return raw


def _status_notes(status: Any) -> list[NoteCode]:
    if status == "ok":
        return []
    return [_STATUS_NOTES.get(status, NoteCode.INCONCLUSIVE)]


def _flagged_entries(read: Mapping[str, Any]) -> list[dict[str, str]]:
    """One entry per distinct flagged file, smallest digest first, at most :data:`MAX_ENTRIES`."""
    by_digest: dict[str, str] = {}
    for section in _FLAGGED_SECTIONS:
        for entry in read.get(section) or []:
            if isinstance(entry, Mapping) and evidence_schema.is_sha256(entry.get("sha256")):
                by_digest.setdefault(entry["sha256"], str(entry.get("path", ""))[:MAX_PATH_CHARS])
    return [{"path": by_digest[digest], "sha256": digest} for digest in sorted(by_digest)[:MAX_ENTRIES]]


def _processes(values: Any) -> list[dict[str, str]]:
    """The guest's process list in the extractor's shape; an entry it would
    refuse (a phase outside install/run) is a broken guest, so it is dropped
    here rather than forwarded: at most :data:`MAX_PROCESSES` entries."""
    processes: list[dict[str, str]] = []
    for entry in values if isinstance(values, list) else []:
        if isinstance(entry, Mapping) and isinstance(entry.get("name"), str) and entry.get("phase") in _PHASES:
            processes.append({"name": entry["name"][:MAX_PROCESS_NAME_CHARS], "phase": entry["phase"]})
    return processes[:MAX_PROCESSES]


def _strings(values: Any) -> list[str]:
    return [value for value in values or [] if isinstance(value, str)] if isinstance(values, list) else []
