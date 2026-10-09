"""The local JSONL log files under ``$BLACKBOX_HOME`` and their size cap.

Append-only JSON-lines writes under one process lock, trimmed to a bounded
size; file discovery for findings/audit logs across protected agents.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List
from ..kernel import constants

# ---------------------------------------------------------------------------
# Bounded JSONL logs
# ---------------------------------------------------------------------------

_LOG_MAX_BYTES = 8 * 1024 * 1024  # trim each log at 8 MB
_LOG_KEEP_BYTES = 4 * 1024 * 1024  # keep the most recent ~4 MB after trimming
_lock = threading.Lock()


def _home() -> Path:
    home = constants.blackbox_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
    except Exception:  # pragma: no cover - defensive
        pass
    return home


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False)
    with _lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        _trim_if_needed(path)


def _trim_if_needed(path: Path) -> None:
    """Keep the tail of *path* when it grows past the cap (whole lines only)."""
    try:
        if path.stat().st_size <= _LOG_MAX_BYTES:
            return
        with path.open("rb") as fh:
            fh.seek(-_LOG_KEEP_BYTES, os.SEEK_END)
            tail = fh.read()
        # Drop a possibly-partial first line.
        nl = tail.find(b"\n")
        if nl != -1:
            tail = tail[nl + 1 :]
        path.write_bytes(tail)
    except Exception:  # pragma: no cover - defensive
        pass


def _findings_files() -> List["tuple[Path, str]"]:
    """Return ``(path, default_framework)`` for every findings log in the home.

    ``findings.jsonl`` is the Hermes plugin's own log; sibling
    ``findings.<framework>.jsonl`` files come from other local agents (e.g.
    OpenClaw) sharing the same blackbox home. Framework is taken from each
    finding line when present, else the filename.
    """
    home = _home()
    out: List["tuple[Path, str]"] = [(home / "findings.jsonl", "hermes")]
    try:
        for extra in sorted(home.glob("findings.*.jsonl")):
            # findings.<framework>.jsonl → framework from the middle segment.
            parts = extra.name.split(".")
            fw = parts[1] if len(parts) == 3 else "unknown"
            out.append((extra, fw))
    except Exception:  # pragma: no cover - defensive
        pass
    return out


def _audit_files() -> List["tuple[Path, str]"]:
    """Return routine audit logs for Hermes and every attached framework."""
    home = _home()
    out: List["tuple[Path, str]"] = [(home / "audit.jsonl", "hermes")]
    try:
        for extra in sorted(home.glob("audit.*.jsonl")):
            parts = extra.name.split(".")
            fw = parts[1] if len(parts) == 3 else "unknown"
            out.append((extra, fw))
    except Exception:  # pragma: no cover - defensive
        pass
    return out


def _load_jsonl(path: Path, default_event: str) -> List[Dict[str, Any]]:
    """Load a jsonl file, tagging each row with ``event=default_event`` when
    the line has no explicit event (e.g. file_access.jsonl, dependencies.jsonl)."""
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if "event" not in row:
            row["event"] = default_event
        out.append(row)
    return out
