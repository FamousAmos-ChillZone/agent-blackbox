"""Recording and reading findings (what Blackbox flagged or blocked).

:func:`record` writes one finding (redacted, with bounded conversation
context); :func:`record_file_access` / :func:`record_dependency` write the
activity side-logs; :func:`read_findings` / :func:`count_findings` and the
framework helpers serve the CLI and dashboard.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from ..kernel import constants
from . import log_store
from . import redaction

logger = logging.getLogger(__name__)


# Read-path caps for the conversation context on a finding row, so a huge log
# line can't bloat the ``/api/findings`` response.
_CONTEXT_MAX_TURNS = 16
_CONTEXT_TURN_CHARS = 3000
_CONTEXT_FIELD_CHARS = 6000


def _bounded_context(ctx: Any) -> Optional[Dict[str, Any]]:
    """Normalize, redact, and bound a finding's local conversation ``context``.

    Shape ``{turns: [{role, text}], input, result, truncated}``, every field
    optional. Every text field passes through :func:`sanitize_text` so it is
    safe even if a caller forgot to redact. Returns ``None`` when empty; bad
    shapes degrade to ``None`` rather than raising (fail-open).
    """
    if not isinstance(ctx, dict):
        return None
    out: Dict[str, Any] = {}
    raw_turns = ctx.get("turns")
    if isinstance(raw_turns, list) and raw_turns:
        turns: List[Dict[str, str]] = []
        for turn in raw_turns[-_CONTEXT_MAX_TURNS:]:
            if not isinstance(turn, dict):
                continue
            text = redaction.sanitize_text(str(turn.get("text") or ""), _CONTEXT_TURN_CHARS)
            if not text:
                continue
            turns.append({
                "role": str(turn.get("role") or "user")[:32],
                "text": text,
            })
        if turns:
            out["turns"] = turns
    for key in ("input", "result"):
        val = ctx.get(key)
        if isinstance(val, str) and val:
            out[key] = redaction.sanitize_text(val, _CONTEXT_FIELD_CHARS)
    if not out:
        return None
    if ctx.get("truncated"):
        out["truncated"] = True
    return out


def _flatten_finding_row(rec: Dict[str, Any], default_fw: str) -> Dict[str, Any]:
    # Lift the per-line ``finding`` fields up to a dashboard-friendly row.
    finding = rec.get("finding") or (rec.get("findings") or [{}])[0] or {}
    detail = rec.get("detail") or {}
    return {
        "time": rec.get("iso") or rec.get("ts"),
        "ts": rec.get("ts") or 0,
        "event": rec.get("event"),
        "session_id": detail.get("session_id"),
        "task_id": detail.get("task_id"),
        "turn_id": detail.get("turn_id"),
        "identifier": finding.get("identifier"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "framework": finding.get("framework") or rec.get("framework") or default_fw,
        "workspace": finding.get("workspace") or rec.get("workspace") or detail.get("workspace"),
        "tool_name": finding.get("tool_name") or detail.get("tool_name"),
        "evidence": finding.get("evidence") or finding.get("title"),
        "confirmed": bool(finding.get("confirmed", True)),
        "source": finding.get("source") or ("public" if finding.get("confirmed", True) else "heuristic"),
        # Local-only conversation snapshot (redacted upstream).
        "context": _bounded_context(detail.get("context") or finding.get("context")),
    }


def _dedupe_finding_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeated findings emitted by multiple API calls in one turn."""
    deduped: Dict[tuple, Dict[str, Any]] = {}
    order: List[tuple] = []
    for row in rows:
        scope = row.get("turn_id") or row.get("task_id") or row.get("session_id") or row.get("time")
        key = (
            row.get("framework"),
            row.get("workspace"),
            row.get("event"),
            scope,
            row.get("identifier"),
            row.get("evidence"),
        )
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = row
            order.append(key)
            continue
        if (row.get("ts") or 0) < (existing.get("ts") or 0):
            deduped[key] = row
    return [deduped[key] for key in order]


def read_findings(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return findings newest-first, paged, merged across every agent's log.

    Reads ``findings.jsonl`` plus any ``findings.<framework>.jsonl`` siblings.
    Empty on any error.
    """
    rows: List[Dict[str, Any]] = []
    for path, default_fw in log_store._findings_files():
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rows.append(_flatten_finding_row(rec, default_fw))
    rows = _dedupe_finding_rows(rows)
    # Newest-first across all logs; rows with no numeric ts keep insertion order.
    rows.sort(key=lambda r: r.get("ts") or 0, reverse=True)
    return rows[offset : offset + limit]


def count_findings() -> int:
    return len(read_findings(limit=1_000_000))


def local_frameworks() -> List[str]:
    """Frameworks that have written findings into this shared home (for the
    dashboard's agent list). Always includes ``hermes`` when its log exists."""
    out: List[str] = []
    for path, default_fw in log_store._findings_files():
        if path.exists() and default_fw not in out:
            out.append(default_fw)
    return out


def local_active_frameworks() -> List[str]:
    """Frameworks with observed local Blackbox activity.

    Findings identify their framework explicitly through ``findings*.jsonl``;
    routine activity lives in ``audit.jsonl`` / ``audit.<framework>.jsonl``.
    """
    out = local_frameworks()
    for audit_path, framework in log_store._audit_files():
        if framework in out or not audit_path.exists():
            continue
        try:
            if any(line.strip() for line in audit_path.read_text(encoding="utf-8").splitlines()):
                if framework == "hermes":
                    out.insert(0, framework)
                else:
                    out.append(framework)
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def record(
    *,
    event: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Append an audit record; on findings also append to findings.jsonl.

    *findings* are Finding dicts (evidence already redacted). *detail* is extra
    context (tool name, ids, args) and is redacted again here before writing.
    """
    try:
        now = time.time()
        base = {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "event": event,
            # Profile-level identity is local-only and lets the dashboard keep
            # separate Hermes homes from inheriting each other's activity.
            "workspace": str(constants.hermes_home()),
        }
        if detail:
            # Redact the detail normally, but rebuild ``detail.context`` via
            # ``_bounded_context``: a plain ``redact`` would re-clamp the
            # conversation snapshot to the 1200-char ``input``/``prompt`` cap.
            raw_context = detail.get("context") if isinstance(detail, dict) else None
            base["detail"] = redaction.redact(detail)
            bounded = _bounded_context(raw_context) if isinstance(raw_context, dict) else None
            if bounded:
                base["detail"]["context"] = bounded
            elif isinstance(base["detail"], dict):
                base["detail"].pop("context", None)
        if findings:
            base["findingCount"] = len(findings)
            base["findings"] = [_finding_summary(f) for f in findings]
        log_store._append_jsonl(log_store._home() / "audit.jsonl", base)
        for finding in findings or []:
            log_store._append_jsonl(log_store._home() / "findings.jsonl", {**base, "finding": _finding_summary(finding)})
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: audit record failed: %s", exc)


def _finding_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "identifier": finding.get("identifier"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "framework": finding.get("framework") or "hermes",
        "tool_name": finding.get("tool_name"),
        "evidence": redaction.sanitize_text(str(finding.get("evidence") or ""), 700),
        "confirmed": bool(finding.get("confirmed", True)),
        "candidate": bool(finding.get("candidate", not finding.get("confirmed", True))),
        "source": str(finding.get("source") or ("public" if finding.get("confirmed", True) else "heuristic")),
        "ts": time.time(),
    }


# ---------------------------------------------------------------------------
# File-access visibility log ($BLACKBOX_HOME/file_access.jsonl)
# ---------------------------------------------------------------------------


def record_file_access(tool: str, path: str, mode: str) -> None:
    """Append a file-access visibility record so a user can see what files
    their agent touched.

    Visibility log, distinct from findings: local-only, NEVER shared to SWM.
    The path is truncated but not redacted (it is the point of the log).
    Best-effort and fail-open.
    """
    try:
        now = time.time()
        log_store._append_jsonl(log_store._home() / "file_access.jsonl", {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "tool": str(tool or "")[:120],
            "path": str(path or "")[:1000],
            "mode": str(mode or "")[:16],
            "workspace": str(constants.hermes_home()),
        })
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: file access record failed: %s", exc)


def record_dependency(ecosystem: str, name: str, version: str, tool: str = "") -> None:
    """Append a dependency-install record.

    Lib-inventory trail: EVERY install is recorded (not only threats), so an
    operator can see every package an agent pulled in. Local-only visibility
    log, never shared to SWM; best-effort and fail-open.
    """
    try:
        now = time.time()
        log_store._append_jsonl(log_store._home() / "dependencies.jsonl", {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "ecosystem": str(ecosystem or "")[:40],
            "name": str(name or "")[:200],
            "version": str(version or "")[:80],
            "tool": str(tool or "")[:120],
            "workspace": str(constants.hermes_home()),
        })
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: dependency record failed: %s", exc)


def read_file_access(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return file-access visibility records newest-first, paged."""
    path = log_store._home() / "file_access.jsonl"
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out[offset : offset + limit]
