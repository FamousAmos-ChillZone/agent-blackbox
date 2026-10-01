"""Outbound-report bookkeeping: the share ledger, per-threat cooldown, daily cap.

:func:`record_share_outcome` / :func:`read_share_ledger` keep the durable
record of every community share attempt; :func:`recently_reported` /
:func:`mark_reported` enforce the 6-hour per-threat cooldown;
:func:`allow_report` the daily report cap. Lives beside the audit logs because
it shares their store and lock.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List
from . import log_store
from . import redaction

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Outbound-report daily rate limiter
# ---------------------------------------------------------------------------


def _rate_state_path() -> Path:
    return log_store._home() / "report_rate.json"


# ---------------------------------------------------------------------------
# Community reports ledger ($BLACKBOX_HOME/reports_log.jsonl)
# ---------------------------------------------------------------------------

#: Durable record of every outbound community-report attempt (KI-015). The
#: cooldown state above prunes after 6h, so WITHOUT this file a node forgets
#: what it ever contributed; the ledger is what makes ``blackbox report
#: --status`` work offline and enables promotion-feedback later. Append-only
#: JSONL, size-capped by the shared trim like every other log here.
_REPORTS_LOG = "reports_log.jsonl"


def record_share_outcome(
    *,
    identifier: str,
    category: str,
    severity: str,
    subject: str,
    asset_name: str,
    ok: bool,
    error: str = "",
) -> None:
    """Append one outbound-share attempt (success or failure) to the ledger.

    Called by the community share worker AFTER the share resolves, never on
    the hook hot path. ``error`` is sanitized like every audit text so a
    failure message can never smuggle a secret into the log. Fail-open.
    """
    try:
        log_store._append_jsonl(
            log_store._home() / _REPORTS_LOG,
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "identifier": str(identifier or "")[:512],
                "category": str(category or "")[:64],
                "severity": str(severity or "")[:16],
                "subject": str(subject or "")[:512],
                "asset_name": str(asset_name or "")[:128],
                "ok": bool(ok),
                "error": redaction.sanitize_text(error, 400) if error else "",
            },
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: share-ledger write failed (%s)", exc)


def read_share_ledger(limit: int = 100) -> List[Dict[str, Any]]:
    """Newest-first rows from the reports ledger; empty list when absent.

    The offline half of ``blackbox report --status`` (the graph-backed half
    is the Q9 reporter-profile query, merged by the caller when reachable).
    """
    path = log_store._home() / _REPORTS_LOG
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict):
                    rows.append(item)
    except Exception:  # pragma: no cover - fail open
        return []
    return list(reversed(rows[-max(1, limit):]))


# Re-reporting the same identifier within this window adds no signal (the
# sighting KA name is stable per identifier+reporter, so a re-share only
# refreshes dateModified) — skip it to keep reports low-noise.
REPORT_COOLDOWN_SECS = 6 * 3600


def _read_rate_state() -> Dict[str, Any]:
    path = _rate_state_path()
    if not path.exists():
        return {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        return state if isinstance(state, dict) else {}
    except Exception:
        return {}


def recently_reported(identifier: str, cooldown: int = REPORT_COOLDOWN_SECS) -> bool:
    """True when *identifier* was reported within the last *cooldown* seconds.

    Fail-open: any state error reads as "not recently reported".
    """
    if not identifier:
        return False
    try:
        stamps = _read_rate_state().get("reported") or {}
        ts = float(stamps.get(identifier, 0))
        return (time.time() - ts) < max(1, cooldown)
    except Exception:  # pragma: no cover - fail open
        return False


def mark_reported(identifier: str) -> None:
    """Stamp *identifier* as handled now (per-threat cooldown), pruning expired.

    Decoupled from :func:`allow_report` so the cooldown also covers the private
    WM audit KA; otherwise, with reporting off or the daily cap hit, the stamp
    would never be set and the private KA would rewrite on every event.
    """
    if not identifier:
        return
    try:
        with log_store._lock:
            state = _read_rate_state()
            stamps = state.get("reported")
            stamps = dict(stamps) if isinstance(stamps, dict) else {}
            now = time.time()
            stamps[identifier] = now
            state["reported"] = {
                k: v for k, v in stamps.items()
                if isinstance(v, (int, float)) and (now - v) < REPORT_COOLDOWN_SECS
            }
            _rate_state_path().write_text(json.dumps(state), encoding="utf-8")
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: mark_reported failed (%s)", exc)


def allow_report(daily_limit: int) -> bool:
    """Return True if another outbound SWM report is within today's cap.

    Only the date-keyed daily counter; the per-threat cooldown is enforced by
    :func:`recently_reported` / :func:`mark_reported`. Fail-open: on any state
    error, allow the report.

    Concurrency (KI-038, decided): the counter is guarded by an in-process
    lock only. Several agent PROCESSES sharing one BLACKBOX_HOME can race the
    read-modify-write and land slightly over the cap. Accepted deliberately:
    the cap is an anti-flood brake (order-of-magnitude bound), not an exact
    quota — the per-threat cooldown and one-subject-per-(reporter,threat)
    naming bound the graph impact regardless, and a cross-process file lock
    here would put lock-contention I/O on the finding path for no real gain.
    """
    today = time.strftime("%Y-%m-%d", time.gmtime())
    path = _rate_state_path()
    try:
        with log_store._lock:
            state = _read_rate_state()
            if state.get("date") != today:
                # New day: reset the counter but preserve the cooldown stamps.
                state = {"date": today, "count": 0, "reported": state.get("reported", {})}
            if daily_limit > 0 and int(state.get("count", 0)) >= daily_limit:
                logger.debug("blackbox: daily report limit %s reached", daily_limit)
                return False
            state["count"] = int(state.get("count", 0)) + 1
            path.write_text(json.dumps(state), encoding="utf-8")
            return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: rate-limit state failed (%s); allowing", exc)
        return True
