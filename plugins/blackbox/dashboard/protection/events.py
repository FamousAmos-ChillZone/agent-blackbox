"""Trader Shield's full event report: every wallet event, with the session around it (local only).

``GET /api/wallet-protection/events`` answers the dashboard's full-screen "Wallet events"
window. Each event is one time the agent reached for a wallet vault, a seed phrase or a
labelled private key, told the way a person reads it:

* ``outcome`` (blocked / flagged), ``title``, ``identifier``, ``severity``, ``ts``;
* ``tool`` and ``command`` — the exact tool call (redacted, size-capped);
* ``asked`` — the request in the conversation just before the agent acted (redacted);
* ``profile`` — the closed-vocabulary threat profile the finding carries;
* ``session`` — agent, model, start/end, how it ended;
* ``timeline`` — that session's steps in order (model calls, tool calls, file reads,
  installs, threats met on the way — e.g. a prompt injection in what the agent read),
  each naming the threats it raised (``threat_titles``), the step that triggered the
  event marked ``this: true``.

PRIVATE BY CONSTRUCTION: everything is read from this machine's own audit logs through
the one session reconstruction the local graph also uses (:func:`audit.read_local_activity`)
and served only by the loopback dashboard. Wallet findings carry ``source: "secret"``,
which the community share gate never sends (``NEVER_SHARED_SOURCES``), so none of this —
summary or detail — ever reaches the community graph. No network addresses are shown.

Usage::

    wallet_event_report()   # {"events": [...], "private": True}
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ... import audit
from ...kernel.crypto_secrets import wallet_mode
from ...kernel.display_safety import log_safe
from ..safe_payloads import safe_identifier

MAX_REPORT_EVENTS = 100
#: Steps shown per session; a long session keeps the steps nearest the event.
MAX_TIMELINE_STEPS = 40
SESSIONS_SCANNED = 200


def local_text(value: Any, limit: int) -> str:
    """Text from this machine's own logs, for the page: controls stripped and clamped.

    Not :func:`..safe_payloads.safe_text`: that one defangs indicators for community-written
    text, and would show the operator's own ``backup.tgz`` as ``backup[.]tgz``. These values
    were redacted when they were logged, and the page escapes them when it inserts them."""
    return log_safe(value if value is not None else "", limit)


def is_wallet_identifier(identifier: str) -> bool:
    """Whether a finding identifier is a Trader Shield (wallet) event."""
    return wallet_mode.belongs_to_mode(identifier)


def _last_request(context: Optional[Dict[str, Any]]) -> str:
    """The latest user turn before the action (already redacted by the audit reader)."""
    turns = (context or {}).get("turns") or []
    for turn in reversed(turns):
        if str(turn.get("role") or "").lower() == "user" and turn.get("text"):
            return local_text(turn["text"], 600)
    return ""


def _step(event: Dict[str, Any], is_this: bool) -> Dict[str, Any]:
    """One timeline step: what kind, when, and a short readable label."""
    kind = event.get("type") or "event"
    if kind == "api":
        label = "Asked the model " + str(event.get("model") or "")
    elif kind == "file":
        label = "%s %s" % (event.get("mode") or "read", event.get("path") or "")
    elif kind == "dependency":
        label = "install %s:%s@%s" % (event.get("ecosystem"), event.get("name"), event.get("version"))
    elif kind == "threat":   # met outside a tool call, e.g. an injection in a model request
        label = "Threat found in what the agent was given"
    else:
        label = str(event.get("action") or "")   # redacted when it was logged (audit.record)
    threats = event.get("threats") or []
    outcomes = sorted({"blocked" if t.get("decision") == "block" else "flagged" for t in threats})
    return {"type": local_text(kind, 16), "ts": event.get("ts") or 0, "tool": local_text(event.get("tool"), 40),
            "label": local_text(label, 240), "result": local_text(event.get("resultStatus"), 16),
            "threats": outcomes, "threat_titles": [local_text(t.get("title"), 120) for t in threats][:4],
            "this": is_this}


def _timeline(events: List[Dict[str, Any]], index: int) -> List[Dict[str, Any]]:
    """The session's steps, at most :data:`MAX_TIMELINE_STEPS`, centred on step *index*."""
    start = max(0, min(index - MAX_TIMELINE_STEPS // 2, len(events) - MAX_TIMELINE_STEPS))
    window = events[start:start + MAX_TIMELINE_STEPS]
    return [_step(event, start + offset == index) for offset, event in enumerate(window)]


def _session_summary(session: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": local_text(session.get("shortId"), 16), "agent": local_text(session.get("agent"), 24),
            "model": local_text(session.get("model"), 64), "start": session.get("start"), "end": session.get("end"),
            "status": local_text(session.get("status"), 16), "steps": len(session.get("events") or [])}


def _event(threat: Dict[str, Any], step: Dict[str, Any], session: Dict[str, Any], index: int) -> Dict[str, Any]:
    """One wallet event as the report window shows it (see the module doc)."""
    return {"ts": threat.get("ts") or step.get("ts") or 0,
            "identifier": safe_identifier(threat.get("identifier")),
            "title": local_text(threat.get("title"), 160), "severity": local_text(threat.get("severity"), 16),
            "outcome": "blocked" if threat.get("decision") == "block" else "flagged",
            "evidence": local_text(threat.get("evidence"), 160),
            "tool": local_text(threat.get("tool") or step.get("tool"), 40),
            "command": local_text(step.get("action"), 400),
            "asked": _last_request(threat.get("context")),
            "profile": {key: local_text(value, 48) for key, value in (threat.get("profile") or {}).items()
                        if isinstance(value, str)},
            "session": _session_summary(session),
            "timeline": _timeline(session.get("events") or [], index)}


def wallet_event_report() -> Dict[str, Any]:
    """Every wallet event on this machine, newest first (fail-open: empty when logs are unreadable)."""
    try:
        sessions = audit.read_local_activity(max_sessions=SESSIONS_SCANNED).get("sessions") or []
    except Exception:   # an unreadable log means "no events", never a broken window
        sessions = []
    events: List[Dict[str, Any]] = []
    for session in sessions:
        for index, step in enumerate(session.get("events") or []):
            for threat in step.get("threats") or []:
                if is_wallet_identifier(str(threat.get("identifier") or "")):
                    events.append(_event(threat, step, session, index))
    events.sort(key=lambda event: event["ts"], reverse=True)
    return {"events": events[:MAX_REPORT_EVENTS], "private": True}
