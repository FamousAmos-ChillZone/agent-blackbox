"""The five Hermes hook entry points — every tool call and model request passes here.

``on_pre_tool_call`` / ``on_pre_api_request`` run detection BEFORE execution
and may block (block mode, verified rules only); ``on_post_tool_call`` logs
local activity and starts background discovery; ``on_session_start`` /
``on_session_end`` manage per-session context. Fail-open at every boundary: a
Blackbox fault must never break the host agent.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from .. import audit, detection, ruleset
from ..kernel import config as config_mod, constants
from ..kernel.config import BlackboxConfig
from . import background
from . import reporting
from . import session_context

logger = logging.getLogger(__name__)


def _config() -> BlackboxConfig:
    return config_mod.load_blackbox_config()


def blackbox_block_message(findings: List[detection.Finding]) -> str:
    """Human-readable block message summarizing the blocking findings."""
    lines = [
        "Blackbox blocked this tool call — it matched "
        f"{len(findings)} known threat{'s' if len(findings) != 1 else ''} in the threat graph:",
        "",
    ]
    for f in findings:
        lines.append(f"- [{f.severity.upper()}] {f.category}: {f.title} ({f.identifier})")
    lines.append("")
    lines.append(
        "Treat the source content as untrusted. If this is a false positive, "
        "switch Blackbox to audit mode and report the identifier to Umanitek."
    )
    return "\n".join(lines)
_seen_api_findings: Dict[tuple, float] = {}
_API_FINDING_DEDUPE_TTL_SECS = 10 * 60


def _dedupe_api_findings(findings: List[detection.Finding], detail: Dict[str, Any]) -> List[detection.Finding]:
    """Drop repeated pre-api findings from additional model calls in one turn."""
    turn_key = str(detail.get("turn_id") or detail.get("task_id") or detail.get("session_id") or "")
    if not turn_key:
        return findings
    now = time.time()
    for key, seen_at in list(_seen_api_findings.items()):
        if now - seen_at > _API_FINDING_DEDUPE_TTL_SECS:
            _seen_api_findings.pop(key, None)
    out: List[detection.Finding] = []
    for finding in findings:
        key = (turn_key, finding.identifier, finding.evidence or finding.matched or finding.title)
        if key in _seen_api_findings:
            continue
        _seen_api_findings[key] = now
        out.append(finding)
    return out


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------


def on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> Optional[Dict[str, str]]:
    """Detect threats; audit + report; block in block mode for ≥ block_severity.

    Only CONFIRMED graph findings can block; discovery candidates only alert.
    """
    try:
        cfg = _config()
        rs = ruleset.get(cfg)
        # Visibility: log every file-access tool call (best-effort).
        _record_activity(tool_name, args)
        raw = detection.detect_all(tool_name, args, rs, discover=cfg.discover)
        raw += detection.detect_custom_fileaccess(tool_name, args, cfg.protected_paths)
        findings = reporting._flag_worthy(cfg, raw)
        detail = {
            "tool_name": tool_name,
            "session_id": session_id,
            "task_id": task_id,
            "tool_call_id": tool_call_id,
            "args": audit.redact(args),
        }
        # Build the heavier conversation context only on a finding, so routine
        # tool calls stay lean in the audit log.
        if findings:
            ctx = session_context._tool_context(session_id, args)
            if ctx:
                detail["context"] = ctx
        reporting._report_and_audit(cfg, "pre_tool_call", findings, detail)
        # OSV auto-discovery runs off the blocking path so a network lookup
        # never delays or breaks the tool call.
        if cfg.discover and cfg.osv_lookup:
            background._spawn_osv_discovery(cfg, rs, tool_name, args)
        if cfg.block_enabled:
            # Confirmed findings and custom rules block; community/heuristic ones
            # only alert. ``vulnerability`` kind never blocks (a legit-but-
            # vulnerable package must keep working) — only ``malware`` is stopped.
            blocking = [
                f for f in findings
                if (f.confirmed or f.source in ("custom", "secret"))
                and getattr(f, "kind", None) not in (constants.KIND_VULNERABILITY, "historical")
                # IOC findings alert but never auto-block in this rollout: network
                # and crypto-address blocklists are higher-churn/higher-FP than
                # pinned package versions, so validate them in audit mode first.
                and f.category != "ioc"
                and cfg.meets_block_threshold(f.severity)
            ]
            if blocking:
                return {"action": "block", "message": blackbox_block_message(blocking)}
        return None
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: pre_tool_call failed: %s", exc)
        return None


def _record_activity(tool_name: str, args: Any) -> None:
    """Log what the agent touched to the visibility trail (fail-open).

    Covers both the dedicated file tools and the shell channel (parsing reads,
    downloads, and dependency installs out of commands). Visibility, not
    detection: everything is logged regardless of whether it flags.
    """
    try:
        access = detection.file_access_arg(tool_name, args)
        if access:
            audit.record_file_access(access["tool"], access["path"], access["mode"])
            return
        if (tool_name or "").strip().lower() not in detection.SHELL_TOOLS:
            return
        command = detection.command_from_args(tool_name, args)
        if not command:
            return
        for path in detection.parse_shell_reads(command):
            audit.record_file_access("shell", path, "read")
        for url in detection.parse_downloads(command):
            audit.record_file_access("shell", url, "download")
        for dep in detection.parse_dependency_installs(command):
            audit.record_dependency(dep["ecosystem"], dep["name"], dep.get("version", ""), "shell")
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: activity visibility log failed: %s", exc)


def on_post_tool_call(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int = 0,
    **_: Any,
) -> None:
    """Audit the redacted tool result. Never blocks."""
    try:
        audit.record(
            event="post_tool_call",
            detail={
                "tool_name": tool_name,
                "session_id": session_id,
                "task_id": task_id,
                "tool_call_id": tool_call_id,
                "duration_ms": duration_ms,
                "result": audit.redact(result),
            },
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: post_tool_call failed: %s", exc)


def _untrusted_request_text(user_message: Any, request_messages: Any) -> str:
    """Return only the current turn's untrusted text for injection scanning.

    The API request also contains Hermes' system/developer instructions and
    earlier assistant turns. Those are trusted runtime context, not attacker
    input; scanning them caused harmless prompts to inherit matches from the
    system prompt. Scan the current user turn plus tool results produced during
    that turn, while keeping the full conversation separately for local audit
    context.
    """
    current = str(user_message or "").strip()
    messages = request_messages if isinstance(request_messages, list) else []

    # Limit the scan to the most recent user turn and anything returned by tools
    # after it. This also prevents an old injection from firing again on every
    # later request in the same conversation.
    start = 0
    for idx in range(len(messages) - 1, -1, -1):
        msg = messages[idx]
        if isinstance(msg, dict) and str(msg.get("role") or "").lower() == "user":
            start = idx
            break

    parts: List[str] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        value = text.strip()
        if value and value not in seen:
            seen.add(value)
            parts.append(value)

    add(current)
    for msg in messages[start:]:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "").lower()
        # User content and tool output are the untrusted boundaries. System,
        # developer, and assistant content must never create a user finding.
        if role not in ("user", "tool"):
            continue
        add(session_context._message_text(msg.get("content")))
    return "\n".join(parts)


def on_pre_api_request(**kwargs: Any) -> None:
    """Scan current user/tool input for prompt-injection patterns.

    Observer-only: blocking happens at the tool call, not here.
    """
    try:
        cfg = _config()
        rs = ruleset.get(cfg)
        text = _untrusted_request_text(
            kwargs.get("user_message"), kwargs.get("request_messages")
        )
        findings = detection.detect_injection(text, rs)
        if cfg.discover:
            findings = findings + detection.discover_injection(text, rs)
        findings = reporting._flag_worthy(cfg, findings)
        detail = {
            "session_id": kwargs.get("session_id"),
            "task_id": kwargs.get("task_id"),
            "turn_id": kwargs.get("turn_id"),
            "model": kwargs.get("model"),
            "provider": kwargs.get("provider"),
        }
        # Always warm the per-session store (so later tool-call findings can show
        # the turn); attach as context only when this request produced a finding.
        turns = session_context._conversation_turns(kwargs.get("user_message"), kwargs.get("request_messages"))
        session_context._remember_convo(str(kwargs.get("session_id") or ""), turns)
        findings = _dedupe_api_findings(findings, detail)
        if findings and turns:
            detail["context"] = {"turns": turns}
        reporting._report_and_audit(cfg, "pre_api_request", findings, detail)
        # Optional LLM second opinion, off-thread so it never delays the request.
        if cfg.llm_ready:
            background._spawn_llm_review(cfg, text, detail)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: pre_api_request failed: %s", exc)


def on_session_start(session_id: str = "", **kwargs: Any) -> None:
    try:
        audit.record(event="session_start", detail={"session_id": session_id})
        background._spawn_auto_attach(_config())
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: on_session_start failed: %s", exc)


def on_session_end(session_id: str = "", completed: bool = True, interrupted: bool = False, **kwargs: Any) -> None:
    try:
        session_context._forget_convo(session_id)
        audit.record(
            event="session_end",
            detail={"session_id": session_id, "completed": completed, "interrupted": interrupted},
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: on_session_end failed: %s", exc)
