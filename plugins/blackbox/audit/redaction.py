"""Redaction for anything written to the local audit logs.

:func:`sanitize_text` caps and scrubs one string (secret-shaped values, bearer
tokens); :func:`redact` walks nested values. Secret VALUE patterns come from
``kernel.redaction`` — the one implementation (G1).
"""

from __future__ import annotations

import re
from typing import Any, Dict
from ..kernel.redaction import redact_secret_values
from ..kernel import display_safety

# ---------------------------------------------------------------------------
# Redaction (ported verbatim from the original plugin/node-ui regexes)
# ---------------------------------------------------------------------------

_MAX_TEXT = 2000

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key"
    r"|client[_-]?secret|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)


def sanitize_text(value: str, max_len: int = _MAX_TEXT) -> str:
    """Redact common secret shapes from *value*, fold CR/LF and strip control
    characters (R8: a value can never forge a log line or drive a terminal
    that tails the log), then truncate to *max_len*.

    Redacts with ``kernel.redaction`` (the one implementation) BEFORE
    truncating, so a secret never lands raw — or half-cut — in the audit log.
    """
    text = display_safety.log_safe(redact_secret_values(str(value)), limit=max_len + 32)
    if len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


def redact(value: Any, depth: int = 0) -> Any:
    """Recursively redact secrets from an arbitrary JSON-ish structure."""
    if depth > 5:
        return "[truncated-depth]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in list(value)[:50]]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, child in value.items():
            key_str = str(key)
            if _SECRET_KEY_RE.search(key_str):
                out[key_str] = "[REDACTED]"
            elif key_str.lower() in {"content", "body", "input", "prompt"} and isinstance(child, str):
                out[key_str] = sanitize_text(child, 1200)
            else:
                out[key_str] = redact(child, depth + 1)
        return out
    return sanitize_text(str(value))
