"""Redaction — THE one implementation that scrubs secret values out of text.

Every place that writes or sends text that might hold a secret (the local
audit logs, the private audit record, the opt-in LLM reviewer) goes through
this module, so a secret shape learned once is scrubbed everywhere (quality
item G1). The same rule table is detection's source for "the agent is
handling a real secret" findings.

Usage::

    from ..kernel import redaction
    safe = redaction.redact_secret_values(text)
    for secret_type, severity, pattern in redaction.SECRET_VALUE_RULES: ...
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Secret VALUE detection — an actual key/token/private-key present in tool args.
# This is the "the agent is handling/leaking a real secret" signal, distinct
# from touching a secret FILE. Format-anchored so only unambiguous secret shapes
# match (a legit `Authorization: Bearer <opaque>` API call is NOT flagged, but a
# recognizable provider key or a private-key block is).
# ---------------------------------------------------------------------------

SECRET_VALUE_RULES = (
    # The WHOLE block — through its END line, or to the end of the text when the
    # block was cut off — so redaction removes the key material, not just the
    # header line (KI-178). Detection matches on the same header as before.
    ("private-key", "critical", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
    ("aws-access-key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("anthropic-api-key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-api-key", "high", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("github-token", "high", re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}")),
    ("slack-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-key", "high", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}")),
    ("gcp-service-account-key", "high", re.compile(r'"type"\s*:\s*"service_account"')),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)


# Redaction-only shapes: scrubbed from anything written or sent, but too broad
# to be detection signals (they would raise findings on ordinary text).
_REDACTION_ONLY_RULES = (
    # Shorter/older provider keys than the detection rules above require.
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("github-token", re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}")),
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
# A secret-named key followed by `:` or `=` and a value: `DB_PASSWORD=...`,
# `"api_key": "..."`. The key name stays (it explains the log line); the value
# goes. A value already replaced by a typed marker (`[REDACTED_...]`) is kept.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?P<key>\b[A-Za-z0-9_-]*(?:api[_-]?key|token|secret|password|passwd|credential"
    r"|private[_-]?key|client[_-]?secret|access[_-]?key)[A-Za-z0-9_-]*[\"']?)"
    r"(?P<sep>\s*[:=]\s*[\"']?)"
    r"(?P<value>[^\s\"'\[\],;]{8,})",
    re.IGNORECASE,
)


def redact_secret_values(text: str) -> str:
    """Replace every recognizable secret value in *text* with a marker.

    Known secret shapes become typed markers (``[REDACTED_PRIVATE_KEY]``);
    bearer tokens become ``Bearer [REDACTED]``; secret-named assignments keep
    their key and lose their value (``DB_PASSWORD=[REDACTED]``). Truncate
    AFTER calling this, never before — a secret cut in half no longer matches.
    """
    out = str(text)
    for typ, _severity, pattern in SECRET_VALUE_RULES:
        out = pattern.sub(f"[REDACTED_{typ.upper().replace('-', '_')}]", out)
    for typ, pattern in _REDACTION_ONLY_RULES:
        out = pattern.sub(f"[REDACTED_{typ.upper().replace('-', '_')}]", out)
    out = _BEARER_RE.sub("Bearer [REDACTED]", out)
    return _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group('key')}{m.group('sep')}[REDACTED]", out)
