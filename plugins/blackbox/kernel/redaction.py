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
    ("private-key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
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


def redact_secret_values(text: str) -> str:
    """Replace every recognizable secret value in *text* with a typed marker."""
    out = str(text)
    for typ, _severity, pattern in SECRET_VALUE_RULES:
        out = pattern.sub(f"[REDACTED_{typ.upper().replace('-', '_')}]", out)
    return out
