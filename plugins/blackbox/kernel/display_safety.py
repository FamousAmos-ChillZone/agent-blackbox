"""Safe display of untrusted text in a terminal.

:func:`term_safe` keeps printable characters only (no ANSI/control sequences)
and caps the length — use it for every community or remote string the CLI prints.
"""

from __future__ import annotations


def term_safe(value: object, limit: int = 200) -> str:
    """Render an untrusted string safely for a terminal (KI-009 / LES-001).

    Community/graph-derived text is attacker-authored input at the display
    surface: strip every non-printable character (ANSI escapes, control
    codes) and clamp the length. Use this on ANY value printed to the
    terminal that did not originate on this machine.
    """
    text = str(value or "")
    cleaned = "".join(ch for ch in text if ch.isprintable())
    return cleaned[:limit]
