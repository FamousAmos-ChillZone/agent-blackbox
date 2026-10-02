"""Safe display of untrusted text — ONE implementation for CLI, dashboard and logs (R8).

Community and graph strings are attacker-authored input at every display
surface (LES-001). This module is the only place that decides what such a
string may look like when shown:

* :func:`strip_controls` — removes every control and format character: C0/C1
  controls (so no ANSI/OSC escape or CR/LF), bidi overrides and zero-width
  characters (so text cannot reorder or hide what it shows).
* :func:`term_safe` — the CLI: printable characters only, clamped.
* :func:`log_safe` — audit lines: controls gone, CR/LF folded to a space, so a
  value can never forge a log line.
* :func:`defang` — never auto-link: ``http://`` → ``hxxp://``, dots inside
  hostnames and IPs → ``[.]``.
* :func:`idn_beside` — show Punycode beside Unicode: a ``xn--`` label gets its
  Unicode form in brackets, a non-ASCII label its Punycode (Chromium's IDN
  policy: the reader sees both and the look-alike shows).
* :func:`web_safe` — the dashboard's JSON values: controls stripped, clamped,
  defanged, IDN shown both ways. It does NOT HTML-escape: the page escapes
  exactly once when it inserts text (escaping here too produced the
  double-escaped ``&amp;lt;`` seen on the benches, KI-191).

Every scanning regex here is bounded (G6).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Callable, Optional

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SCHEME_RE = re.compile(r"\b(https?)(://)", re.IGNORECASE)
#: Any host, ASCII or not — at most 10 labels (G6) — not already inside the
#: brackets this module adds. Labels are letters/digits with inner hyphens.
_ANY_HOST_RE = re.compile(r"(?<![\w.])(?:[^\W_](?:(?:[^\W_]|-){0,61}[^\W_])?\.){1,10}[^\W\d_]{2,24}(?![\w.])")


def strip_controls(value: object) -> str:
    """*value* without control (Cc) and format (Cf) characters — no escapes,
    no CR/LF, no bidi overrides, no zero-width characters."""
    return "".join(ch for ch in str(value or "") if unicodedata.category(ch) not in ("Cc", "Cf"))


def term_safe(value: object, limit: int = 200) -> str:
    """Render an untrusted string safely for a terminal (KI-009 / LES-001):
    printable characters only (no ANSI/control sequences, no format
    characters), clamped to *limit*."""
    return "".join(ch for ch in strip_controls(value) if ch.isprintable())[:limit]


def log_safe(value: object, limit: int = 4000) -> str:
    """One audit-log value: CR/LF folded to a space, other controls gone, clamped."""
    folded = str(value or "").replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return strip_controls(folded)[:limit]


def _dotted(text: str) -> str:
    return text.replace(".", "[.]")


def defang(text: str) -> str:
    """Make indicators non-clickable: ``hxxp://``, ``[.]`` inside hosts and IPs."""
    text = _SCHEME_RE.sub(lambda m: m.group(1)[0] + "xx" + m.group(1)[3:] + m.group(2), text)
    text = _IPV4_RE.sub(lambda m: _dotted(m.group(0)), text)
    return _ANY_HOST_RE.sub(lambda m: _dotted(m.group(0)), text)


def _other_idn_form(host: str) -> Optional[str]:
    """The Unicode form of a Punycode host, the Punycode form of a non-ASCII
    host, None for a plain ASCII host or a malformed one."""
    try:
        if not host.isascii():
            return host.encode("idna").decode("ascii")
        if "xn--" in host.lower():
            return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        pass
    return None


def idn_beside(text: str, render: Callable[[str], str] = str) -> str:
    """Append the other IDN form, in brackets, after each host that has one:
    a Punycode host (``xn--`` label) gets its Unicode form, a non-ASCII host
    its Punycode. The reader sees both, so a look-alike cannot hide. *render*
    is applied to the host and to its other form (:func:`web_safe` defangs
    both in this one pass)."""
    def beside(match: "re.Match[str]") -> str:
        host = match.group(0)
        other = _other_idn_form(host)
        return render(host) if other is None else f"{render(host)} [{render(other)}]"

    return _ANY_HOST_RE.sub(beside, text)


def web_safe(value: object, limit: int = 256) -> str:
    """A community/graph-derived string as the dashboard's JSON carries it:
    controls stripped, clamped, both IDN forms, defanged. Not HTML-escaped —
    the page escapes once at insertion (KI-191)."""
    return defang(idn_beside(strip_controls(value)[:limit], render=_dotted))
