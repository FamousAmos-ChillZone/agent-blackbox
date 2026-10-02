"""SPARQL helpers shared by every reader of the graph.

* :func:`sparql_string_literal` — THE escaper for any value interpolated into
  a query (never hand-escape at a call site).
* ``MAX_ROWS`` — the hard ceiling on rows any paged read may collect.
* :func:`extract_binding` / :func:`normalize_bindings` — reading the daemon's
  answers: one result cell to a plain string, any response shape to a row
  list. Re-exported by :mod:`.dkg_client` (``from ..kernel.dkg_client import
  extract_binding`` keeps working).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# Safety ceiling so a misbehaving node can never spin the pager forever.
MAX_ROWS = 1_000_000


def sparql_string_literal(value: object) -> str:
    """Escape *value* as a double-quoted SPARQL string literal (KI-029).

    THE one escaping implementation for runtime strings entering SPARQL
    (cursors, identifiers, addresses). Community-graph strings are untrusted
    input that our own read pipeline re-interpolates into queries; everything
    goes through here, nothing is hand-escaped at call sites.
    """
    text = str(value or "")
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{text}"'


# ---------------------------------------------------------------------------
# SPARQL binding normalization
# ---------------------------------------------------------------------------


def extract_binding(value: Any) -> str:
    """Unwrap a single SPARQL binding cell to a plain string.

    Handles the SPARQL-JSON ``{"value": "..."}`` object shape as well as the
    daemon's bare-string shape (IRIs bare, literals ``"..."``, typed literals
    ``"x"^^<...>``, lang literals ``"x"@en``). Literal escapes are decoded.
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        inner = value.get("value")
        return str(inner) if inner is not None else ""
    if isinstance(value, str):
        if value.startswith('"'):
            return _unquote_literal(value)
        return value
    return str(value)


#: N-Triples string escapes (ECHAR) -> the character each stands for.
_NT_ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "r": "\r", "f": "\f", '"': '"', "'": "'", "\\": "\\"}


def _unquote_literal(term: str) -> str:
    """The value of an N-Triples literal term (``"..."``, optionally followed
    by ``^^<type>`` or ``@lang``) with its escapes decoded.

    The daemon returns literals in this raw form, so any value containing a
    quote or backslash — a signed envelope, a command shape — arrives
    escaped. Scans one character at a time so an escaped backslash right
    before the closing quote is read correctly. A term with no closing quote
    is returned unchanged.
    """
    out: List[str] = []
    i = 1
    while i < len(term):
        ch = term[i]
        if ch == '"':
            return "".join(out)
        if ch == "\\" and i + 1 < len(term):
            nxt = term[i + 1]
            width = {"u": 4, "U": 8}.get(nxt)
            if width and i + 2 + width <= len(term):
                try:
                    out.append(chr(int(term[i + 2:i + 2 + width], 16)))
                    i += 2 + width
                    continue
                except ValueError:
                    pass
            out.append(_NT_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return term


def normalize_bindings(result: Any) -> List[Dict[str, Any]]:
    """Extract a list of binding rows from any of the daemon's response shapes."""
    rows = recognized_bindings(result)
    return [] if rows is None else rows


def recognized_bindings(result: Any) -> Optional[List[Dict[str, Any]]]:
    """The binding rows of a response in a shape the daemon is known to use,
    or None for anything else (a malformed reply is NOT an empty result)."""
    if not isinstance(result, dict):
        return None
    rows = None
    if isinstance(result.get("bindings"), list):
        rows = result["bindings"]
    elif isinstance(result.get("results"), dict) and isinstance(result["results"].get("bindings"), list):
        rows = result["results"]["bindings"]
    elif isinstance(result.get("result"), dict) and isinstance(result["result"].get("bindings"), list):
        rows = result["result"]["bindings"]
    if not isinstance(rows, list):
        return None
    return [row for row in rows if isinstance(row, dict)]


def rows_or_fallback(result: Any, on_error: Any) -> Any:
    """What a query returns: the rows of a recognized response, else the
    caller's *on_error* (``[]`` when None). A caller that passes a sentinel
    therefore sees a malformed reply as a failure, never as an empty graph."""
    rows = recognized_bindings(result)
    if rows is None:
        return [] if on_error is None else on_error
    return rows
