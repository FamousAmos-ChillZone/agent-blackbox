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

from typing import Any, Dict, List


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
    ``"x"^^<...>``, lang literals ``"x"@en``).
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        inner = value.get("value")
        return str(inner) if inner is not None else ""
    if isinstance(value, str):
        if value.startswith('"'):
            i = 1
            while i < len(value):
                if value[i] == '"' and value[i - 1] != "\\":
                    break
                i += 1
            return value[1:i] if i < len(value) else value
        return value
    return str(value)


def normalize_bindings(result: Any) -> List[Dict[str, Any]]:
    """Extract a list of binding rows from any of the daemon's response shapes."""
    if not isinstance(result, dict):
        return []
    rows = None
    if isinstance(result.get("bindings"), list):
        rows = result["bindings"]
    elif isinstance(result.get("results"), dict) and isinstance(result["results"].get("bindings"), list):
        rows = result["results"]["bindings"]
    elif isinstance(result.get("result"), dict) and isinstance(result["result"].get("bindings"), list):
        rows = result["result"]["bindings"]
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]
