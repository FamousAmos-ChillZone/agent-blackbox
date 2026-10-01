"""SPARQL helpers shared by every reader of the graph.

* :func:`sparql_string_literal` — THE escaper for any value interpolated into
  a query (never hand-escape at a call site).
* ``MAX_ROWS`` — the hard ceiling on rows any paged read may collect.
"""

from __future__ import annotations


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
