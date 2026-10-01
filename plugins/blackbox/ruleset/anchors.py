"""Legacy proof anchors — backward compatibility for proof-era VM data.

Order-independent per-threat anchor hashes and a combined root, used only by
:func:`.compiler.verified_identifiers` to accept threats published under the
earlier proof scheme.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable

# ---------------------------------------------------------------------------
# Legacy proof anchors (read compatibility only)
# ---------------------------------------------------------------------------

#: Detection-relevant fields covered by a threat's anchor hash, in canonical
#: order. Producers and consumers hash the same SPARQL binding values, so
#: tampering with any field the detector consumes breaks the batch root.
ANCHOR_FIELDS = ("identifier", "kind", "severity", "name", "pattern", "toolName", "argShape")


def threat_anchor_hash(fields: Dict[str, Any]) -> str:
    """Canonical sha256 over a threat row's detection-relevant fields."""
    lines = [f"{k}={fields.get(k) or ''}" for k in ANCHOR_FIELDS]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def anchor_hashes_from_rows(rows: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """Map identifier -> anchor hash from plain-string binding rows.

    A re-published threat can yield several rows per identifier; keeping the
    lexicographically greatest hash makes independent clients converge on
    the same value without coordinating row order.
    """
    out: Dict[str, str] = {}
    for row in rows:
        ident = str(row.get("identifier") or "").strip()
        if not ident:
            continue
        h = threat_anchor_hash(row)
        if ident not in out or h > out[ident]:
            out[ident] = h
    return out


def anchor_root(pairs: Iterable[tuple]) -> str:
    """Batch root: sha256 over the sorted ``identifier\\x00hash`` lines."""
    lines = sorted(f"{ident}\x00{h}" for ident, h in pairs)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
