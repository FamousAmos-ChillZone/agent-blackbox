"""Which key manifest a reader acts on (reader policy, Refine R7b).

The manifest FORMAT is :mod:`...kernel.signing.key_manifest`; this module is
what a reader does with the manifests it finds in a graph: keep only those a
trusted root signed for this network and graph, skip one still inside its
72 h time-lock, prefer a dated one, and freeze when two root-signed manifests
disagree at the same order.

Usage::

    manifests = trusted_manifests(rows, environment, graph, roots)
    manifest = effective_manifest(manifests, today)       # None = no curator statement counts
    conflict = manifests_conflict(manifests)              # SECURITY alarm
"""

from __future__ import annotations

from typing import Any, AbstractSet, Dict, Iterable, List, Mapping, Optional, Tuple

from ...kernel import signing, sparql_text
from ...kernel.dkg_client import extract_binding
from ...kernel.signing import key_manifest
from ..statements import curator_statements


def key_manifests_sparql(after: str) -> str:
    """One page of key-manifest rows after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?signedStatement WHERE {{
  ?r a g:KeyManifest ;
     g:signedStatement ?signedStatement .
  {cursor}
}} ORDER BY STR(?r) LIMIT 500
"""


def newest_trusted_manifest(rows: Iterable[Mapping[str, Any]], environment: str, graph: str,
                            roots: AbstractSet[str]) -> Optional[key_manifest.KeyManifest]:
    """The newest manifest (by root epoch, version) signed by one of *roots*."""
    if not roots:
        return None
    return key_manifest.newest(trusted_manifests(rows, environment, graph, roots))


def trusted_manifests(rows: Iterable[Mapping[str, Any]], environment: str, graph: str,
                      roots: AbstractSet[str]) -> List[key_manifest.KeyManifest]:
    """Every root-signed manifest in *rows* for this environment and graph."""
    manifests = []
    for row in rows:
        envelope = signing.from_text(extract_binding(row.get(curator_statements.SIGNED_STATEMENT_VAR)))
        manifest = key_manifest.verify_manifest(envelope, environment=environment, graph=graph, root_keys=roots)
        if manifest is not None:
            manifests.append(manifest)
    return manifests


def effective_manifest(manifests: Iterable[key_manifest.KeyManifest], today: str) -> Optional[key_manifest.KeyManifest]:
    """The manifest readers act on: never one inside its 72 h time-lock; an undated
    manifest only when no dated one exists (an undated newer manifest cannot bypass
    the lock); every manifest at an order two root-signed manifests disagree on is
    skipped — the reader stays frozen at the previous version (review round 4)."""
    rows = list(manifests)
    seen: Dict[Tuple[int, int], set] = {}
    for m in rows:
        seen.setdefault(m.order, set()).add(m.content_hash())
    candidates = [m for m in rows if len(seen[m.order]) == 1 and key_manifest.manifest_clock(m, today)[0] != "pending"]
    dated = [m for m in candidates if m.issued_day]
    return key_manifest.newest(dated or candidates)


def manifests_conflict(manifests: Iterable[key_manifest.KeyManifest]) -> bool:
    """R10b SECURITY: two trusted manifests with the same (root epoch, version)
    but different content — someone published a second truth."""
    seen: Dict[Tuple[int, int], str] = {}
    for manifest in manifests:
        digest = manifest.content_hash()
        if seen.setdefault(manifest.order, digest) != digest:
            return True
    return False
