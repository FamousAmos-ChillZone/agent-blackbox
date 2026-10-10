"""Browsing the live tiers: one page of verified dependency / IOC threats from the store.

The dashboard's graph page used to slice an in-memory list of every public
rule. Those rules now stay in the node's store (DKG-lookup B6), so a page is a
bounded query: a filtered subject window (OFFSET / LIMIT, no ORDER BY — a sort
over 250k subjects cost 25× on the bench, KI-264; the store's own order is
stable between pages of one generation), then the window's triples through the
compiler's own builders (:func:`partitions.rows_from_triples`,
:func:`row_adapters._row_to_graph_entry`). Totals for the whole filtered result
come from the scope's counts when nothing is filtered, else one COUNT per kind.

Every untrusted value (the search needle, the ecosystem) enters a query as an
escaped literal (LES-001/002); every query names its predicates and carries a
LIMIT or is a GROUP BY summary (LES-013). A store that could not answer gives
``known=False`` — the caller shows what it has and says the live part is unavailable.

Usage: ``page = public_page(scope, store, category="dependency", ecosystem="npm", offset=0, limit=50)``
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ...kernel.dkg_client import extract_binding
from ...kernel.sparql_text import sparql_string_literal as literal
from ...kernel.store import StoreClient
from .. import row_adapters
from ..partitions import rows_from_triples
from .scope import VerifiedScope

logger = logging.getLogger(__name__)

#: A browse query waits at most this long (a dashboard read, not the hot path).
BROWSE_TIMEOUT_SECONDS = 10.0
#: Entries per live page at most; the dashboard pages past it with ``offset``.
MAX_PAGE = 500
#: Triples fetched for a page: subjects × ~15 triples, with headroom.
_TRIPLES_PER_SUBJECT = 40

_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
_DP = "urn:defender:p:"
_BP = "urn:blackbox:p:"
#: The live kinds in page order, and the category each answers to.
KINDS: Tuple[str, ...] = ("dependency", "ioc")


@dataclass(frozen=True)
class LivePage:
    """``entries`` — graph entries (identifier, category, severity, name, subject,
    source) for the requested window; ``total`` — live entries matching the
    filters (all kinds); ``kind_totals`` — per kind; ``ecosystem_totals`` —
    dependency entries per ecosystem; ``known`` — False when the store could not
    answer (``reason`` says why); what was gathered before is still in the page."""

    entries: List[Dict[str, Any]] = field(default_factory=list)
    total: int = 0
    kind_totals: Dict[str, int] = field(default_factory=dict)
    ecosystem_totals: Dict[str, int] = field(default_factory=dict)
    known: bool = True
    reason: str = ""


def public_page(scope: VerifiedScope, store: StoreClient, *, category: str = "", ecosystem: str = "",
                needle: str = "", offset: int = 0, limit: int = 50) -> LivePage:
    """One page of the live public tiers that match the filters (see module doc)."""
    kinds = [kind for kind in KINDS if _kind_matches(kind, category, ecosystem)]
    limit = max(0, min(int(limit), MAX_PAGE))
    offset = max(0, int(offset))
    browser = _Browser(scope, store, ecosystem=ecosystem.strip().lower(), needle=needle.strip().lower())
    totals: Dict[str, int] = {}
    for kind in kinds:
        total = browser.total(kind)
        if total is None:
            return LivePage(known=False, reason=browser.reason)
        totals[kind] = total
    ecosystems = browser.ecosystems() if "dependency" in kinds else {}
    if ecosystems is None:
        return LivePage(kind_totals=totals, total=sum(totals.values()), known=False, reason=browser.reason)
    entries: List[Dict[str, Any]] = []
    for kind in kinds:                      # the window runs across the kinds in order
        if offset >= totals[kind]:
            offset -= totals[kind]
            continue
        take = min(limit, totals[kind] - offset)
        if take <= 0:
            break
        found = browser.window(kind, offset, take)
        if found is None:
            return LivePage(entries, sum(totals.values()), totals, ecosystems, False, browser.reason)
        entries.extend(found)
        limit -= take
        offset = 0
    return LivePage(entries, sum(totals.values()), totals, ecosystems)


def _kind_matches(kind: str, category: str, ecosystem: str) -> bool:
    category = category.strip().lower()
    if category and category != kind:
        return False
    return not (ecosystem.strip() and kind != "dependency")   # ecosystems belong to dependencies


class _Browser:
    """The queries behind one page (one scope, one store, one set of filters)."""

    def __init__(self, scope: VerifiedScope, store: StoreClient, *, ecosystem: str, needle: str) -> None:
        self.scope, self.store = scope, store
        self.ecosystem, self.needle = ecosystem, needle
        self.prefix = f"did:dkg:context-graph:{scope.context_graph_id}/_verifiable_memory/"
        self.reason = ""

    def _pattern(self, kind: str) -> str:
        """The subject pattern of *kind* with the filters applied, inside ``GRAPH ?g``."""
        if kind == "dependency":
            pattern = (f"?t <{_TYPE}> <urn:defender:DependencySignal> ; "
                       f"<{_DP}package> ?pkg ; <{_DP}ecosystem> ?eco .")
            filters = ([f"?eco = {literal(self.ecosystem)}"] if self.ecosystem else []) + (
                [f"CONTAINS(LCASE(?pkg), {literal(self.needle)})"] if self.needle else [])
        else:
            pattern = (f"{{ ?t <{_TYPE}> <urn:defender:IocSignal> ; <{_DP}value> ?val . }} UNION "
                       f'{{ ?t <{_TYPE}> <urn:blackbox:SourceObservation> ; <{_BP}lifecycleStatus> "active" ; '
                       f"<{_BP}normalizedValue> ?val . }}")
            filters = [f"CONTAINS(LCASE(?val), {literal(self.needle)})"] if self.needle else []
        clause = " ".join(f"FILTER({f})" for f in filters)
        return f"GRAPH ?g {{ {pattern} {clause} }} FILTER(STRSTARTS(STR(?g), {literal(self.prefix)}))"

    def _select(self, sparql: str) -> Optional[List[Dict[str, str]]]:
        answer = self.store.select(sparql, timeout=BROWSE_TIMEOUT_SECONDS)
        if not answer.known:
            self.reason = answer.reason
            logger.debug("blackbox: live browse could not read the store: %s", answer.reason)
        return answer.rows

    def total(self, kind: str) -> Optional[int]:
        """Entries of *kind* matching the filters: the scope's count when nothing
        is filtered, else one COUNT (None when the store could not answer)."""
        if not self.ecosystem and not self.needle:
            return int(self.scope.verified_counts.get(kind, 0))
        rows = self._select(f"SELECT (COUNT(DISTINCT ?t) AS ?n) WHERE {{ {self._pattern(kind)} }}")
        if rows is None:
            return None
        return _int(rows[0].get("n")) if rows else 0

    def ecosystems(self) -> Optional[Dict[str, int]]:
        """Dependency entries per ecosystem under the filters (a GROUP BY summary)."""
        rows = self._select(f"SELECT ?eco (COUNT(DISTINCT ?t) AS ?n) WHERE {{ {self._pattern('dependency')} }} GROUP BY ?eco")
        if rows is None:
            return None
        return {extract_binding(row.get("eco")).lower(): _int(row.get("n")) for row in rows if extract_binding(row.get("eco"))}

    def window(self, kind: str, offset: int, limit: int) -> Optional[List[Dict[str, Any]]]:
        """Graph entries for *limit* subjects of *kind* after *offset*."""
        rows = self._select(f"""SELECT ?g ?t ?p ?o WHERE {{
  {{ SELECT ?g ?t WHERE {{ {self._pattern(kind)} }} OFFSET {int(offset)} LIMIT {int(limit)} }}
  GRAPH ?g {{ ?t ?p ?o }}
}} LIMIT {int(limit) * _TRIPLES_PER_SUBJECT}""")
        return None if rows is None else self._entries(rows)

    def _entries(self, rows: Sequence[Dict[str, str]]) -> List[Dict[str, Any]]:
        by_graph: Dict[str, List[Tuple[str, str, str]]] = {}
        for row in rows:
            graph, subject = extract_binding(row.get("g")), extract_binding(row.get("t"))
            if graph in self.scope.assertion_graphs and subject not in self.scope.suppressed_subjects:
                by_graph.setdefault(graph, []).append((subject, extract_binding(row.get("p")), row.get("o") or ""))
        entries: List[Dict[str, Any]] = []
        for graph, triples in by_graph.items():
            for built in rows_from_triples(graph, triples):
                entry = row_adapters._row_to_graph_entry(built, "public")
                if entry and entry["identifier"] not in self.scope.revoked_identifiers:
                    entries.append(entry)
        return entries


def _int(cell: Any) -> int:
    try:
        return int(float(extract_binding(cell) or 0))
    except ValueError:
        return 0
