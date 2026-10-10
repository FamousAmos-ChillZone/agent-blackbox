"""Exact verified-rule lookups against the node's local store.

Pattern: Facade — detection asks two questions (``dependencies``, ``iocs``)
and never sees SPARQL, the scope filter or the row builder. Equivalence with
the compiled rules is by REUSE, not by a second implementation: the matching
subjects' triples come back and go through :func:`partitions.rows_from_triples`
and :func:`row_adapters._row_to_rule`, exactly as the compiler did.

Safety:

* untrusted values (what the agent is doing) enter a query only as escaped
  string literals (``sparql_string_literal``, LES-001/002), never as IRIs or
  query text;
* every query names its predicates and carries a LIMIT (LES-013);
* a row counts only when its graph is in the scope, its subject is not
  suppressed and its identifier not revoked;
* a store that failed or timed out gives ``COULD_NOT_TELL`` — hits found
  before the failure are still hits, but the absence of a hit proves nothing;
* every outcome is recorded in :data:`.health.HEALTH`, so a degraded store is
  visible to `blackbox status` and the dashboard, never silent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ...kernel.dkg_client import extract_binding
from ...kernel.sparql_text import sparql_string_literal as literal
from ...kernel.store import StoreClient
from .. import row_adapters
from ..partitions import rows_from_triples
from .health import HEALTH, LookupHealth
from .scope import VerifiedScope

logger = logging.getLogger(__name__)

HIT = "hit"
CLEAN = "clean"
COULD_NOT_TELL = "could-not-tell"

#: Values per query. A 50-value IOC batch answered in 17 ms on the bench.
CHUNK = 200
#: The most values one call looks up — the content scanner's own candidate cap.
MAX_VALUES = 4000
#: Rows per query: candidates × ~15 triples each, with headroom.
ROW_LIMIT = 20_000

_DP = "urn:defender:p:"
_BP = "urn:blackbox:p:"

DependencyCandidate = Tuple[str, str, str]   # (ecosystem, package name, version or "*")


@dataclass(frozen=True)
class LookupAnswer:
    """``rules`` — matched public rules keyed as the compiled dicts were
    (``eco:name@version`` for dependencies, ``ioc:type:value`` for IOCs);
    ``outcome`` — ``HIT`` / ``CLEAN`` / ``COULD_NOT_TELL``; ``reason`` — the
    store's reason when it could not tell."""

    rules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    outcome: str = CLEAN
    reason: str = ""

    @property
    def known(self) -> bool:
        return self.outcome != COULD_NOT_TELL


class VerifiedLookup:
    """Exact lookups for one scope against one store. Stateless; build one per
    ruleset generation (:func:`compiler.Ruleset.live_lookup`)."""

    def __init__(self, scope: VerifiedScope, store: StoreClient, health: Optional[LookupHealth] = None) -> None:
        self.scope = scope
        self.store = store
        self.health = health or HEALTH

    def dependencies(self, candidates: Sequence[DependencyCandidate]) -> LookupAnswer:
        """Public dependency rules for exactly these ``(ecosystem, name, version)``
        triples; pass ``"*"`` as the version for a whole-package rule."""
        tuples: List[Tuple[str, str, str]] = []
        for ecosystem, name, version in candidates[:MAX_VALUES]:
            ecosystem = ecosystem.strip().lower()
            for spelling in self.scope.spellings(ecosystem, name):
                tuples.append((spelling, ecosystem, version.strip()))
        return self._run(tuples, _dependency_sparql, "dependency")

    def iocs(self, identifiers: Sequence[str]) -> LookupAnswer:
        """Public IOC rules among these ``ioc:type:value`` identifiers (already
        normalised by ``threat_ids.ioc_identifier``). The store is asked by
        value; the answer is keyed by the identifier the graph gives the rule."""
        values = list(dict.fromkeys(
            ident.split(":", 2)[2] for ident in identifiers[:MAX_VALUES] if ident.count(":") >= 2
        ))
        return self._run(values, _ioc_sparql, "ioc")

    def _run(self, items: Sequence[Any], build_query: Any, category: str) -> LookupAnswer:
        if not items:
            return LookupAnswer({}, CLEAN)
        answer = self._ask(items, build_query, category)
        self.health.record(answer.known, answer.reason)
        return answer

    def _ask(self, items: Sequence[Any], build_query: Any, category: str) -> LookupAnswer:
        if not self.scope.ready:
            return LookupAnswer({}, COULD_NOT_TELL, "verified scope not ready")
        rules: Dict[str, Dict[str, Any]] = {}
        for start in range(0, len(items), CHUNK):
            answer = self.store.select(build_query(items[start:start + CHUNK]))
            if not answer.known:
                return LookupAnswer(rules, COULD_NOT_TELL, answer.reason)
            rules.update(self._rules_from(answer.rows or [], category))
        return LookupAnswer(rules, HIT if rules else CLEAN)

    def _rules_from(self, rows: Iterable[Dict[str, str]], category: str) -> Dict[str, Dict[str, Any]]:
        """Triples → rules through the compiler's own builders, scope applied."""
        by_graph: Dict[str, List[Tuple[str, str, str]]] = {}
        for row in rows:
            graph = extract_binding(row.get("g"))
            subject = extract_binding(row.get("t"))
            if graph not in self.scope.assertion_graphs or subject in self.scope.suppressed_subjects:
                continue
            by_graph.setdefault(graph, []).append((subject, extract_binding(row.get("p")), row.get("o") or ""))
        rules: Dict[str, Dict[str, Any]] = {}
        for graph, triples in by_graph.items():
            for built_row in rows_from_triples(graph, triples):
                mapped = row_adapters._row_to_rule(built_row, "public")
                if mapped is None or mapped[0] != category:
                    continue
                _category, key, rule = mapped
                if rule.get("identifier") in self.scope.revoked_identifiers:
                    continue
                rules.setdefault(key, rule)
        return rules


def _dependency_sparql(tuples: Sequence[Tuple[str, str, str]]) -> str:
    values = " ".join(f"({literal(pkg)} {literal(eco)} {literal(ver)})" for pkg, eco, ver in tuples)
    return f"""SELECT ?g ?t ?p ?o WHERE {{
  VALUES (?pkg ?eco ?ver) {{ {values} }}
  GRAPH ?g {{
    ?t <{_DP}package> ?pkg ; <{_DP}ecosystem> ?eco ; <{_DP}version> ?ver .
    ?t ?p ?o .
  }}
}} LIMIT {ROW_LIMIT}"""


def _ioc_sparql(values: Sequence[str]) -> str:
    literals = " ".join(literal(value) for value in values)
    return f"""SELECT ?g ?t ?p ?o WHERE {{
  VALUES ?val {{ {literals} }}
  GRAPH ?g {{
    {{ ?t <{_DP}value> ?val . }} UNION {{ ?t <{_BP}normalizedValue> ?val . }}
    ?t ?p ?o .
  }}
}} LIMIT {ROW_LIMIT}"""
