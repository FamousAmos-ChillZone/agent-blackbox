"""Per-asset facts — counts and package spellings — read ONCE per verified asset.

WHY: the refresh used to count the live tiers and scan for odd package spellings
over the WHOLE store every time (7–20 s of full scans). The node's store is shared
with the DKG node itself, whose supervisor restarts Oxigraph when one of the node's
own queries misses its deadline — and a Blackbox scan on a busy 2-vCPU node can
cause exactly that (bench A 05:15 / C 04:19 UTC, 2026-10-10). A confirmed asset is
anchored on chain and never changes, so its facts are read once, in small batches
bound to named graphs (index lookups, not scans), with a pause between queries so
the node's own queries interleave, and carried forward forever after. After the
first sync a refresh reads nothing here.

Pattern: Cache-aside over immutable keys (the asset IRI). Usage::

    facts = read_new_asset_facts(store, wanted=scope_graphs, known=previous_facts)
    counts, aliases = totals(facts, scope_graphs)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from ...kernel import threat_ids
from ...kernel.dkg_client import extract_binding
from ...kernel.store import StoreClient

logger = logging.getLogger(__name__)

#: Assets per query: VALUES-bound graphs keep each query an index lookup.
BATCH = 20
#: Seconds each query may take, and the pause between queries (the node's own
#: queries run in the gaps).
QUERY_TIMEOUT_SECONDS = 20.0
PAUSE_SECONDS = 0.2
#: Total seconds one refresh spends here; the rest waits for the next refresh.
BUDGET_SECONDS = 120.0

_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
_DP = "urn:defender:p:"
_BP = "urn:blackbox:p:"
#: Key prefix of the per-ecosystem dependency counts (``"dependency:npm"``).
ECOSYSTEM_COUNT_PREFIX = "dependency:"


@dataclass(frozen=True)
class AssetFacts:
    """One asset's facts. ``counts`` — rules by tier (``dependency``, ``ioc``) and
    dependency rules per ecosystem (``dependency:<eco>``); ``aliases`` —
    ``"eco:canonical"`` → stored spellings that differ from the canonical one."""

    counts: Mapping[str, int] = field(default_factory=dict)
    aliases: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {"counts": dict(self.counts), "aliases": {k: list(v) for k, v in self.aliases.items()}}

    @classmethod
    def from_json(cls, data: Any) -> Optional["AssetFacts"]:
        if not isinstance(data, dict):
            return None
        counts, aliases = data.get("counts"), data.get("aliases")
        return cls(
            counts={str(k): int(v) for k, v in counts.items() if isinstance(v, (int, float))}
            if isinstance(counts, dict) else {},
            aliases={str(k): tuple(str(x) for x in v) for k, v in aliases.items() if isinstance(v, list)}
            if isinstance(aliases, dict) else {},
        )


def read_new_asset_facts(store: StoreClient, *, wanted: FrozenSet[str], known: Mapping[str, AssetFacts],
                         budget_seconds: float = BUDGET_SECONDS) -> Dict[str, AssetFacts]:
    """*known* facts for the assets still wanted, plus facts read now for the wanted
    assets not known yet — in batches, within the budget, stopping at the first
    query the store could not answer (the rest are read on a later refresh)."""
    facts = {graph: fact for graph, fact in known.items() if graph in wanted}
    missing = sorted(graph for graph in wanted if graph not in facts)
    deadline = time.monotonic() + budget_seconds
    for start in range(0, len(missing), BATCH):
        if time.monotonic() >= deadline:
            logger.info("blackbox: verified asset facts — %d asset(s) wait for the next refresh", len(missing) - start)
            break
        batch = missing[start:start + BATCH]
        read = _read_batch(store, batch)
        if read is None:
            break
        facts.update(read)
    return facts


def totals(facts: Mapping[str, AssetFacts], graphs: Iterable[str]) -> Tuple[Dict[str, int], Dict[str, Tuple[str, ...]]]:
    """Counts summed and aliases merged over *graphs* (assets without facts add nothing)."""
    counts: Dict[str, int] = {}
    aliases: Dict[str, set] = {}
    for graph in graphs:
        fact = facts.get(graph)
        if fact is None:
            continue
        for key, value in fact.counts.items():
            counts[key] = counts.get(key, 0) + int(value)
        for key, spellings in fact.aliases.items():
            aliases.setdefault(key, set()).update(spellings)
    return counts, {key: tuple(sorted(values)) for key, values in aliases.items()}


def _values(batch: List[str]) -> str:
    return " ".join(f"<{graph}>" for graph in batch)


def _queries(batch: List[str]) -> List[Tuple[str, str]]:
    """(kind, SPARQL) for one batch: three tier counts, the ecosystem split, the spellings."""
    values = _values(batch)
    def count(pattern: str) -> str:
        return f"SELECT ?g (COUNT(DISTINCT ?t) AS ?n) WHERE {{ VALUES ?g {{ {values} }} GRAPH ?g {{ {pattern} }} }} GROUP BY ?g"
    return [
        ("dependency", count(f"?t <{_TYPE}> <urn:defender:DependencySignal> .")),
        ("ioc", count(f"?t <{_TYPE}> <urn:defender:IocSignal> .")),
        ("ioc", count(f'?t <{_TYPE}> <urn:blackbox:SourceObservation> ; <{_BP}lifecycleStatus> "active" .')),
        ("ecosystem", f"SELECT ?g ?eco (COUNT(?t) AS ?n) WHERE {{ VALUES ?g {{ {values} }} GRAPH ?g {{ "
                      f"?t <{_TYPE}> <urn:defender:DependencySignal> ; <{_DP}ecosystem> ?eco . }} }} GROUP BY ?g ?eco"),
        ("aliases", f"SELECT DISTINCT ?g ?eco ?pkg WHERE {{ VALUES ?g {{ {values} }} GRAPH ?g {{ "
                    f"?t <{_DP}package> ?pkg ; <{_DP}ecosystem> ?eco . }} "
                    f'FILTER(?pkg != LCASE(?pkg) || (?eco = "pypi" && (CONTAINS(?pkg, "_") || CONTAINS(?pkg, ".")))) }} '
                    f"LIMIT 50000"),
    ]


def _read_batch(store: StoreClient, batch: List[str]) -> Optional[Dict[str, AssetFacts]]:
    counts: Dict[str, Dict[str, int]] = {graph: {"dependency": 0, "ioc": 0} for graph in batch}
    aliases: Dict[str, Dict[str, set]] = {graph: {} for graph in batch}
    for kind, sparql in _queries(batch):
        answer = store.select(sparql, timeout=QUERY_TIMEOUT_SECONDS)
        time.sleep(PAUSE_SECONDS)
        if not answer.known:
            logger.warning("blackbox: verified asset facts not read (%s); retrying next refresh", answer.reason)
            return None
        for row in answer.rows or []:
            graph = extract_binding(row.get("g"))
            if graph not in counts:
                continue
            if kind == "aliases":
                ecosystem = extract_binding(row.get("eco")).strip().lower()
                stored = extract_binding(row.get("pkg"))
                canonical = threat_ids.canonical_package_name(ecosystem, stored)
                if ecosystem and stored and stored != canonical:
                    aliases[graph].setdefault(f"{ecosystem}:{canonical}", set()).add(stored)
                continue
            key = ECOSYSTEM_COUNT_PREFIX + extract_binding(row.get("eco")).strip().lower() if kind == "ecosystem" else kind
            counts[graph][key] = counts[graph].get(key, 0) + _int(row.get("n"))
    return {graph: AssetFacts(counts=counts[graph],
                              aliases={k: tuple(sorted(v)) for k, v in aliases[graph].items()}) for graph in batch}


def _int(cell: Any) -> int:
    try:
        return int(float(extract_binding(cell) or 0))
    except ValueError:
        return 0
