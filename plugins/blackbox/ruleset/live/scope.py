"""The verified scope: what a live lookup is allowed to believe.

A lookup against the store sees every named graph the node holds — the open
community graph, foreign owners' assets, tentative assets not yet confirmed.
Only rows from Umanitek's confirmed assets may become public (blockable)
rules, so the KI-106 owner pin lives here as a SET the lookup checks in O(1)
instead of a per-lookup join (which cost 0.5–3 s on the bench).

Pattern: Memento — one frozen snapshot per refresh, persisted inside
``ruleset.json`` and handed to every process; rebuilt by :func:`refresh_scope`.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Sequence, Tuple

from ...kernel import threat_ids
from ...kernel.dkg_client import DkgClient, DkgError, extract_binding
from ...kernel.store import StoreClient, loopback_store_url
from .. import fetching

logger = logging.getLogger(__name__)

#: The alias read is a refresh-time scan over every package literal, not a
#: hot-path lookup: it took 7.9 s on a node busy downloading the graph.
ALIAS_READ_TIMEOUT_SECONDS = 60.0
#: The three aggregate counts are GROUP BY summaries (LES-013); 0.4 s on the bench.
COUNT_READ_TIMEOUT_SECONDS = 60.0
#: Bounded by construction (LES-013): 117 aliases exist today.
ALIAS_READ_LIMIT = 50_000

_DP = "urn:defender:p:"
_BP = "urn:blackbox:p:"
_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"


@dataclass(frozen=True)
class VerifiedScope:
    """One refresh's view of the verified graph, for the lookup to filter by.

    ``store_url`` — the node's local store endpoint (loopback only; empty when
    the node did not report one). ``assertion_graphs`` — the confirmed,
    owner-pinned VM assertion graphs: a row from any other graph is ignored.
    ``suppressed_subjects`` — threats a public CorrectionSignal withdrew.
    ``revoked_identifiers`` — rules the curator revoked (reduction: always applies).
    ``package_aliases`` — ``"eco:canonical-name"`` → the spellings the graph
    actually stores (117 npm names carry capitals; the compiler lowercased
    them, so the lookup must ask for every spelling). ``verified_counts`` — rules
    per live tier (``dependency``, ``ioc``) for status, health and the dashboard.
    ``built_at`` — epoch seconds.
    """

    context_graph_id: str = ""
    store_url: str = ""
    assertion_graphs: FrozenSet[str] = frozenset()
    suppressed_subjects: FrozenSet[str] = frozenset()
    revoked_identifiers: FrozenSet[str] = frozenset()
    package_aliases: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    #: How many verified rules the live tiers hold (``dependency``, ``ioc``) — the
    #: counts the compile used to produce, now three aggregate queries per refresh.
    verified_counts: Mapping[str, int] = field(default_factory=dict)
    built_at: float = 0.0

    @property
    def ready(self) -> bool:
        """True when lookups can run: a store to ask and assets to trust."""
        return bool(self.store_url and self.assertion_graphs)

    def spellings(self, ecosystem: str, name: str) -> Tuple[str, ...]:
        """Every spelling of *name* the graph may store: the canonical one plus
        the aliases recorded for it."""
        canonical = threat_ids.canonical_package_name(ecosystem, name)
        return (canonical, *self.package_aliases.get(f"{ecosystem.strip().lower()}:{canonical}", ()))

    def to_json(self) -> Dict[str, Any]:
        return {
            "context_graph_id": self.context_graph_id,
            "store_url": self.store_url,
            "assertion_graphs": sorted(self.assertion_graphs),
            "suppressed_subjects": sorted(self.suppressed_subjects),
            "revoked_identifiers": sorted(self.revoked_identifiers),
            "package_aliases": {key: list(values) for key, values in sorted(self.package_aliases.items())},
            "verified_counts": dict(self.verified_counts),
            "built_at": self.built_at,
        }

    @classmethod
    def from_json(cls, data: Any) -> "VerifiedScope":
        """A scope from :meth:`to_json` output; anything malformed is an empty scope."""
        if not isinstance(data, dict):
            return cls()
        aliases = data.get("package_aliases")
        return cls(
            context_graph_id=str(data.get("context_graph_id") or ""),
            store_url=str(data.get("store_url") or ""),
            assertion_graphs=_strings(data.get("assertion_graphs")),
            suppressed_subjects=_strings(data.get("suppressed_subjects")),
            revoked_identifiers=_strings(data.get("revoked_identifiers")),
            package_aliases={str(k): tuple(str(v) for v in vs) for k, vs in aliases.items()
                             if isinstance(vs, list)} if isinstance(aliases, dict) else {},
            verified_counts={str(k): int(v) for k, v in counts.items() if isinstance(v, (int, float))}
            if isinstance(counts := data.get("verified_counts"), dict) else {},
            built_at=float(data.get("built_at") or 0.0),
        )


def _strings(value: Any) -> FrozenSet[str]:
    return frozenset(str(item) for item in value) if isinstance(value, list) else frozenset()


def refresh_scope(
    client: DkgClient,
    context_graph_id: str,
    *,
    previous: Optional[VerifiedScope],
    confirmed: Optional[Sequence[str]],
    suppressed: Optional[Iterable[str]],
    revoked: Iterable[str],
    store: Optional[StoreClient] = None,
) -> VerifiedScope:
    """The next scope. Every part that could not be read this time keeps the
    previous scope's value (fail-open, but never "could not read" → "nothing").

    *confirmed* / *suppressed* are None when the refresh could not read them
    (a last-good generation being reused); *revoked* always applies.
    """
    previous = previous or VerifiedScope()
    store_url = _store_url(client) or previous.store_url
    graphs = frozenset(confirmed) if confirmed is not None else previous.assertion_graphs
    aliases, counts = previous.package_aliases, previous.verified_counts
    if store_url and graphs:
        store = store or StoreClient(store_url)
        read = _read_aliases(store, graphs)
        if read is not None:
            aliases = read
        counted = _read_counts(store, graphs)
        if counted is not None:
            counts = counted
    return VerifiedScope(
        context_graph_id=context_graph_id,
        store_url=store_url,
        assertion_graphs=graphs,
        suppressed_subjects=frozenset(suppressed) if suppressed is not None else previous.suppressed_subjects,
        revoked_identifiers=frozenset(revoked),
        package_aliases=aliases,
        verified_counts=counts,
        built_at=time.time(),
    )


def _store_url(client: DkgClient) -> str:
    try:
        return loopback_store_url(client.status(timeout=5.0))
    except DkgError as exc:
        logger.debug("blackbox: node status unavailable for the store endpoint: %s", exc)
        return ""


def _aliases_sparql() -> str:
    """Package names whose stored spelling differs from the canonical one:
    capitals anywhere, or ``_`` / ``.`` in a PyPI name (PEP 503 collapses them)."""
    return f"""SELECT DISTINCT ?g ?eco ?pkg WHERE {{
  GRAPH ?g {{ ?t <{_DP}package> ?pkg ; <{_DP}ecosystem> ?eco . }}
  FILTER(?pkg != LCASE(?pkg) || (?eco = "pypi" && (CONTAINS(?pkg, "_") || CONTAINS(?pkg, "."))))
}} LIMIT {ALIAS_READ_LIMIT}"""


def _read_aliases(store: StoreClient, graphs: FrozenSet[str]) -> Optional[Dict[str, Tuple[str, ...]]]:
    """``"eco:canonical"`` → stored spellings, from the scope's graphs only; None
    when the store could not be asked (the caller keeps the previous aliases)."""
    answer = store.select(_aliases_sparql(), timeout=ALIAS_READ_TIMEOUT_SECONDS)
    if not answer.known:
        logger.warning("blackbox: package aliases not refreshed (%s); keeping the previous ones", answer.reason)
        return None
    found: Dict[str, set] = {}
    for row in answer.rows or []:
        if extract_binding(row.get("g")) not in graphs:
            continue
        ecosystem = extract_binding(row.get("eco")).strip().lower()
        stored = extract_binding(row.get("pkg"))
        canonical = threat_ids.canonical_package_name(ecosystem, stored)
        if ecosystem and stored and stored != canonical:
            found.setdefault(f"{ecosystem}:{canonical}", set()).add(stored)
    return {key: tuple(sorted(values)) for key, values in found.items()}


def scope_for_generation(
    client: DkgClient,
    context_graph_id: str,
    *,
    previous: Optional[VerifiedScope],
    suppressed: Optional[Iterable[str]],
    revoked: Iterable[str],
    listing: Optional[fetching.PartitionListing] = None,
) -> Optional[VerifiedScope]:
    """:func:`refresh_scope` fed by the node's partition listing (*listing* when
    the refresh already read it, else read now) — what the refresh cycle calls
    on every path. Fail-open: when anything raises, the previous scope stays
    (a scope problem never costs the generation)."""
    try:
        listing = listing or fetching.confirmed_partitions(client, context_graph_id)
        return refresh_scope(
            client, context_graph_id, previous=previous,
            confirmed=listing.confirmed if listing is not None else None,
            suppressed=suppressed, revoked=revoked,
        )
    except Exception as exc:  # pragma: no cover - fail open (an outer boundary)
        logger.warning("blackbox: verified scope not refreshed: %s", exc)
        return previous


#: The live tiers and the triple pattern that counts one rule of each.
_COUNTED_TIERS = (
    ("dependency", f"?t <{_TYPE}> <urn:defender:DependencySignal> ."),
    ("ioc", f"?t <{_TYPE}> <urn:defender:IocSignal> ."),
    ("ioc", f'?t <{_TYPE}> <urn:blackbox:SourceObservation> ; <{_BP}lifecycleStatus> "active" .'),
)


def _count_sparql(pattern: str) -> str:
    return f"SELECT ?g (COUNT(DISTINCT ?t) AS ?n) WHERE {{ GRAPH ?g {{ {pattern} }} }} GROUP BY ?g"


def _read_counts(store: StoreClient, graphs: FrozenSet[str]) -> Optional[Dict[str, int]]:
    """Verified rules per live tier, summed over the scope's graphs only (an IOC
    is an IocSignal or an ACTIVE SourceObservation, as the compile counted them);
    None when any count could not be read (the caller keeps the previous counts)."""
    counts: Dict[str, int] = {"dependency": 0, "ioc": 0}
    for tier, pattern in _COUNTED_TIERS:
        answer = store.select(_count_sparql(pattern), timeout=COUNT_READ_TIMEOUT_SECONDS)
        if not answer.known:
            logger.warning("blackbox: verified %s count not refreshed (%s); keeping the previous one", tier, answer.reason)
            return None
        for row in answer.rows or []:
            if extract_binding(row.get("g")) in graphs:
                try:
                    counts[tier] += int(float(extract_binding(row.get("n")) or 0))
                except ValueError:
                    continue
    return counts
