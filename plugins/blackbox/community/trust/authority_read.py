"""Reading what the curators have said, from the graphs (Refine R2, Community Curation).

:func:`read_curator_view` builds ONE view per authority — each from its own
pinned roots, its own key manifest and the graph that manifest is bound to —
then combines them (:mod:`.combine`: the most restrictive current word wins).

* VERIFIED authority: roots pinned per network; manifest and enforcement
  statements in the verified graph (one writer, read by scan as before); its
  advisory statements in the community graph.
* COMMUNITY authority: roots pinned per community graph; manifest and every
  statement in the community graph; flag-only powers (``kernel.signing.authority``).

Everything read from the COMMUNITY graph goes through two defences, because
anyone can write there (:mod:`.bounded_read`, :mod:`.trust_store`):

* statements are looked up by the identifiers the caller is interested in
  (*interest*: the reporters and threats it holds), never scanned;
* the view is built from the node's own stored, re-verified copy PLUS whatever
  the lookup returned, and the verified result is stored again. A lookup that
  fails, times out or is flooded therefore changes nothing: trust only moves
  forward by verified statements. Only when nothing is stored AND the lookup
  could not be completed is the view ``unavailable`` (readers keep last good);
* the community authority's enforcement-RAISING statements pass this reader's
  daily cap (:mod:`.raising_budget`): a burst is admitted at the daily rate,
  reductions at once.

Usage (through the package)::

    view = community.read_curator_view(client, cfg, interest={"author:<key>", "ioc:ip:203.0.113.7"})
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import AbstractSet, Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from ...kernel import constants, signing
from ...kernel.config import BlackboxConfig
from ...kernel.dkg_client import DkgClient
from ...kernel.signing import key_manifest, trust_anchors
from ...kernel.signing.authority import Authority, allowed_kinds
from ...kernel.sparql_text import page_rows
from ..report_signer import network_environment
from ..statements import curator_statements, curator_view
from . import bounded_read, raising_budget, trust_store
from . import manifests as manifest_policy
from .combine import combine

logger = logging.getLogger(__name__)

Row = Mapping[str, Any]


@dataclass(frozen=True)
class _Resolved:
    """One authority as resolved for this read: its trusted ``roots``, the
    ``manifest`` readers act on (None: no curator statement of this authority
    counts), whether two trusted manifests ``conflict``, whether the manifest
    could not be read (``unavailable``), the authority's statements from the
    VERIFIED graph (``enforcement_rows`` — the verified authority only) and
    the trusted manifest rows worth storing (the community authority only)."""

    authority: Authority
    roots: FrozenSet[str] = frozenset()
    manifest: Optional[key_manifest.KeyManifest] = None
    conflict: bool = False
    unavailable: bool = False
    enforcement_rows: Tuple[Row, ...] = ()
    manifest_rows: Tuple[Dict[str, str], ...] = ()


def read_curator_view(client: DkgClient, cfg: BlackboxConfig, environment: str = "", *,
                      interest: Iterable[str] = ()) -> curator_view.CuratorView:
    """What the curators have said, verified — both authorities combined under
    the most-restrictive-wins rule (:mod:`.combine`).

    *interest* — the identifiers the caller needs statements about
    (``author:<reporter key>`` and threat identifiers, most important first);
    the ``curator`` notices and everything already stored are always included.

    An empty view unless a root is trusted and a root-signed key manifest is
    found. Fail-open: an unreadable read contributes nothing that could raise
    enforcement, and never removes what this node already verified."""
    try:
        environment = environment or network_environment(client.status())
    except Exception as exc:  # node unreachable: no curator view this time
        logger.debug("blackbox: curator view skipped (%s)", exc)
        return curator_view.CuratorView()
    verified_roots = trust_anchors.trusted_roots(environment) if environment else frozenset()
    community_roots = _community_roots(cfg) if environment else frozenset()
    if not verified_roots and not community_roots:
        return curator_view.CuratorView()   # no root, no manifest, no curator statement counts
    today = curator_view.today_utc()
    graph = cfg.community_graph_id
    store = trust_store.TrustStore()
    stored = store.load(graph) if graph else trust_store.StoredTrust()
    statements, readable, complete = _community_statements(client, graph, stored, interest)
    verified = _resolve_verified(client, cfg, environment, verified_roots, today)
    community = _resolve_community(client, cfg, environment, community_roots, stored, today)
    kept, community_keys = _verifiable(statements, verified, community, graph)
    admission = raising_budget.admit([row for row in kept if trust_store.statement_key(row) in community_keys],
                                     stored.admitted, first_read=stored.baseline_until is None, today=today)
    if graph:
        store.remember(graph, community.manifest_rows, kept, admitted=admission.admitted)
    verified_view = _view(verified, statements, readable, cfg, today)
    acted_on = [row for row in statements if trust_store.statement_key(row) not in admission.held]
    community_view = replace(_view(community, acted_on, readable, cfg, today), held_raising=len(admission.held),
                             lookup_incomplete=not complete)
    if community_view.manifest is None and not community_view.unavailable and not community_view.manifest_conflict:
        return verified_view   # no community authority on this graph: exactly the verified view
    return combine(verified_view, community_view, today=today)


def _community_roots(cfg: BlackboxConfig) -> FrozenSet[str]:
    """The community roots for this node's community graph — none when the
    community graph is also configured as the verified graph (the two
    authorities must never share a graph)."""
    graph = cfg.community_graph_id
    if not graph or graph == cfg.context_graph_id:
        return frozenset()
    return trust_anchors.community_roots(graph)


def _community_statements(client: DkgClient, graph: str, stored: trust_store.StoredTrust,
                          interest: Iterable[str]) -> Tuple[List[Dict[str, str]], bool, bool]:
    """(candidate statement rows, readable, complete): this node's stored
    statements plus an exact lookup of *interest*. ``readable`` is False only
    when the lookup could not be completed AND nothing is stored — the one case
    where this node knows nothing about what the curators said in the
    community graph. ``complete`` is False whenever the lookup was cut short."""
    if not graph:
        return [], False, True
    wanted = [bounded_read.CURATOR_IDENTIFIER, *interest, *stored.identifiers]
    found = bounded_read.lookup_statements(client, graph, wanted)
    if not found.complete:
        logger.warning("blackbox: community trust lookup incomplete (%d batch(es) failed, %d reached the row limit) — "
                       "keeping the statements this node already verified", found.failed, found.limited)
    rows = bounded_read.fold([*stored.statements, *found.rows])
    return rows, found.complete or bool(stored.statements), found.complete


def _resolve_verified(client: DkgClient, cfg: BlackboxConfig, environment: str, roots: FrozenSet[str],
                      today: str) -> _Resolved:
    """The VERIFIED authority: its manifest and enforcement statements, both
    from the verified graph (one writer, so it is read by scan as before)."""
    if not roots:
        return _Resolved(Authority.VERIFIED)
    verified, memory = cfg.context_graph_id, constants.VIEW_VERIFIABLE_MEMORY
    manifest_rows = page_rows(client, verified, memory, manifest_policy.key_manifests_sparql)
    if manifest_rows is None:   # KI-228: a FAILED page is not an empty one
        return _Resolved(Authority.VERIFIED, roots, unavailable=True)
    manifests = manifest_policy.trusted_manifests(manifest_rows, environment, verified, roots)
    manifest = manifest_policy.effective_manifest(manifests, today)   # R7b time-lock; round 4: dated beats undated, conflicts freeze
    conflict = manifest_policy.manifests_conflict(manifests)   # R10b SECURITY alarm
    if manifest is None:
        return _Resolved(Authority.VERIFIED, roots, conflict=conflict)
    rows = page_rows(client, verified, memory, curator_statements.curator_statements_sparql)
    if rows is None:   # KI-228: enforcement statements live here; a failed page must freeze, not erase
        return _Resolved(Authority.VERIFIED, roots, manifest, conflict, unavailable=True)
    return _Resolved(Authority.VERIFIED, roots, manifest, conflict, enforcement_rows=tuple(rows))


def _resolve_community(client: DkgClient, cfg: BlackboxConfig, environment: str, roots: FrozenSet[str],
                       stored: trust_store.StoredTrust, today: str) -> _Resolved:
    """The COMMUNITY authority: its manifest from the community graph (stored
    copies plus a lookup), verified against the roots pinned for THIS graph."""
    graph = cfg.community_graph_id
    if not roots:
        return _Resolved(Authority.COMMUNITY)
    found = bounded_read.lookup_manifests(client, graph, trust_store.manifest_orders(stored.manifests))
    rows = bounded_read.fold([*stored.manifests, *found.rows])
    manifests = manifest_policy.trusted_manifests(rows, environment, graph, roots)
    manifest = manifest_policy.effective_manifest(manifests, today)
    # Nothing trusted known is "no community authority" only when the lookup was
    # complete; otherwise this node simply could not look (KI-241, KI-244).
    return _Resolved(Authority.COMMUNITY, roots, manifest, manifest_policy.manifests_conflict(manifests),
                     unavailable=manifest is None and not found.complete,
                     manifest_rows=tuple(_trusted_manifest_rows(rows, environment, graph, roots)))


def _view(resolved: _Resolved, statements: Sequence[Row], readable: bool, cfg: BlackboxConfig,
          today: str) -> curator_view.CuratorView:
    """One authority's view from its resolved manifest and the community-graph
    *statements*. With a manifest but nothing known about the community graph's
    statements, the view is unavailable: unknown is not "they said nothing"."""
    if resolved.manifest is None or resolved.unavailable:
        return curator_view.CuratorView(authority=resolved.authority, manifest=resolved.manifest,
                                        manifest_conflict=resolved.conflict, unavailable=resolved.unavailable)
    if cfg.community_graph_id and not readable:   # KI-244
        return curator_view.CuratorView(authority=resolved.authority, manifest=resolved.manifest,
                                        manifest_conflict=resolved.conflict, unavailable=True)
    return curator_view.build_view(resolved.manifest, resolved.enforcement_rows, statements,
                                   verified_graph=cfg.context_graph_id, community_graph=cfg.community_graph_id,
                                   today=today, manifest_conflict=resolved.conflict, root_keys=resolved.roots,
                                   community_readable=readable, authority=resolved.authority)


def _trusted_manifest_rows(rows: Iterable[Row], environment: str, graph: str, roots: AbstractSet[str]) -> List[Dict[str, str]]:
    """The manifest rows a trusted root signed for this network and graph (worth storing)."""
    kept = []
    for row in rows:
        envelope = signing.from_text(str(row.get(curator_statements.SIGNED_STATEMENT_VAR, "")))
        if key_manifest.verify_manifest(envelope, environment=environment, graph=graph, root_keys=roots) is not None:
            kept.append({"r": str(row.get("r", "")), "identifier": "", "signedStatement": str(row.get("signedStatement", ""))})
    return kept


def _verifiable(statements: Iterable[Row], verified: _Resolved, community: _Resolved,
                graph: str) -> Tuple[List[Row], Set[str]]:
    """(the statement rows worth storing, the keys of those the COMMUNITY
    authority signed). A row is kept when it verifies under either authority's
    manifest for a kind that authority may publish in the community graph. A
    root-alone reduction counts as verifiable here; whether it is HONOURED is
    decided on every read, by the curators' silence. ONE row is kept per
    signed statement however many copies of it the graph holds (KI-266): of the
    copies that verified, the one with the fewest signatures (anyone can add a
    signature of their own to a genuine statement), then the smallest text."""
    kept: Dict[str, Row] = {}
    community_keys: Set[str] = set()
    for row in statements:
        for resolved in (verified, community):
            if resolved.manifest is None:
                continue
            record = curator_statements.parse_statement(row, resolved.manifest, graph=graph, root_keys=resolved.roots,
                                                        curators_silent=True)
            if record is not None and record.kind in allowed_kinds(resolved.authority, in_verified_graph=False):
                key = trust_store.statement_key(row)
                if key not in kept or _copy_rank(row) < _copy_rank(kept[key]):
                    kept[key] = row
                if resolved.authority is Authority.COMMUNITY:
                    community_keys.add(key)
                break
    return list(kept.values()), community_keys


def _copy_rank(row: Row) -> Tuple[int, str]:
    """Which of several verified copies of one statement is kept — lower wins."""
    text = str(row.get("signedStatement", ""))
    return text.count('"signer":'), text


def known_curator_statements(client: DkgClient, cfg: BlackboxConfig, identifiers: Iterable[str], *,
                             verified_graph: bool = False) -> List[Tuple[str, Dict[str, str]]]:
    """``(graph id, row)`` for every curator statement about *identifiers* this
    node can find: its stored copies and an exact lookup in the community
    graph, plus (with *verified_graph*) the verified graph's statements. Rows
    are UNVERIFIED candidates — the caller checks signatures. Used by the
    curators' tooling to continue sequence numbers where the last statement
    left off, whichever kind it was and whichever machine published it."""
    wanted = {identifier for identifier in identifiers if identifier}
    found: List[Tuple[str, Dict[str, str]]] = []
    graph = cfg.community_graph_id
    if graph:
        stored = trust_store.TrustStore().load(graph).statements
        looked_up = bounded_read.lookup_statements(client, graph, sorted(wanted)).rows
        found.extend((graph, row) for row in bounded_read.fold([*stored, *looked_up]) if row.get("identifier") in wanted)
    if verified_graph:
        rows = page_rows(client, cfg.context_graph_id, constants.VIEW_VERIFIABLE_MEMORY,
                         curator_statements.curator_statements_sparql) or []
        found.extend((cfg.context_graph_id, row) for row in bounded_read.fold(rows) if row.get("identifier") in wanted)
    return found
