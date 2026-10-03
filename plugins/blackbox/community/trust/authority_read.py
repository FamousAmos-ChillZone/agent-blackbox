"""Reading what the curators have said, from the graphs (Refine R2, Community Curation).

:func:`read_curator_view` builds ONE view per authority — each from its own
pinned roots, its own key manifest and the graph that manifest is bound to —
then combines them (:mod:`.combine`: the most restrictive current word wins).

* VERIFIED authority: roots pinned per network; manifest and enforcement
  statements in the verified graph; advisory statements in the community graph.
* COMMUNITY authority: roots pinned per community graph; manifest and every
  statement in the community graph; flag-only powers (``kernel.signing.authority``).

A FAILED page of manifests or statements marks the view ``unavailable`` so
readers keep their last good stages (KI-228, KI-244); an unreadable page never
raises enforcement.

Usage (through the package): ``view = community.read_curator_view(client, cfg)``.
"""

from __future__ import annotations

import logging
from typing import AbstractSet, Any, Dict, FrozenSet, List, Optional

from ...kernel import constants
from ...kernel.config import BlackboxConfig
from ...kernel.dkg_client import DkgClient
from ...kernel.signing import trust_anchors
from ...kernel.signing.authority import Authority
from ...kernel.sparql_text import page_rows
from ..report_signer import network_environment
from ..statements import curator_statements, curator_view
from . import manifests as manifest_policy
from .combine import combine

logger = logging.getLogger(__name__)


def read_curator_view(client: DkgClient, cfg: BlackboxConfig, environment: str = "") -> curator_view.CuratorView:
    """What the curators have said, verified — both authorities combined
    under the most-restrictive-wins rule (:mod:`.combine`).

    An empty view unless a root is trusted and a root-signed key manifest is
    found: the VERIFIED authority's root is pinned per network and its
    manifest lives in the verified graph; the COMMUNITY authority's root is
    pinned per community graph and its manifest lives in the community graph.
    Fail-open: an unreadable page contributes nothing (no curator statement
    can then raise enforcement); a FAILED page marks the view ``unavailable``
    so readers keep their last good stages."""
    try:
        environment = environment or network_environment(client.status())
    except Exception as exc:  # node unreachable: no curator view this time
        logger.debug("blackbox: curator view skipped (%s)", exc)
        return curator_view.CuratorView()
    verified_roots = trust_anchors.trusted_roots(environment) if environment else frozenset()
    community_roots = _community_roots(cfg) if environment else frozenset()
    if not verified_roots and not community_roots:
        return curator_view.CuratorView()   # no root, no manifest, no curator statement counts
    community_page = _community_statement_rows(client, cfg)
    today = curator_view.today_utc()
    verified = _verified_view(client, cfg, environment, verified_roots, community_page, today)
    community = _community_view(client, cfg, environment, community_roots, community_page, today)
    if community.manifest is None and not community.unavailable and not community.manifest_conflict:
        return verified   # no community authority on this graph: exactly the verified view
    return combine(verified, community, today=today)


def _community_roots(cfg: BlackboxConfig) -> FrozenSet[str]:
    """The community roots for this node's community graph — none when the
    community graph is also configured as the verified graph (the two
    authorities must never share a graph)."""
    graph = cfg.community_graph_id
    if not graph or graph == cfg.context_graph_id:
        return frozenset()
    return trust_anchors.community_roots(graph)


def _community_statement_rows(client: DkgClient, cfg: BlackboxConfig) -> Optional[List[Dict[str, Any]]]:
    """Curator statements in the community graph (None: not configured, or the page failed)."""
    if not cfg.community_graph_id:
        return None
    return page_rows(client, cfg.community_graph_id, constants.VIEW_SHARED_WORKING_MEMORY,
                     curator_statements.curator_statements_sparql)


def _verified_view(client: DkgClient, cfg: BlackboxConfig, environment: str, roots: AbstractSet[str],
                   community_page: Optional[List[Dict[str, Any]]], today: str) -> curator_view.CuratorView:
    """The VERIFIED authority's view: manifest + enforcement statements from the
    verified graph, its advisory statements from the community graph."""
    if not roots:
        return curator_view.CuratorView()
    verified, memory = cfg.context_graph_id, constants.VIEW_VERIFIABLE_MEMORY
    manifest_rows = page_rows(client, verified, memory, manifest_policy.key_manifests_sparql)
    if manifest_rows is None:   # KI-228: a FAILED page is not an empty one
        return curator_view.CuratorView(unavailable=True)
    manifests = manifest_policy.trusted_manifests(manifest_rows, environment, verified, roots)
    manifest = manifest_policy.effective_manifest(manifests, today)   # R7b time-lock; round 4: dated beats undated, conflicts freeze
    conflict = manifest_policy.manifests_conflict(manifests)   # R10b SECURITY alarm
    if manifest is None:
        return curator_view.CuratorView(manifest_conflict=conflict)
    verified_rows = page_rows(client, verified, memory, curator_statements.curator_statements_sparql)
    if verified_rows is None:   # KI-228: enforcement statements live here; a failed page must freeze, not erase
        return curator_view.CuratorView(manifest=manifest, manifest_conflict=conflict, unavailable=True)
    return curator_view.build_view(manifest, verified_rows,
                                   community_page or [], verified_graph=verified, community_graph=cfg.community_graph_id,
                                   manifest_conflict=conflict, root_keys=roots,
                                   community_readable=community_page is not None)


def _community_view(client: DkgClient, cfg: BlackboxConfig, environment: str, roots: AbstractSet[str],
                    community_page: Optional[List[Dict[str, Any]]], today: str) -> curator_view.CuratorView:
    """The COMMUNITY authority's view: its manifest and every statement it may
    make, all from the community graph, verified against the roots pinned for
    THIS community graph only."""
    graph = cfg.community_graph_id
    if not roots:
        return curator_view.CuratorView(authority=Authority.COMMUNITY)
    manifest_rows = page_rows(client, graph, constants.VIEW_SHARED_WORKING_MEMORY, manifest_policy.key_manifests_sparql)
    if manifest_rows is None or community_page is None:   # KI-244: a failed community page freezes, never erases
        return curator_view.CuratorView(authority=Authority.COMMUNITY, unavailable=True)
    manifests = manifest_policy.trusted_manifests(manifest_rows, environment, graph, roots)
    manifest = manifest_policy.effective_manifest(manifests, today)
    conflict = manifest_policy.manifests_conflict(manifests)
    if manifest is None:
        return curator_view.CuratorView(authority=Authority.COMMUNITY, manifest_conflict=conflict)
    return curator_view.build_view(manifest, [], community_page, verified_graph=cfg.context_graph_id,
                                   community_graph=graph, today=today, manifest_conflict=conflict, root_keys=roots,
                                   community_readable=True, authority=Authority.COMMUNITY)
