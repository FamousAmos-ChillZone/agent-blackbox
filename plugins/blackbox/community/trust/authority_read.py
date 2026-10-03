"""Reading what the curator has said, from the graphs (Refine R2).

:func:`read_curator_view` resolves the trusted roots for this network, reads
the key manifests and the curator statements, and returns ONE verified
:class:`~..statements.curator_view.CuratorView`. Fail-open: an unreadable page
contributes nothing that could raise enforcement; a FAILED page of manifests
or verified-graph statements marks the view ``unavailable`` so readers keep
their last good stages (KI-228).

Usage (through the package): ``view = community.read_curator_view(client, cfg)``.
"""

from __future__ import annotations

import logging

from ...kernel import constants
from ...kernel.config import BlackboxConfig
from ...kernel.dkg_client import DkgClient
from ...kernel.signing import trust_anchors
from ...kernel.sparql_text import page_rows
from ..report_signer import network_environment
from ..statements import curator_statements, curator_view
from . import manifests as manifest_policy

logger = logging.getLogger(__name__)


def read_curator_view(client: DkgClient, cfg: BlackboxConfig, environment: str = "") -> curator_view.CuratorView:
    """What the curator has said, verified (Refine R2): an empty view unless
    this network trusts a curator root and a root-signed key manifest is in
    the verified graph. Fail-open: an unreadable page contributes nothing
    (no curator statement can then raise enforcement)."""
    try:
        environment = environment or network_environment(client.status())
    except Exception as exc:  # node unreachable: no curator view this time
        logger.debug("blackbox: curator view skipped (%s)", exc)
        return curator_view.CuratorView()
    roots = trust_anchors.trusted_roots(environment)
    if not environment or not roots:
        return curator_view.CuratorView()
    verified, memory = cfg.context_graph_id, constants.VIEW_VERIFIABLE_MEMORY
    manifest_rows = page_rows(client, verified, memory, manifest_policy.key_manifests_sparql)
    if manifest_rows is None:   # KI-228: a FAILED page is not an empty one
        return curator_view.CuratorView(unavailable=True)
    manifests = manifest_policy.trusted_manifests(manifest_rows, environment, verified, roots)
    today = curator_view.today_utc()
    manifest = manifest_policy.effective_manifest(manifests, today)   # R7b time-lock; round 4: dated beats undated, conflicts freeze
    conflict = manifest_policy.manifests_conflict(manifests)   # R10b SECURITY alarm
    if manifest is None:
        return curator_view.CuratorView(manifest_conflict=conflict)
    community_page = page_rows(client, cfg.community_graph_id, constants.VIEW_SHARED_WORKING_MEMORY, curator_statements.curator_statements_sparql) if cfg.community_graph_id else None
    community_rows = community_page or []
    verified_rows = page_rows(client, verified, memory, curator_statements.curator_statements_sparql)
    if verified_rows is None:   # KI-228: enforcement statements live here; a failed page must freeze, not erase
        return curator_view.CuratorView(manifest=manifest, manifest_conflict=conflict, unavailable=True)
    return curator_view.build_view(manifest, verified_rows,
                                   community_rows, verified_graph=verified, community_graph=cfg.community_graph_id,
                                   manifest_conflict=conflict, root_keys=roots,
                                   community_readable=community_page is not None)
