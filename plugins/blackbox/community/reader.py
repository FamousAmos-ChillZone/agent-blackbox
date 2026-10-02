"""Reading the community graph: fetch, verify, and the three-state read.

Fetches ``g:ThreatReport`` rows from the community graph's shared memory,
verifies them (:mod:`.verification`), honours retractions, and returns ONE
tagged :class:`CommunityRead`. Also the curator pause flag
(``COMMUNITY_PAUSE_SUBJECT``) and the report count. Aggregation into rules is
:mod:`.aggregation`.

Usage (through the package): ``read = community.read_verified_reports(client, cfg)``
-> ``community.aggregate_community_reports(read.reports, prior_first_seen)``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import replace, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from ..kernel import constants
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient, extract_binding
from ..kernel import sparql_text
from .statements import author_budget, curator_statements, curator_view, digests, disputes, retractions, tombstones
from .report_signer import network_environment
from ..kernel.signing import key_manifest
from .verification import ReportVerifier, VerifiedReport, verify_report_rows

logger = logging.getLogger(__name__)

def community_report_count(client: DkgClient, cfg: BlackboxConfig) -> int:
    """Count threat reports in the COMMUNITY graph's shared memory (B5).

    Repointed from the verified graph's SWM view to the dedicated community
    graph — the two-graph split. Returns 0 when no community graph is
    configured or on any error (fail-open read).
    """
    if not cfg.community_graph_id:
        return 0
    sparql = (
        "SELECT (COUNT(DISTINCT ?r) AS ?n) WHERE { "
        "?r a <http://umanitek.ai/ontology/guardian/ThreatReport> }"
    )
    rows = client.query(
        sparql,
        cfg.community_graph_id,
        view=constants.VIEW_SHARED_WORKING_MEMORY,
        on_error=None,
    )
    if not rows:
        return 0
    try:
        return int(extract_binding(rows[0].get("n")) or 0)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Community tier (B5): fetch → aggregate → adapt, with the untrusted-data
# boundary enforced in exactly one place.
# ---------------------------------------------------------------------------

#: Per-page row cap for the community report pager (same discipline as the
#: verified tiers, smaller pages — reports are tiny).
_COMMUNITY_PAGE_SIZE = 5000

#: Most report rows read from the community graph in one refresh (KI-100) —
#: far below the generic paged-read ceiling; reports are tiny and a real
#: community graph is orders of magnitude smaller.
_COMMUNITY_MAX_ROWS = 100_000

#: Fleet-wide emergency stop (KI-036): curators publish this subject with
#: g:enabled "true" INTO THE VERIFIED GRAPH to pause community ingest
#: everywhere. Read-only for us — no new write path, one-way trust preserved.
COMMUNITY_PAUSE_SUBJECT = "urn:guardian:community:pause"


def _community_reports_sparql(after: str) -> str:
    """Catalog query Q1: cursor-paged ThreatReport fetch with OPTIONAL harvest."""
    cursor = ""
    if after:
        cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})"
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?identifier ?reporter ?severity ?kind ?iocType ?toolName ?argShape
       ?packageName ?packageVersion ?packageEcosystem ?category ?skillName
       ?dangerShape ?pattern ?injectionContext ?skillArtifactHash ?skillRegistry ?iocContext ?reportReason
       ?signedStatement WHERE {{
  ?r a g:ThreatReport ;
     g:identifier ?identifier ;
     g:reporter ?reporter ;
     g:severity ?severity .
  OPTIONAL {{ ?r g:kind ?kind }}
  OPTIONAL {{ ?r g:iocType ?iocType }}
  OPTIONAL {{ ?r g:toolName ?toolName }}
  OPTIONAL {{ ?r g:argShape ?argShape }}
  OPTIONAL {{ ?r g:packageName ?packageName }}
  OPTIONAL {{ ?r g:packageVersion ?packageVersion }}
  OPTIONAL {{ ?r g:packageEcosystem ?packageEcosystem }}
  OPTIONAL {{ ?r g:category ?category }}
  OPTIONAL {{ ?r g:skillName ?skillName }}
  OPTIONAL {{ ?r g:dangerShape ?dangerShape }}
  OPTIONAL {{ ?r g:pattern ?pattern }}
  OPTIONAL {{ ?r g:injectionContext ?injectionContext }}
  OPTIONAL {{ ?r g:skillArtifactHash ?skillArtifactHash }}
  OPTIONAL {{ ?r g:skillRegistry ?skillRegistry }}
  OPTIONAL {{ ?r g:iocContext ?iocContext }}
  OPTIONAL {{ ?r g:reportReason ?reportReason }}
  OPTIONAL {{ ?r g:signedStatement ?signedStatement }}
  {cursor}
}} ORDER BY STR(?r) LIMIT {_COMMUNITY_PAGE_SIZE}
"""


def community_pause_active(client: DkgClient, cfg: BlackboxConfig) -> bool:
    """KI-036: True when curators have raised the fleet-wide pause flag.

    Read from the VERIFIED graph (only Umanitek writes there). Fail-open to
    NOT paused — a network error must not silently disable the community
    tier; the flag exists for deliberate emergencies only.
    """
    try:
        sparql = (
            f"SELECT ?v WHERE {{ <{COMMUNITY_PAUSE_SUBJECT}> "
            f"<{constants.BLACKBOX_ONTOLOGY}enabled> ?v }} LIMIT 1"
        )
        rows = client.query(sparql, cfg.context_graph_id, on_error=None)
        if rows is None or not rows:
            return False
        return extract_binding(rows[0].get("v")).strip().lower() == "true"
    except Exception:  # pragma: no cover - fail open
        return False


def fetch_community_report_rows(client: DkgClient, cfg: BlackboxConfig) -> Optional[List[Dict[str, Any]]]:
    """Page every ThreatReport from the community graph's shared memory
    (see :func:`page_community_rows`)."""
    return page_community_rows(client, cfg, _community_reports_sparql)


def page_community_rows(client: DkgClient, cfg: BlackboxConfig,
                        sparql_after: Callable[[str], str]) -> Optional[List[Dict[str, Any]]]:
    """Page a community-graph query (shared memory); see :func:`page_rows`."""
    return page_rows(client, cfg.community_graph_id, constants.VIEW_SHARED_WORKING_MEMORY, sparql_after)


def page_rows(client: DkgClient, graph: str, view: str,
              sparql_after: Callable[[str], str]) -> Optional[List[Dict[str, Any]]]:
    """Page every row a query returns from *graph* / *view*; ``sparql_after(cursor)``
    builds one page's query (subjects after *cursor*, ordered, LIMITed).

    Same cursor discipline as the verified pager (monotonic subject cursor,
    bounded pages, hard row ceiling). Returns None when ANY page fails or
    comes back malformed, so the caller keeps last-good (fail-open); [] when
    the node answered that the graph holds no such rows.
    """
    rows: List[Dict[str, Any]] = []
    after = ""
    sentinel = object()
    while len(rows) < _COMMUNITY_MAX_ROWS:
        page = client.query(sparql_after(after), graph, view=view, on_error=sentinel)
        if page is sentinel:
            # A failed or malformed page — even after good ones — makes the
            # whole read unavailable: a partial list must never pass as the
            # graph's contents (R0 tri-state, KI-112).
            return None
        if not page:
            break
        rows.extend(page)
        cursors = [extract_binding(r.get("r")) for r in page if extract_binding(r.get("r"))]
        next_cursor = max(cursors) if cursors else ""
        if not next_cursor or next_cursor <= after:
            break  # non-monotonic cursor: stop rather than loop forever
        after = next_cursor
        if len(page) < _COMMUNITY_PAGE_SIZE:
            break
    return rows


class ReadState(Enum):
    """What a community read found — never confuse "empty" with "unavailable"."""

    ROWS = "rows"                          # verified reports were read
    AUTHORISED_EMPTY = "authorised-empty"  # the node is subscribed + synced and holds none
    UNAVAILABLE = "unavailable"            # could not read, verify or confirm — keep last-good


@dataclass(frozen=True)
class CommunityRead:
    """The result of :func:`read_verified_reports` (a tagged result).

    ``state`` says which case this is; ``reports`` holds the verified reports
    that count (empty unless ROWS); ``reason`` explains an UNAVAILABLE read.
    Callers act on ``state`` — an UNAVAILABLE read must never be treated as
    "no threats". Refine R2: ``disputes`` — verified disputes (display and,
    later, decay; never enforcement); ``retractions`` — verified retractions
    (display; withdrawn reports are already left out); ``digests`` — verified
    weekly sighting digests (one per author and week); ``heat`` — per threat,
    the estimated agents that met it in the latest digest week, from counted
    authors only (R2b); ``held_back`` — statements over an
    author's daily budget; ``pending_tombstones`` — retractions waiting for a
    report this node has not seen; ``curator`` — what the curator has said,
    verified (reports of a rejected or revoked threat no longer count).
    """

    state: ReadState
    reports: Tuple[VerifiedReport, ...] = ()
    reason: str = ""
    disputes: Tuple[disputes.VerifiedDispute, ...] = ()
    retractions: Tuple[retractions.VerifiedRetraction, ...] = ()
    digests: Tuple[digests.VerifiedDigest, ...] = ()
    heat: Mapping[str, digests.HeatEstimate] = field(default_factory=dict)
    held_back: int = 0
    pending_tombstones: int = 0
    #: R10b: rows dropped because they were signed for another network / graph, or dated in the future.
    env_mismatch: int = 0
    future_dated: int = 0
    curator: curator_view.CuratorView = field(default_factory=curator_view.CuratorView)

    @property
    def available(self) -> bool:
        return self.state is not ReadState.UNAVAILABLE


def _unavailable(reason: str) -> CommunityRead:
    logger.info("blackbox: community read unavailable: %s", reason)
    return CommunityRead(ReadState.UNAVAILABLE, reason=reason)


def _empty_is_authorised(client: DkgClient, graph: str) -> bool:
    """Membership probe for an EMPTY read: only a node that says it is
    subscribed to the graph and synced may report "the graph is empty".
    Anything else (not subscribed, still syncing, probe failed) is not proof."""
    try:
        entries = client.context_graphs()
    except Exception as exc:  # probe failure is "not proven", never "empty"
        logger.debug("blackbox: community membership probe failed: %s", exc)
        return False
    for entry in entries:
        if str(entry.get("id") or "") == graph:
            return bool(entry.get("subscribed")) and bool(entry.get("synced"))
    return False


def read_verified_reports(client: DkgClient, cfg: BlackboxConfig) -> CommunityRead:
    """THE community read (R0c/R0d, tri-state R0): every report in the
    community graph whose signature verifies for this node's network and graph.

    The one place community reports are fetched and verified — the ruleset,
    the dashboard's community statistics and `blackbox report --status` all
    start here. UNAVAILABLE when any page failed or came back malformed, when
    the node's network id is unknown (nothing can be verified), or when the
    graph reads empty but the node cannot confirm it is subscribed and
    synced. No community graph configured = AUTHORISED_EMPTY. Reports their
    own signer retracted are left out (:mod:`.retractions`).
    """
    if not cfg.community_graph_id:
        return CommunityRead(ReadState.AUTHORISED_EMPTY)
    rows = fetch_community_report_rows(client, cfg)
    if rows is None:
        return _unavailable("a page of the community graph failed or was malformed")
    try:
        environment = network_environment(client.status())
    except Exception as exc:  # node unreachable: "cannot verify now"
        return _unavailable(f"node status unavailable ({exc})")
    if not environment:
        return _unavailable("the node reports no network id, so nothing can be verified")
    if not rows:
        if _empty_is_authorised(client, cfg.community_graph_id):
            return CommunityRead(ReadState.AUTHORISED_EMPTY)
        return _unavailable("empty read without proof of a synced subscription")
    verifier = ReportVerifier(environment, cfg.community_graph_id)
    reports, _dropped = verify_report_rows(rows, verifier)
    read = _honour_statements(client, cfg, environment, reports)
    return replace(read, env_mismatch=verifier.drops["env_mismatch"], future_dated=verifier.drops["future_dated"])


def _honour_statements(client: DkgClient, cfg: BlackboxConfig, environment: str,
                       reports: List[VerifiedReport]) -> CommunityRead:
    """Honour every reporter statement BEFORE anything is counted (Refine R2).

    Reads and verifies retractions and disputes, applies ONE per-author
    budget over reports, retractions and disputes (reader-observed days),
    then removes withdrawn reports. A failed or malformed page of either
    statement type makes the whole read unavailable (keep last-good), so a
    withdrawn report is never counted again because its retraction could not
    be read.
    """
    graph = cfg.community_graph_id
    retraction_rows = page_community_rows(client, cfg, retractions.retractions_sparql)
    dispute_rows = page_community_rows(client, cfg, disputes.disputes_sparql)
    if retraction_rows is None or dispute_rows is None:
        return _unavailable("a page of retractions or disputes failed or was malformed")
    # Digests only ADD a heat estimate: a failed page costs this read its heat, never its counts.
    found_digests = digests.verified_digests(page_community_rows(client, cfg, digests.digests_sparql) or [],
                                             environment, graph)
    found_retractions = retractions.verified_retractions(retraction_rows, environment, graph)
    found_disputes = disputes.verified_disputes(dispute_rows, environment, graph)
    statements = [author_budget.Statement(item.author, item.subject)
                  for item in (*reports, *found_retractions, *found_disputes, *found_digests)]
    budget = author_budget.AuthorBudget(author_budget.FirstSeenStore()).admit(statements)
    curator = read_curator_view(client, cfg, environment)
    # A threat the curator rejected or revoked stops counting here (terminal verdicts, R2).
    reports = [r for r in reports if r.subject in budget.admitted
               and not (curator.rejected(r.identifier) or r.identifier in curator.revoked)]
    admitted_retractions = [r for r in found_retractions if r.subject in budget.admitted]
    withdrawn, pending = tombstones.applicable_withdrawals(admitted_retractions, reports, budget.first_seen,
                                                           time.time())
    admitted_digests = digests.one_per_author_week([d for d in found_digests if d.subject in budget.admitted],
                                                   budget.first_seen)
    return CommunityRead(ReadState.ROWS, reports=tuple(retractions.apply_retractions(reports, withdrawn)),
                         disputes=tuple(d for d in found_disputes if d.subject in budget.admitted),
                         retractions=tuple(admitted_retractions), digests=tuple(admitted_digests),
                         heat=digests.heat_for_week(admitted_digests, curator, digests.latest_week(admitted_digests)),
                         held_back=budget.held_back, pending_tombstones=pending, curator=curator)


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
    roots = curator_view.trusted_roots(environment)
    if not environment or not roots:
        return curator_view.CuratorView()
    verified, memory = cfg.context_graph_id, constants.VIEW_VERIFIABLE_MEMORY
    manifests = curator_view.trusted_manifests(page_rows(client, verified, memory, curator_view.key_manifests_sparql) or [],
                                               environment, verified, roots)
    today = curator_view.today_utc()
    effective = [m for m in manifests if key_manifest.manifest_clock(m, today)[0] != "pending"]   # R7b 72 h time-lock
    manifest = key_manifest.newest(effective)
    conflict = curator_view.manifests_conflict(manifests)   # R10b SECURITY alarm
    if manifest is None:
        return curator_view.CuratorView(manifest_conflict=conflict)
    community_rows = (page_community_rows(client, cfg, curator_statements.curator_statements_sparql) or []
                      if cfg.community_graph_id else [])
    return curator_view.build_view(manifest, page_rows(client, verified, memory,
                                                       curator_statements.curator_statements_sparql) or [],
                                   community_rows, verified_graph=verified, community_graph=cfg.community_graph_id,
                                   manifest_conflict=conflict, root_keys=roots)
