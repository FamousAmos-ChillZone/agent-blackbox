"""Reading the community graph: reports -> corroborated community rules.

Fetches ``g:ThreatReport`` rows from the community graph's shared memory,
honours the curator pause flag (``COMMUNITY_PAUSE_SUBJECT``), and aggregates
reports into :class:`CommunityRule` values — the typed seam where untrusted
community strings are clamped and made display-only (KI-004/012). Never
compiles or interprets community content.

Usage (through the package): ``community.fetch_community_report_rows(client, cfg)``
-> ``community.aggregate_community_reports(rows, prior_first_seen)``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from ..kernel import constants
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient, extract_binding
from ..kernel import sparql_text
from .report_signer import network_environment
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

#: Bounded ingest (KI-010): a spammer can invent unlimited identifiers; we
#: keep the corroborated head (reporter count, then oldest observation), never the tail.
_COMMUNITY_MAX_RULES = 5000

#: Per-page row cap for the community report pager (same discipline as the
#: verified tiers, smaller pages — reports are tiny).
_COMMUNITY_PAGE_SIZE = 5000

#: Most report rows read from the community graph in one refresh (KI-100) —
#: far below the generic paged-read ceiling; reports are tiny and a real
#: community graph is orders of magnitude smaller.
_COMMUNITY_MAX_ROWS = 100_000

#: Most threats one verified signer may contribute to a compile (KI-100/111).
#: Its OLDEST-known threats are kept, so a fresh flood from one key can neither
#: crowd out other signers nor displace that signer's own earlier reports.
MAX_REPORTS_PER_AUTHOR = 500

#: Fleet-wide emergency stop (KI-036): curators publish this subject with
#: g:enabled "true" INTO THE VERIFIED GRAPH to pause community ingest
#: everywhere. Read-only for us — no new write path, one-way trust preserved.
COMMUNITY_PAUSE_SUBJECT = "urn:guardian:community:pause"


@dataclass(frozen=True)
class CommunityRule:
    """One aggregated community threat — the typed seam of the read path.

    Holds the corroborated view of every report for one identifier:
    ``reporter_count`` is COUNT(DISTINCT reporter) — honest by the naming
    scheme; ``severity`` is the max across reporters (community can only
    flag, so loud-side is safe); ``first_seen``/``last_seen`` are THIS
    node's ingest observations, never reporter-supplied timestamps
    (KI-012 — display metadata can't be gamed by post-dating).

    Pattern: Adapter — :meth:`as_rule` converts to the plain rule-dict shape
    the existing merge/detection machinery expects, and is the SINGLE point
    where community-authored strings are clamped and typed display-only.
    No community string is ever compiled or interpreted (KI-004): community
    rules match by identifier equality alone.
    """

    identifier: str
    category: str
    severity: str
    reporter_count: int
    first_seen: float
    last_seen: float
    fields: "tuple[tuple[str, str], ...]" = ()

    _CLAMP = 256

    def as_rule(self) -> Dict[str, Any]:
        """The merge-compatible rule dict; every value clamped display-only."""
        clamp = lambda v: str(v or "")[: self._CLAMP]  # noqa: E731 - tiny local helper
        rule = {
            "identifier": clamp(self.identifier),
            "name": clamp(self.identifier),
            "severity": constants.normalize_severity(self.severity),
            "source": "community",
            "reporterCount": int(self.reporter_count),
            "firstSeen": float(self.first_seen),
            "lastSeen": float(self.last_seen),
        }
        for key, value in self.fields:
            rule[clamp(key)] = clamp(value)
        return rule


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
    """Page every row a community query returns; ``sparql_after(cursor)``
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
        page = client.query(
            sparql_after(after),
            cfg.community_graph_id,
            view=constants.VIEW_SHARED_WORKING_MEMORY,
            on_error=sentinel,
        )
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
    (empty unless ROWS); ``reason`` explains an UNAVAILABLE read. Callers act
    on ``state`` — an UNAVAILABLE read must never be treated as "no threats".
    """

    state: ReadState
    reports: Tuple[VerifiedReport, ...] = ()
    reason: str = ""

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
    synced. No community graph configured = AUTHORISED_EMPTY.
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
    reports, _dropped = verify_report_rows(rows, ReportVerifier(environment, cfg.community_graph_id))
    return CommunityRead(ReadState.ROWS, reports=tuple(reports))


def _cap_per_author(reports: Iterable[VerifiedReport], prior_first_seen: Dict[str, float]) -> List[VerifiedReport]:
    """At most MAX_REPORTS_PER_AUTHOR threats per verified signer, keeping
    each signer's oldest-known threats (this node's first-seen history;
    threats it has never seen sort last, then by identifier)."""
    by_author: Dict[str, List[VerifiedReport]] = {}
    for report in reports:
        by_author.setdefault(report.author, []).append(report)
    kept: List[VerifiedReport] = []
    for author_reports in by_author.values():
        author_reports.sort(key=lambda r: (prior_first_seen.get(r.identifier, float("inf")), r.identifier))
        kept.extend(author_reports[:MAX_REPORTS_PER_AUTHOR])
    if len(kept) < sum(len(v) for v in by_author.values()):
        logger.warning("blackbox: community reports capped at %d per signer", MAX_REPORTS_PER_AUTHOR)
    return kept


def aggregate_community_reports(
    reports: Iterable[VerifiedReport], prior_first_seen: Dict[str, float]
) -> List[CommunityRule]:
    """Fold VERIFIED reports into per-identifier CommunityRules.

    Only :class:`~.verification.VerifiedReport` values reach here — a raw row
    cannot be counted (R0c). Aggregation keys on the exact identifier literal
    (KI-027); ``reporter_count`` is the number of distinct SIGNERS (the
    self-described reporter string never counts, KI-067/110); severity is the
    max seen; evidence comes from the signed payload; first_seen carries over
    from this node's previous cache, never a reporter-supplied date (KI-012).
    """
    now = time.time()
    grouped: Dict[str, Dict[str, Any]] = {}
    for report in _cap_per_author(reports, prior_first_seen):
        slot = grouped.setdefault(
            report.identifier,
            {"authors": set(), "severity": "info", "fields": {}},
        )
        slot["authors"].add(report.author)
        if constants.SEVERITY_RANK.get(report.severity, 0) > constants.SEVERITY_RANK.get(slot["severity"], 0):
            slot["severity"] = report.severity
        for var, value in report.fields:
            slot["fields"].setdefault(var, value)
    rules = [
        CommunityRule(
            identifier=identifier,
            category=identifier.split(":", 1)[0],
            severity=slot["severity"],
            reporter_count=len(slot["authors"]),
            first_seen=float(prior_first_seen.get(identifier, now)),
            last_seen=now,
            fields=tuple(sorted(slot["fields"].items())),
        )
        for identifier, slot in grouped.items()
    ]
    # Bounded ingest: corroboration first, then the OLDEST observation (KI-111 —
    # newest-first let a flood of fresh singletons evict honest older ones),
    # then the identifier, so the cut is deterministic.
    rules.sort(key=lambda r: (-r.reporter_count, r.first_seen, r.identifier))
    if len(rules) > _COMMUNITY_MAX_RULES:
        logger.warning(
            "blackbox: community ingest capped at %d rules (%d dropped — corroborated head kept)",
            _COMMUNITY_MAX_RULES,
            len(rules) - _COMMUNITY_MAX_RULES,
        )
        rules = rules[:_COMMUNITY_MAX_RULES]
    return rules
