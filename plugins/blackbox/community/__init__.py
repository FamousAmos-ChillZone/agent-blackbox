"""Community — the shared community threat graph.

Every protected agent can report what it sees; every other agent reads it.
Community findings only ever FLAG — they never block — and community strings
are untrusted data that is clamped, typed and displayed, never interpreted.

Public surface:

* :class:`CommunityRule` — one corroborated community threat (the typed seam).
* :func:`fetch_community_report_rows` / :func:`aggregate_community_reports` —
  read reports, then fold them into rules (honest distinct-reporter counts).
* :func:`community_pause_active` / ``COMMUNITY_PAUSE_SUBJECT`` — the curator's
  fleet-wide ingest pause flag (read-only for us).
* :func:`community_report_count` — how many reports the graph holds.
* :class:`CommunitySharePolicy`, ``NEVER_SHARED_SOURCES`` — THE outbound gate;
  :func:`spawn_community_share` sends an allowed finding. This node's
  reporting identity is resolved by ``kernel.identity.reporter_address``.
* :func:`add_report_parser` + :func:`cmd_report` (``blackbox report``), :func:`print_community_status`
  (the status block), :func:`ensure_community_subscription` (join on sync).
* :func:`build_report_quads` / :func:`build_false_positive_quads` /
  :func:`build_retraction_quads` — the
  privacy-safe statements a report or dispute shares (write side).
* :func:`read_verified_reports` — THE community read: fetch + verify (R0c/R0d).
* The curator's view and statements (Refine R2/R6): :func:`read_curator_view` ->
  :class:`CuratorView`; :func:`sign_curator_statement`, :func:`curator_statement_quads`,
  :func:`key_manifest_quads`, :data:`VERIFIED_GRAPH_KINDS` (which kinds live in the verified graph).
* :func:`stage_for` (+ :class:`Stage`, :class:`Enforcement`, :class:`StageResult`) —
  a community threat's local stage from the counted-author list (R3).
* :func:`record_verified_sighting` / :func:`publish_due_digests` — the
  seen-again counter: tally verified matches, publish one weekly digest (R2b).
* :mod:`shadow` — the shadow phase (R15): the MONITOR clamp and the §12 metrics log.
* :mod:`consent` — the sharing consent record (R13): opt-in, bound to the terms' content, withdrawable;
  the share gate refuses without it.
* :mod:`allowlist` — the allowlist / warninglist verdict and canaries (R9): byte-exact
  names hold, look-alikes support the report.
* :mod:`reputation` — automated graduation, novelty, partners, collusion and the
  curator-private ledger (R4); readers see its decisions only through the counted-author list.
* :func:`publish_due_copies` — keep-alive (R5): this node re-publishes an
  epoch-named copy of each of its own live reports; :func:`lifetime_days` —
  how long a community statement lives, per threat type (plan §03).
* :func:`contributing_agent_count`, :func:`community_agents`,
  :func:`most_reported_threats`, :func:`reports_signed_by` — statistics over
  verified reports, counted by signer (unsanitized; the caller escapes).

Usage::

    from .. import community
    rows = community.fetch_community_report_rows(client, cfg)
    rules = community.aggregate_community_reports(rows or [], prior_first_seen)
"""

from __future__ import annotations

from .report_builder import build_false_positive_quads, build_report_quads, build_retraction_quads
from .membership import ensure_community_subscription
from .report_cli import add_report_parser, cmd_report, print_community_status
from .sharing import NEVER_SHARED_SOURCES, CommunitySharePolicy, spawn_community_share
from .graph_stats import community_agents, contributing_agent_count, most_reported_threats, reports_signed_by
from .verification import ReportVerifier, VerifiedReport, verify_report_rows
from .report_signer import network_environment
from .aggregation import CommunityRule, aggregate_community_reports
from .digest import publish_due_digests, record_verified_sighting
from .keep_alive import publish_due_copies
from . import allowlist, consent, reputation, shadow
from .pulse import PULSE
from .pulse import fingerprint as community_fingerprint
from .statements.lifetimes import lifetime_days
from .statements.author_budget import FirstSeenStore as _FirstSeenStore
from .share_retry import retry_due_shares, share_retry_stats
from .stages import Enforcement, Stage, StageResult, stage_for
from .statements.curator_view import VERIFIED_GRAPH_KINDS, CuratorView, counted_dispute_weight
from .statements.curator_statements import manifest_quads as key_manifest_quads
from .statements.curator_statements import sign_statement as sign_curator_statement
from .statements.curator_statements import statement_quads as curator_statement_quads
from .reader import (
    COMMUNITY_PAUSE_SUBJECT,
    community_pause_active,
    community_report_count,
    fetch_community_report_rows,
    CommunityRead,
    ReadState,
    page_rows,
    read_curator_view,
    read_verified_reports,
)
from .statements.curator_view import trusted_roots as curator_trusted_roots


def first_seen_trail():
    """R10b: ({subject hash: first-seen epoch}, baseline) from the reader's budget trail — read-only."""
    return _FirstSeenStore().snapshot()


__all__ = [
    "COMMUNITY_PAUSE_SUBJECT",
    "NEVER_SHARED_SOURCES",
    "CommunitySharePolicy",
    "CommunityRead",
    "CommunityRule",
    "ReadState",
    "ReportVerifier",
    "VerifiedReport",
    "aggregate_community_reports",
    "build_false_positive_quads",
    "build_retraction_quads",
    "build_report_quads",
    "add_report_parser",
    "cmd_report",
    "ensure_community_subscription",
    "community_pause_active",
    "community_agents",
    "community_report_count",
    "contributing_agent_count",
    "most_reported_threats",
    "network_environment",
    "fetch_community_report_rows",
    "print_community_status",
    "CuratorView",
    "Enforcement",
    "VERIFIED_GRAPH_KINDS",
    "curator_statement_quads",
    "key_manifest_quads",
    "sign_curator_statement",
    "Stage",
    "StageResult",
    "counted_dispute_weight",
    "publish_due_digests",
    "publish_due_copies",
    "reputation",
    "allowlist",
    "consent",
    "shadow",
    "lifetime_days",
    "first_seen_trail",
    "PULSE",
    "community_fingerprint",
    "retry_due_shares",
    "share_retry_stats",
    "stage_for",
    "read_curator_view",
    "page_rows",
    "curator_trusted_roots",
    "record_verified_sighting",
    "read_verified_reports",
    "reports_signed_by",
    "spawn_community_share",
    "verify_report_rows",
]
