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
* :func:`cmd_report` (``blackbox report``), :func:`print_community_status`
  (the status block), :func:`ensure_community_subscription` (join on sync).
* :func:`build_report_quads` / :func:`build_false_positive_quads` — the
  privacy-safe statements a report or dispute shares (write side).
* :func:`contributing_agent_count`, :func:`fetch_reporter_rows` +
  :func:`group_community_agents`, :func:`most_reported_threats` — graph-wide
  statistics for the dashboard (unsanitized; the caller escapes).

Usage::

    from .. import community
    rows = community.fetch_community_report_rows(client, cfg)
    rules = community.aggregate_community_reports(rows or [], prior_first_seen)
"""

from __future__ import annotations

from .report_builder import build_false_positive_quads, build_report_quads
from .report_command import cmd_report, ensure_community_subscription, print_community_status
from .sharing import NEVER_SHARED_SOURCES, CommunitySharePolicy, spawn_community_share
from .graph_stats import (
    contributing_agent_count,
    fetch_reporter_rows,
    group_community_agents,
    most_reported_threats,
)
from .verification import ReportVerifier, VerifiedReport, verify_report_rows
from .report_signer import network_environment
from .reader import (
    COMMUNITY_PAUSE_SUBJECT,
    CommunityRule,
    aggregate_community_reports,
    community_pause_active,
    community_report_count,
    fetch_community_report_rows,
)

__all__ = [
    "COMMUNITY_PAUSE_SUBJECT",
    "NEVER_SHARED_SOURCES",
    "CommunitySharePolicy",
    "CommunityRule",
    "ReportVerifier",
    "VerifiedReport",
    "aggregate_community_reports",
    "build_false_positive_quads",
    "build_report_quads",
    "cmd_report",
    "ensure_community_subscription",
    "community_pause_active",
    "community_report_count",
    "contributing_agent_count",
    "fetch_reporter_rows",
    "group_community_agents",
    "most_reported_threats",
    "network_environment",
    "fetch_community_report_rows",
    "print_community_status",
    "spawn_community_share",
    "verify_report_rows",
]
