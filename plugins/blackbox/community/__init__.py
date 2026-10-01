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
  :func:`spawn_community_share` sends an allowed finding; :func:`reporter_address`
  resolves this node's reporting identity (never a fallback).
* :func:`build_report_quads` / :func:`build_false_positive_quads` — the
  privacy-safe statements a report or dispute shares (write side).

Usage::

    from .. import community
    rows = community.fetch_community_report_rows(client, cfg)
    rules = community.aggregate_community_reports(rows or [], prior_first_seen)
"""

from __future__ import annotations

from .report_builder import build_false_positive_quads, build_report_quads
from .sharing import NEVER_SHARED_SOURCES, CommunitySharePolicy, reporter_address, spawn_community_share
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
    "aggregate_community_reports",
    "build_false_positive_quads",
    "build_report_quads",
    "community_pause_active",
    "community_report_count",
    "fetch_community_report_rows",
    "reporter_address",
    "spawn_community_share",
]
