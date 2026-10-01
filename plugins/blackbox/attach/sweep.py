"""Attach / detach everything this machine has, in one call.

:func:`attach_all` / :func:`detach_all` run the Hermes and OpenClaw
discoverers and return a per-target report the CLI and dashboard render.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from . import hermes_homes
from . import openclaw_bridge
from . import openclaw_discovery

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def attach_all(*, hermes: bool = True, openclaw: bool = True, dry_run: bool = False) -> Dict[str, Any]:
    """Attach Blackbox to every discovered target. Returns a combined report."""
    report: Dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run}
    if hermes:
        for home in hermes_homes.discover_hermes_homes():
            report["hermes"].append(hermes_homes.attach_hermes(home, dry_run=dry_run))
    if openclaw:
        for ws in openclaw_discovery.discover_openclaw_workspaces():
            report["openclaw"].append(openclaw_bridge.attach_openclaw(ws, dry_run=dry_run))
    report["count"] = _protected_count(report)
    return report


def detach_all(
    *, hermes: bool = True, openclaw: bool = True, remove_files: bool = False, dry_run: bool = False
) -> Dict[str, Any]:
    """Detach Blackbox from every discovered target. Returns a combined report."""
    report: Dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run}
    if hermes:
        for home in hermes_homes.discover_hermes_homes():
            report["hermes"].append(hermes_homes.detach_hermes(home, remove_files=remove_files, dry_run=dry_run))
    if openclaw:
        for ws in openclaw_discovery.discover_openclaw_workspaces():
            report["openclaw"].append(openclaw_bridge.detach_openclaw(ws, dry_run=dry_run))
    return report


def _protected_count(report: Dict[str, Any]) -> int:
    """Number of targets Blackbox is (now) protecting in an attach report."""
    total = 0
    for row in report.get("hermes", []):
        if row.get("ok"):
            total += 1
    for row in report.get("openclaw", []):
        if row.get("ok"):
            total += 1
    return total
