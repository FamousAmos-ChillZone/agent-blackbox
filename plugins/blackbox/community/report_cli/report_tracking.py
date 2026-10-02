"""Lifecycle TRACK for a reporter: what happened to each report, and its standing (Refine R10).

:func:`outcome_line` renders one share-ledger row as "what happened to my
report": the share outcome, then the threat's current local stage and reason
from the compiled community store — the same stage every node computes (R3).
:func:`report_standing` / :func:`standing_lines` say whether this reporter is
COUNTED or on PROBATION (from the public counted-author list), how many of
its verified reports are on the graph, and a co-sighting estimate from this
week's digests (R2b). The curator-private standing pull is R13.
Called by :func:`.report_command.cmd_report` (``--status`` / ``--standing``).
"""

from __future__ import annotations

from typing import Any, Dict, List

from ...kernel import display_safety, reporter_key
from ...kernel.dkg_client import DkgClient
from .. import reader as graph_reader

#: How a ledger outcome is shown (community.ShareOutcome values).
_OUTCOME_LABELS = {"accepted": "ok", "already-shared": "already shared", "failed": "FAILED",
                   "retrying": "retrying", "failed-after-retries": "FAILED after retries"}   # R16


def outcome_line(row: Dict[str, Any], compiled: Dict[str, Dict[str, Any]]) -> str:
    """R10 TRACK: one ledger row as "what happened to my report": the share
    outcome, then the threat's current local stage and reason from the
    compiled community store (what every node sees)."""
    outcome = _OUTCOME_LABELS.get(str(row.get("outcome") or ("accepted" if row.get("ok") else "failed")), "FAILED")
    identifier = str(row.get("identifier") or "")
    rule = compiled.get(identifier) or {}
    stage = f"{rule.get('stage')} ({rule.get('enforcement')}) — {rule.get('stageReason')}" if rule.get("stage")         else "not in the compiled community tier (not read yet, retracted, or below the compile cap)"
    return (f"{display_safety.term_safe(row.get('ts'), 24)}  [{outcome}]  {display_safety.term_safe(row.get('category'), 16)}  "
            f"{display_safety.term_safe(identifier, 90)}\n      stage: {display_safety.term_safe(stage, 160)}")


def report_standing(cfg) -> int:
    """R10: this reporter's standing — listed (counted) or on probation — and a
    co-sighting estimate, from the public counted-author list and this
    week's digests. Sightings of known threats protect peers but do not build
    reputation (plan §10). The curator-private standing pull is R13."""
    store = reporter_key.ReporterKeyStore()
    if not store.path.exists():
        print("This node has not signed a report yet; standing starts with the first report.")
        return 0
    own = store.public_key_hex()
    if not cfg.community_graph_id:
        print("No community graph configured.")
        return 0
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    read = graph_reader.read_verified_reports(client, cfg)
    if not read.available:
        print(f"Community graph unavailable right now: {display_safety.term_safe(read.reason, 160)}")
        return 1
    for line in standing_lines(own, read):
        print(line)
    return 0


def standing_lines(own_author: str, read: Any) -> List[str]:
    entry = read.curator.counted.get(own_author)
    mine = {r.identifier for r in read.reports if r.author == own_author}
    co_sighted = sum(read.heat[i].agents for i in mine if i in read.heat)
    lines = []
    if entry is not None:
        lines.append(f"Standing: COUNTED ({entry.author_class}{', ' + entry.org if entry.org else ''}) until {entry.expires} — "
                     "your reports move stages.")
    elif read.curator.manifest is None:
        lines.append("Standing: no curator key manifest is trusted on this network yet — every author counts 0 for now.")
    else:
        lines.append("Standing: PROBATION (not on the counted-author list) — your reports are stored and shown as "
                     "\"new reporter\" and weigh 0 until a curator lists you.")
    lines.append(f"Progress: {len(mine)} verified report(s) of yours are on the graph; "
                 f"co-sightings this week: ~{co_sighted} agent(s) met the threats you reported.")
    lines.append("Sightings of already-verified threats protect peers but do not build reputation.")
    return lines
