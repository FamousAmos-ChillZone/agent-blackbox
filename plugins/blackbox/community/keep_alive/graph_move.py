"""Moving this node's live reports into the one graph (2026-10-16).

Until 2026-10-16 the community had a graph of its own; now its reports live in
the verified graph's shared memory (sub-graph ``COMMUNITY_SUB_GRAPH``). The
live-reports memory (:mod:`.store`) still names the old graph for every report
this node shared there, and nobody reads that graph any more. So each such
report moves ONCE: it is signed again for the configured graph — the same
statement (type, payload, day); only the graph its signature binds changes,
because the old signature does not verify in the new place
(:func:`..report_builder.rebind_quads`) — and shared there under this epoch's
copy name. From then on keep-alive copies it there like any other report.

Two limits keep the move gentle on readers:

* a beat moves at most what its copy budget allows (``MAX_COPIES_PER_BEAT``);
* a UTC day at most :data:`MAX_MOVED_PER_DAY`. A reader that has not seen a
  report in the new place counts it as new that day, under its per-author
  budget of 250 statements a day (``statements.author_budget``); what an author
  sends over that budget is held back on every reader for good.

A report this node cannot sign again (another key's, another network's) leaves
the memory: it could never be read in the new place.

Usage (from :func:`.publisher.publish_due_copies`)::

    beat = graph_move.move_reports(client, cfg, store, epoch, now, budget=MAX_COPIES_PER_BEAT)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any

from ... import audit
from ...kernel import threat_ids
from ...kernel.dkg_client import DkgClient
from .epochs import Epoch, copy_name
from .store import LiveReportStore

logger = logging.getLogger(__name__)

#: Most reports moved per UTC day: with this node's own new reports (at most
#: 100 a day) it stays inside a reader's per-author budget of 250.
MAX_MOVED_PER_DAY = 100
#: Ledger outcome of a report moved into the one graph.
OUTCOME_MOVED = "moved"


@dataclass(frozen=True)
class MoveBeat:
    """What one beat of moving did: ``accepted`` reports the network took in the
    configured graph, ``sends`` how many of the beat's sends it used, and
    ``refused`` — the node refused a write, which ends the beat."""

    accepted: int = 0
    sends: int = 0
    refused: bool = False


def move_reports(client: DkgClient, cfg: Any, store: LiveReportStore, epoch: Epoch, now: float, *,
                 budget: int) -> MoveBeat:
    """Move the live reports that still name another graph into
    ``cfg.context_graph_id``, within *budget* sends and the day's allowance."""
    from .. import report_builder, report_signer, sharing   # the one send path; sharing imports this package

    graph = str(cfg.context_graph_id)
    waiting = [report for report in store.all() if report.graph != graph and report.within_lifetime(now)]
    day = datetime.fromtimestamp(now, UTC).date().isoformat()
    allowance = min(budget, MAX_MOVED_PER_DAY - store.moved_on(day))
    if not waiting or allowance <= 0:
        return MoveBeat()
    signer = report_signer.resolve_report_signer(client, graph)
    if signer is None:   # cannot sign right now: the next beat tries again
        return MoveBeat()
    accepted = sends = 0
    for report in waiting[:allowance]:
        quads = report_builder.rebind_quads(report.quads, signer)
        if quads is None:
            store.forget_names([report.name])
            logger.info("blackbox: a live report of %s was not signed by this node's key on this network; "
                        "it cannot move to %s and is no longer kept alive", report.identifier, graph)
            continue
        name = copy_name(report.name, epoch)
        sends += 1
        outcome, detail = sharing.send_report(client, graph, name, quads)
        if outcome is sharing.ShareOutcome.FAILED:
            logger.info("blackbox: moving live reports refused this beat (%s); retrying on the next refresh",
                        audit.sanitize_text(detail, 120))
            return MoveBeat(accepted, sends, refused=True)
        store.record_move(report.name, graph=graph, quads=quads, epoch=epoch, day=day)
        if outcome is sharing.ShareOutcome.ACCEPTED:
            accepted += 1
            audit.record_share_outcome(identifier=report.identifier, category=threat_ids.category_for(report.identifier),
                                       severity=report.severity, subject=report.subject, asset_name=name, ok=True,
                                       error="", outcome=OUTCOME_MOVED)
    if accepted:
        logger.info("blackbox: %d live report(s) moved into %s", accepted, graph)
    return MoveBeat(accepted, sends)
