"""Statements about other reports — `blackbox report --false-positive` —
and the send-and-record step every manual statement shares.

:func:`send_and_record` sends one built statement and writes the local share
ledger (KI-015: every attempt, success or failure). :func:`submit_false_positive`
is the DISPUTE verb. Called by :func:`.report_command.cmd_report`.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .. import audit
from ..kernel import display_safety, threat_ids
from ..kernel.dkg_client import DkgClient
from . import report_builder, report_schema, report_signer, sharing


def send_and_record(client: DkgClient, cfg, *, identifier: str, category: str, severity: str,
                     subject: str, name: str, quads: List[Dict[str, str]]) -> Tuple["sharing.ShareOutcome", str]:
    """Send one built statement to the community graph and record the attempt
    in the local share ledger, success or failure (KI-015). Returns
    (outcome, detail) for the caller to report."""
    outcome, detail = sharing.send_report(client, cfg.community_graph_id, name, quads)
    audit.record_share_outcome(
        identifier=identifier, category=category, severity=severity,
        subject=subject, asset_name=name, ok=outcome is sharing.ShareOutcome.ACCEPTED,
        error=detail, outcome=outcome.value,
    )
    return outcome, detail


def submit_false_positive(client: DkgClient, cfg, identifier: str, reason: Optional[str], reporter: str,
                           signer: report_signer.ReportSigner) -> int:
    """Dispute a community threat (lifecycle: DISPUTE — the Q8 veto writer).
    A closed --reason is required (Refine R1); nothing is sent without one."""
    try:
        identifier, reason = report_schema.validate_dispute(identifier=identifier, reason=reason or "")
    except report_schema.ReportValidationError as exc:
        print(f"Invalid dispute: {exc}")
        print("Nothing was submitted.")
        return 2
    q = report_builder.build_false_positive_quads(identifier=identifier, reporter_address=reporter,
                                                  reason=reason, signer=signer)
    name = f"fp-{threat_ids.stable_hash(identifier + reporter, 16)}"
    subject = threat_ids.report_uri(identifier, reporter) + ":fp"
    outcome, detail = send_and_record(client, cfg, identifier=identifier, category="false-positive",
                                       severity="info", subject=subject, name=name, quads=q)
    if outcome is sharing.ShareOutcome.FAILED:
        print(f"Dispute FAILED: {display_safety.term_safe(detail, 160)}")
        print("The attempt is recorded in your local reports ledger.")
        return 1
    if outcome is sharing.ShareOutcome.REJECTED_SAME_VERSION:
        print(f"Dispute already on the community graph for: {display_safety.term_safe(identifier)} (not re-sent)")
        return 0
    print(f"False-positive signal shared for: {display_safety.term_safe(identifier)}")
    return 0
