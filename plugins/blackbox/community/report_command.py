"""``blackbox report`` — file, dispute and review this node's community reports.

Manual reports go through the same share path as automatic ones; also
``--false-positive`` disputes and ``--status`` (this node's contributions,
from the share ledger plus the graph).
"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Dict, Optional, Tuple
from .. import audit
from . import graph_stats, report_builder, report_signer
from . import reader as graph_reader
from ..kernel import threat_ids

from ..kernel.config import load_blackbox_config
from ..kernel.dkg_client import DkgClient
from ..kernel import display_safety, identity, reporter_key

logger = logging.getLogger(__name__)

def ensure_community_subscription(client: DkgClient, cfg) -> "tuple[bool, str]":
    """Idempotently subscribe (and enroll) this node into the community graph.

    Fail-open: community connectivity must never break sync. Subscription
    includes shared memory (B1-proven: community reports LIVE in SWM, and the
    default subscribe excludes it — KI-007). When a curator peer is known,
    a join request is forwarded once (KI-040: SWM participation is
    enrollment-mediated even on open graphs; the daemon no-ops when already
    a member). Returns (ok, detail-for-logs).
    """
    if not cfg.community_graph_id:
        return False, "no community graph configured"
    try:
        client.subscribe_context_graph(cfg.community_graph_id, include_shared_memory=True)
    except Exception as exc:
        logger.debug("blackbox: community subscribe failed: %s", exc)
        return False, f"subscribe failed: {exc}"
    if cfg.community_graph_peer_id:
        try:
            client.request_join(cfg.community_graph_id, cfg.community_graph_peer_id)
        except Exception as exc:  # join is best-effort; open enrollment auto-approves
            logger.debug("blackbox: community join request failed: %s", exc)
    return True, "subscribed"


def print_community_status(cfg) -> None:
    """The truthful community lines for `blackbox status` (B4).

    Reads only local state (config + the reports ledger) so status stays
    instant and offline-safe; ledger identifiers are community-era data and
    render through :func:`_term_safe`.
    """
    if not cfg.community_graph_id:
        print("  community graph:   not configured (community sharing dormant)")
        return
    print(f"  community graph:   {display_safety.term_safe(cfg.community_graph_id)}")
    if cfg.community_enabled:
        sharing = f"on (min severity {cfg.report_min_severity}, cap {cfg.daily_report_limit}/day)"
    elif not cfg.report:
        sharing = "off (config key `report` is false)"
    else:
        sharing = "off"
    print(f"  threat sharing:    {sharing}")
    ledger = audit.read_share_ledger(limit=1000)
    contributed = sum(1 for row in ledger if row.get("ok"))
    line = f"  reports shared:    {contributed}"
    if ledger:
        last = ledger[0]
        outcome = "ok" if last.get("ok") else "FAILED"
        line += f" (last: {display_safety.term_safe(last.get('identifier'), 80)} · {outcome} · {display_safety.term_safe(last.get('ts'), 24)})"
    print(line)


#: Per-type required args (KI-025): a manual report with missing coordinates
#: would derive a malformed identifier (e.g. ``dep::pkg@``) that poisons
#: corroboration counting — reject loudly, submit nothing.
_REPORT_REQUIRED_ARGS: Dict[str, "tuple[str, ...]"] = {
    "injection": ("pattern",),
    "escalation": ("tool", "arg_shape"),
    "dependency": ("ecosystem", "name", "version"),
    "fileaccess": ("tool", "category"),
    "skill": ("skill_name",),
    "ioc": ("ioc_type", "value"),
}


def _report_finding_from_args(args: argparse.Namespace) -> "tuple[Optional[dict], str]":
    """Factory: parsed report args → the finding dict the share path expects.

    Pattern: Factory function — the one creational seam of the manual path.
    Validates per-type required args (KI-025) and derives the deterministic
    identifier with the SAME quads helpers automatic detection uses, so a
    manual report and an automatic one about the same threat are
    byte-identical downstream. Returns (finding, "") or (None, error).
    """
    rtype = args.type or ""
    required = _REPORT_REQUIRED_ARGS.get(rtype)
    if required is None:
        return None, "a --type is required (or use --status / --false-positive)"
    missing = [f"--{name.replace('_', '-')}" for name in required if not getattr(args, name, None)]
    if missing:
        return None, f"--type {rtype} requires {', '.join(missing)}"
    fields: Dict[str, Any] = {}
    if rtype == "injection":
        identifier = threat_ids.injection_identifier(args.pattern)
        fields = {"pattern": args.pattern, "owasp_category": args.owasp}
    elif rtype == "escalation":
        identifier = threat_ids.escalation_identifier(args.tool, args.arg_shape)
        fields = {"tool_name": args.tool, "arg_shape": args.arg_shape}
    elif rtype == "dependency":
        identifier = threat_ids.dependency_identifier(args.ecosystem, args.name, args.version)
        fields = {
            "ecosystem": args.ecosystem,
            "package_name": args.name,
            "package_version": args.version,
            "advisory_id": args.advisory_id,
            "kind": args.kind,
        }
    elif rtype == "fileaccess":
        identifier = threat_ids.fileaccess_identifier(args.tool, args.category)
        fields = {"tool_name": args.tool, "file_category": args.category}
    elif rtype == "skill":
        if args.skill_version:
            identifier = threat_ids.skill_version_identifier(args.skill_name, args.skill_version)
        elif args.danger_shape:
            identifier = threat_ids.skill_shape_identifier(args.skill_name, args.danger_shape)
        else:
            return None, "--type skill requires --skill-version or --danger-shape"
        fields = {
            "skill_name": args.skill_name,
            "skill_version": args.skill_version,
            "danger_shape": args.danger_shape,
        }
    else:  # ioc
        identifier = threat_ids.ioc_identifier(args.ioc_type, args.value)
        fields = {"ioc_type": args.ioc_type}
    return {
        "identifier": identifier,
        "category": rtype,
        "severity": args.severity,
        "source": "custom-manual",  # never auto-shared; explicit path only
        "fields": {k: v for k, v in fields.items() if v},
    }, ""


def cmd_report(args: argparse.Namespace) -> int:
    """Manual community reporting: submit, dispute, or review contributions.

    Same gates as automatic sharing (community_enabled, identity, cooldown,
    daily cap) and the SAME share/ledger path — one implementation per
    concern. ACK is real: the command waits for the share job and prints the
    outcome + report subject (lifecycle: ACKNOWLEDGE).
    """
    cfg = load_blackbox_config()
    if args.status:
        return _report_status(cfg)
    if not cfg.community_enabled:
        if not cfg.community_graph_id:
            print("Community sharing is dormant: no community graph is configured.")
        else:
            print("Community sharing is OFF (config key `report: false`).")
        print("Nothing was submitted.")
        return 2
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    resolved = _reporting_identity(client, cfg.community_graph_id)
    if resolved is None:
        return 1
    reporter, signer = resolved
    if args.false_positive:
        return _submit_false_positive(client, cfg, args.false_positive, reporter, signer)
    finding, err = _report_finding_from_args(args)
    if finding is None:
        print(f"Invalid report: {err}")
        print("Nothing was submitted.")
        return 2
    identifier = finding["identifier"]
    if audit.recently_reported(identifier):
        print(f"Already reported within the cooldown window: {display_safety.term_safe(identifier)}")
        return 0
    if not audit.allow_report(cfg.daily_report_limit):
        print(f"Daily report cap reached ({cfg.daily_report_limit}); try again tomorrow.")
        return 2
    subject = threat_ids.report_uri(identifier, reporter)
    name = f"report-{threat_ids.stable_hash(identifier + reporter, 16)}"
    q = report_builder.build_report_quads(
        identifier=identifier,
        category=finding["category"],
        severity=finding["severity"],
        reporter_address=reporter,
        framework="hermes",
        signer=signer,
        **finding["fields"],
    )
    try:
        client.share_knowledge_asset(cfg.community_graph_id, name, q)
    except Exception as exc:
        audit.record_share_outcome(
            identifier=identifier, category=finding["category"],
            severity=finding["severity"], subject=subject, asset_name=name,
            ok=False, error=str(exc),
        )
        print(f"Share FAILED: {display_safety.term_safe(str(exc), 160)}")
        print("The attempt is recorded in your local reports ledger.")
        return 1
    audit.mark_reported(identifier)
    audit.record_share_outcome(
        identifier=identifier, category=finding["category"],
        severity=finding["severity"], subject=subject, asset_name=name, ok=True,
    )
    print("Report shared to the community graph.")
    print(f"  identifier: {display_safety.term_safe(identifier)}")
    print(f"  subject:    {display_safety.term_safe(subject)}")
    return 0


def _reporting_identity(client: DkgClient, graph: str) -> Optional[Tuple[str, report_signer.ReportSigner]]:
    """(reporter address, signer) for a manual report, or None after telling
    the operator why nothing can be submitted (no identity, or cannot sign)."""
    reporter = identity.reporter_address(client)
    if not reporter or not reporter.startswith("0x"):
        print("No resolved node identity — refusing to report as a shared ghost identity.")
        print("Start the DKG node (or finish setup) and retry.")
        return None
    signer = report_signer.resolve_report_signer(client, graph)
    if signer is None:
        print("Cannot sign the report (the node reports no network id, or the reporter key is unusable).")
        print("Nothing was submitted — an unsigned report would not be counted by anyone.")
        return None
    return reporter, signer


def _submit_false_positive(client: DkgClient, cfg, identifier: str, reporter: str,
                           signer: report_signer.ReportSigner) -> int:
    """Dispute a community threat (lifecycle: DISPUTE — the Q8 veto writer)."""
    identifier = identifier.strip()
    if not identifier:
        print("Provide the threat identifier to dispute.")
        return 2
    q = report_builder.build_false_positive_quads(identifier=identifier, reporter_address=reporter, signer=signer)
    name = f"fp-{threat_ids.stable_hash(identifier + reporter, 16)}"
    subject = threat_ids.report_uri(identifier, reporter) + ":fp"
    try:
        client.share_knowledge_asset(cfg.community_graph_id, name, q)
    except Exception as exc:
        print(f"Dispute FAILED: {display_safety.term_safe(str(exc), 160)}")
        return 1
    audit.record_share_outcome(
        identifier=identifier, category="false-positive", severity="info",
        subject=subject, asset_name=name, ok=True,
    )
    print(f"False-positive signal shared for: {display_safety.term_safe(identifier)}")
    return 0


def _report_status(cfg) -> int:
    """Lifecycle TRACK: the ledger first (offline-safe), Q9 when reachable."""
    rows = audit.read_share_ledger(limit=50)
    if not rows:
        print("No community reports from this node yet.")
    else:
        print(f"Community contributions from this node (newest first, {len(rows)} shown):")
        for row in rows:
            outcome = "ok" if row.get("ok") else "FAILED"
            print(f"  {display_safety.term_safe(row.get('ts'), 24)}  [{outcome}]  "
                  f"{display_safety.term_safe(row.get('category'), 16)}  {display_safety.term_safe(row.get('identifier'), 96)}")
    if cfg.community_graph_id:
        try:
            client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
            store = reporter_key.ReporterKeyStore()
            own_author = store.public_key_hex() if store.path.exists() else ""
            read = graph_reader.read_verified_reports(client, cfg)
            if not read.available:
                print(f"Community graph unavailable right now: {display_safety.term_safe(read.reason, 160)}")
            elif own_author:
                # R0d: count what THIS node's key signed and the graph verified —
                # never rows that merely claim our address.
                count = graph_stats.reports_signed_by(read.reports, own_author)
                print(f"On the community graph: {count} verified report(s) signed by this node.")
        except Exception as exc:
            logger.debug("blackbox: report --status graph read failed: %s", exc)
    return 0
