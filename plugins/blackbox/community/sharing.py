"""The share path: which findings may leave the machine, and sending them.

:class:`CommunitySharePolicy` is THE outbound gate (Strategy/Policy object;
pure ``decide()``); :func:`spawn_community_share` sends an allowed finding to
the community graph on a background thread and records the outcome in the
share ledger. The reporter identity comes from ``kernel.identity`` — the gate
refuses to share without one (KI-003).
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional
from .. import audit
from .. import community
from ..kernel import threat_ids
from . import report_signer
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient, DkgError

logger = logging.getLogger(__name__)

#: This runtime IS the Hermes host; the OpenClaw runtime has its own TS
#: pipeline and stamps its own framework when its share path ships (KI-014).
_FRAMEWORK = "hermes"

#: Sources that must never leave the machine in any form. Secret findings
#: could carry the shape of a leak; custom rules and LLM opinions are the
#: operator's private judgment. Enforced BEFORE any graph write.
NEVER_SHARED_SOURCES = ("custom", "llm", "secret")


#: OSV's malicious-package database uses MAL- advisory ids; every other OSV
#: advisory describes a vulnerability.
_MALWARE_ADVISORY_PREFIX = "MAL-"


def is_vulnerability_finding(finding: Dict[str, Any]) -> bool:
    """True for a finding that describes a VULNERABILITY (vs. malware).

    Either it says so (``kind == "vulnerability"``, any tier), or it is an OSV
    discovery candidate (an ``advisory_id`` in its fields, no kind) whose
    advisory is not a malicious-package (``MAL-``) advisory.
    """
    kind = str(finding.get("kind") or "").lower()
    if kind:
        return kind == "vulnerability"
    fields = finding.get("fields") if isinstance(finding.get("fields"), dict) else {}
    advisory = str(fields.get("advisory_id") or "")
    return bool(advisory) and not advisory.upper().startswith(_MALWARE_ADVISORY_PREFIX)


class CommunitySharePolicy:
    """Decides whether ONE finding may be shared to the community graph.

    Pattern: Policy object (Strategy) — the entire outbound gate chain lives
    in this single, dependency-injected, testable class instead of scattered
    conditionals. ``decide()`` is pure (no I/O); the one stateful gate (the
    daily cap) is consumed separately by the caller at spawn time so a denied
    decision never burns cap budget.

    Usage::

        policy = CommunitySharePolicy(cfg)
        ok, why = policy.decide(finding_dict, reporter_address)
        if ok and audit.allow_report(cfg.daily_report_limit):
            spawn_community_share(client, cfg, finding_dict, reporter_address)

    Gate order (first refusal wins, ``why`` names it for the debug log):
    ``community off`` → ``excluded source`` → ``vulnerability`` →
    ``community-only match`` → ``no identifier`` → ``no identity`` (KI-003:
    a fallback identity would merge distinct nodes into one ghost reporter —
    refuse instead).

    Decision 22 (Refine R0, LES-018) — what leaves AUTOMATICALLY is narrowed:

    * vulnerability findings never leave (KI-157): they reveal the reporter's
      unpatched software and add nothing OSV lacks. That covers a
      ``kind=vulnerability`` finding from any tier and an OSV candidate whose
      advisory is not a malicious-package advisory (``MAL-``);
    * a match against a COMMUNITY-only rule never auto-shares (KI-158):
      whoever listed the value would learn who met it. It still flags here and
      can leave only by an explicit operator ``blackbox report``.

    Self-discovered threats and VERIFIED-tier matches still share.
    """

    def __init__(self, cfg: BlackboxConfig) -> None:
        self._cfg = cfg

    def decide(self, finding: Dict[str, Any], reporter: Optional[str]) -> "tuple[bool, str]":
        if not self._cfg.community_enabled:
            return False, "community sharing disabled"
        if finding.get("source") in NEVER_SHARED_SOURCES:
            return False, f"source {finding.get('source')} never leaves the machine"
        if is_vulnerability_finding(finding):
            return False, "vulnerability findings stay in the local audit (decision 22)"
        if finding.get("source") == "community":
            return False, "community-only match: flagged here, shared only by an explicit `blackbox report`"
        if not str(finding.get("identifier") or "").strip():
            return False, "no identifier"
        if not reporter:
            return False, "no resolved reporter identity"
        return True, "ok"


def spawn_community_share(
    client: DkgClient, cfg: BlackboxConfig, finding: Dict[str, Any], reporter: str
) -> threading.Thread:
    """Run the share network lifecycle off the hook hot path (KI-033).

    Daemon thread, same pattern as the OSV and LLM workers in this file: the
    hook returns immediately; the share can take the node's full store/poll
    timeouts without ever freezing the protected agent.
    """
    worker = threading.Thread(
        target=_share_sighting,
        args=(client, cfg, finding, reporter),
        name="blackbox-community-share",
        daemon=True,
    )
    worker.start()
    return worker


def _share_sighting(
    client: DkgClient, cfg: BlackboxConfig, finding: Dict[str, Any], reporter: str
) -> None:
    """Share one privacy-safe sighting into the COMMUNITY graph and ledger it.

    Targets ``cfg.community_graph_id`` — never the verified graph: the
    two-graph separation is the product's core trust boundary. Every attempt
    (success or failure) lands in the local reports ledger (KI-015) so the
    node keeps a durable record of its contributions. A node that cannot sign
    does not share (R0b): the refusal is ledgered like any failure. Fail-open.
    """
    identifier = str(finding.get("identifier") or "")
    subject = threat_ids.report_uri(identifier, reporter)
    name = f"report-{threat_ids.stable_hash(identifier + reporter, 16)}"
    signer = report_signer.resolve_report_signer(client, cfg.community_graph_id)
    if signer is None:
        _ledger_share(finding, subject, name, ok=False, error="cannot sign reports (no network id or reporter key)")
        return
    try:
        # Reports contain signatures, never raw prompts, paths, or source files.
        fields = finding.get("fields") if isinstance(finding.get("fields"), dict) else {}
        q = community.build_report_quads(
            identifier=identifier,
            category=str(finding.get("category") or ""),
            severity=str(finding.get("severity") or "info"),
            reporter_address=reporter,
            framework=_FRAMEWORK,
            signer=signer,
            **{k: v for k, v in fields.items() if v is not None},
        )
        client.share_knowledge_asset(cfg.community_graph_id, name, q)
    except DkgError as exc:
        logger.debug("blackbox: sighting share failed: %s", exc)
        _ledger_share(finding, subject, name, ok=False, error=str(exc))
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: sighting share error: %s", exc)
        _ledger_share(finding, subject, name, ok=False, error=str(exc))
    else:
        _ledger_share(finding, subject, name, ok=True)


def _ledger_share(finding: Dict[str, Any], subject: str, name: str, *, ok: bool, error: str = "") -> None:
    audit.record_share_outcome(
        identifier=str(finding.get("identifier") or ""),
        category=str(finding.get("category") or ""),
        severity=str(finding.get("severity") or ""),
        subject=subject,
        asset_name=name,
        ok=ok,
        error=error,
    )
