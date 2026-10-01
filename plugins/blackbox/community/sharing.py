"""The share path: which findings may leave the machine, and sending them.

:class:`CommunitySharePolicy` is THE outbound gate (Strategy/Policy object;
pure ``decide()``); :func:`spawn_community_share` sends an allowed finding to
the community graph on a background thread, records the outcome in the share
ledger, and :func:`reporter_address` resolves (and caches) this node's agent
address — refusing to report under a fallback identity.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional
from .. import audit
from .. import community
from ..kernel import threat_ids
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
    ``community off`` → ``excluded source`` → ``no identifier`` →
    ``no identity`` (KI-003: a fallback identity would merge distinct nodes
    into one ghost reporter — refuse instead).
    """

    def __init__(self, cfg: BlackboxConfig) -> None:
        self._cfg = cfg

    def decide(self, finding: Dict[str, Any], reporter: Optional[str]) -> "tuple[bool, str]":
        if not self._cfg.community_enabled:
            return False, "community sharing disabled"
        if finding.get("source") in NEVER_SHARED_SOURCES:
            return False, f"source {finding.get('source')} never leaves the machine"
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
    node keeps a durable record of its contributions. Fail-open.
    """
    identifier = str(finding.get("identifier") or "")
    subject = threat_ids.report_uri(identifier, reporter)
    name = f"report-{threat_ids.stable_hash(identifier + reporter, 16)}"
    try:
        # Reports contain signatures, never raw prompts, paths, or source files.
        fields = finding.get("fields") if isinstance(finding.get("fields"), dict) else {}
        q = community.build_report_quads(
            identifier=identifier,
            category=str(finding.get("category") or ""),
            severity=str(finding.get("severity") or "info"),
            reporter_address=reporter,
            framework=_FRAMEWORK,
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


_reporter_cache: Dict[str, str] = {}


def reporter_address(client: DkgClient) -> Optional[str]:
    """Resolve this node's agent address (cached), or ``None`` when unknown.

    Pattern: Sentinel Object — ``None`` IS the "no identity" signal (KI-003).
    The old ``"node"`` string fallback would have merged every identity-less
    node worldwide onto one report subject (first-writer-wins), silently
    dropping reports and corrupting distinct-reporter counting. Identity-keyed
    writes fail closed instead; only real addresses are cached.

    ``agent_identity`` is definitive; ``status`` is a fallback for older daemons.
    """
    if "addr" in _reporter_cache:
        return _reporter_cache["addr"]
    for resolver_name in ("agent_identity", "status"):
        resolver = getattr(client, resolver_name, None)
        if resolver is None:
            continue
        try:
            info = resolver()
        except Exception:
            continue
        if not isinstance(info, dict):
            continue
        for key in ("agentAddress", "defaultAgentAddress", "address"):
            val = info.get(key)
            if isinstance(val, str) and val.strip():
                _reporter_cache["addr"] = val.strip()
                return _reporter_cache["addr"]
    return None
