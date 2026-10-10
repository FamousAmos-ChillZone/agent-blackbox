"""Indicator-of-compromise detection: known-bad domains, URLs, IPs, hashes,
wallets and contracts named in a tool call's arguments, and where each was met.

Split out of :mod:`.detectors` (which runs it inside ``detect_all``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import action_parsing
from . import content_scanners
from .finding import Finding, _rule_source
from .injection_detection import injection_scan_text


def ioc_context(tool_name: str, args: Any) -> Optional[str]:
    """Where an indicator in this tool call's arguments was met (Refine R1).

    In a skill being installed: ``in-skill``; in a dependency install:
    ``in-dependency``; handed to a web/browser tool: ``fetched-by-tool``.
    Anything else has no reportable context (None), so it stays local.
    """
    if action_parsing.skill_install_arg(tool_name, args):
        return "in-skill"
    if action_parsing.parse_dependency_installs(action_parsing.command_text(args)):
        return "in-dependency"
    if (tool_name or "").strip().lower().startswith(action_parsing.FETCH_TOOL_PREFIXES):
        return "fetched-by-tool"
    return None


def ioc_rules(ruleset: Any, identifiers: List[str]) -> Dict[str, Dict[str, Any]]:
    """The IOC rules among *identifiers* (``ioc:type:value``). A
    :class:`~..ruleset.Ruleset` answers through ``ioc_rules()`` (live verified
    lookup first, compiled dict after); a bare object with an ``ioc`` dict is indexed."""
    if not identifiers:
        return {}
    ask = getattr(ruleset, "ioc_rules", None)
    if callable(ask):
        return ask(identifiers).rules
    compiled = getattr(ruleset, "ioc", {}) or {}
    return {ident: compiled[ident] for ident in identifiers if ident in compiled}


def detect_ioc(tool_name: str, args: Any, ruleset: Any, context: Optional[str] = None) -> List[Finding]:
    """Match indicators (domain/url/ip/hash/wallet/contract) in the tool args.

    *context* (``constants.IOC_CONTEXTS``, from :func:`ioc_context`) says where
    the indicator was met; without one a match stays local (Refine R1).

    Extracts candidate indicators from the flattened args and asks the ruleset
    for all of them in one go (live verified lookup, then compiled rules). Only KNOWN-BAD values match, so extraction can be
    broad without raising false positives on unrelated tokens. IOC findings
    ALWAYS flag but never auto-block in this rollout (see :mod:`hooks`) — network
    and address blocklists are higher-churn than pinned package versions, so we
    alert first while the false-positive rate is being validated.
    """
    text = injection_scan_text(args)
    if not text:
        return []
    candidates = content_scanners.iter_ioc_candidates(text)
    rules = ioc_rules(ruleset, candidates)
    out: List[Finding] = []
    seen: set = set()
    for ident in candidates:
        rule = rules.get(ident)
        if rule is None or ident in seen:
            continue
        seen.add(ident)
        src = _rule_source(rule)
        ioc_type = rule.get("iocType") or (ident.split(":", 2) + ["", ""])[1]
        value = ident.split(":", 2)[2] if ident.count(":") >= 2 else ident
        out.append(
            Finding(
                identifier=ident,
                category="ioc",
                severity=rule.get("severity", "high"),
                title=rule.get("name") or f"Known-bad {ioc_type}",
                tool_name=tool_name or "",
                matched=value[:200],
                evidence=f"{ioc_type} {value}"[:200],
                confirmed=src == "public",
                source=src,
                kind=rule.get("kind"),
                fields={"ioc_type": ioc_type, "ioc_context": context},
            )
        )
    return out
