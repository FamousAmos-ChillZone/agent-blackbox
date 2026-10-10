"""Pure, testable matcher over a :class:`~plugins.blackbox.ruleset.Ruleset`.

No hardcoded threat rules act as truth: every rule comes from the graph, in two
trust tiers. Public dependency and IOC rules are ASKED of the ruleset object
(``dependency_rules`` / ``ioc_rules``: a live lookup against the node's local
store, with the compiled dicts filling in — DKG-lookup B4); the small tiers are
scanned from the compiled lists. Rules tagged ``source: "public"`` come from the
verified public threat graph (verifiable-memory) — the source of truth: if it's
there, it's a threat, and a match is CONFIRMED (blockable). Rules tagged
``source: "community"`` come from the shared community pool — a match is
flagged but can never block. Built-in heuristics only *nominate* candidates
(``source: "heuristic"``) for the community graph.

All matching is resilient to peer-supplied garbage: regex compile/exec errors
are caught per rule and oversized inputs are capped.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from typing import Any, Dict, Iterable, List

from . import action_parsing
from . import content_scanners
from . import osv
from . import shell_shapes
from .finding import ANSWERED_BY_FALLBACK, FALLBACK_REASON, Finding, _rule_source, mark_answered_by  # noqa: F401 — re-exported for callers
from .injection_detection import detect_injection, discover_injection, injection_scan_text
from .ioc_detection import detect_ioc, ioc_context
from .skill_detection import detect_skill
from ..kernel import threat_ids

logger = logging.getLogger(__name__)

def _dependency_candidates(dep: Dict[str, Any]) -> List[Any]:
    """The ``(ecosystem, name, version)`` candidates one parsed install can match:
    the exact pinned version first, then the package-level ``@*`` rule — whole-
    package malware / typosquats where EVERY version is bad, including an
    unpinned ``install <pkg>`` (which has no version to key on)."""
    ecosystem = dep["ecosystem"].lower()
    version = dep.get("version") or ""
    return ([(ecosystem, dep["name"], version)] if version else []) + [(ecosystem, dep["name"], "*")]


def dependency_rules(ruleset: Any, candidates: List[Any]) -> Dict[str, Dict[str, Any]]:
    """The dependency rules for ``(ecosystem, name, version)`` *candidates*, keyed
    by ``dependency_key``. A :class:`~..ruleset.Ruleset` answers through
    ``dependency_rules()`` (live verified lookup first, compiled dict after);
    a bare object with a ``dependency`` dict (tests, older callers) is indexed.
    A rule the fallback index answered carries ``answered_by`` (see :func:`mark_answered_by`)."""
    if not candidates:
        return {}
    ask = getattr(ruleset, "dependency_rules", None)
    if callable(ask):
        return mark_answered_by(ask(candidates))
    compiled = getattr(ruleset, "dependency", {}) or {}
    keys = (threat_ids.dependency_key(ecosystem, name, version) for ecosystem, name, version in candidates)
    return {key: compiled[key] for key in keys if key in compiled}


def detect_escalation(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Match a tool call against escalation rules on BOTH toolName AND argShape.

    This is the fix for the original bug where only the tool name (or only the
    shape) was compared. We compute the observed shape once and require an
    exact (tool_name, arg_shape) match against a cached rule.
    """
    arg_shape = shell_shapes.normalize_arg_shape(tool_name or "", args)
    if not arg_shape:
        return []
    tool_lower = (tool_name or "").strip().lower()
    out: List[Finding] = []
    seen: set = set()
    for rule in getattr(ruleset, "escalation", []) or []:
        identifier = rule.get("identifier", "")
        rule_tool = str(rule.get("toolName", "")).strip().lower()
        rule_shape = str(rule.get("argShape", "")).strip()
        if identifier in seen:
            continue
        # Both must match. This is the corrected contract.
        if rule_tool == tool_lower and rule_shape == arg_shape:
            seen.add(identifier)
            src = _rule_source(rule)
            out.append(
                Finding(
                    identifier=identifier,
                    category="escalation",
                    severity=rule.get("severity", "high"),
                    title=rule.get("name") or f"Dangerous {tool_lower} call ({arg_shape})",
                    tool_name=tool_name or "",
                    matched=arg_shape,
                    evidence=arg_shape,
                    confirmed=src == "public",
                    source=src,
                    fields={"tool_name": tool_lower, "arg_shape": arg_shape},
                )
            )
    # Discovery layer: a dangerous shape that no graph rule covers is still a
    # candidate escalation nominated to the community graph — except for shapes
    # that overlap routine behaviour (e.g. `curl … | bash` installers), which
    # only ever match an explicitly curated rule, never self-nominate.
    if not out and arg_shape not in shell_shapes.NO_AUTO_NOMINATE_SHAPES:
        candidate_id = threat_ids.escalation_identifier(tool_lower, arg_shape)
        out.append(
            Finding(
                identifier=candidate_id,
                category="escalation",
                severity="high",
                title=f"Suspicious {tool_lower} call ({arg_shape})",
                tool_name=tool_name or "",
                matched=arg_shape,
                evidence=arg_shape,
                confirmed=False,
                source="heuristic",
                fields={"tool_name": tool_lower, "arg_shape": arg_shape},
            )
        )
    return out


def detect_dependency(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Parse install commands, then look each package up in the ruleset.

    Only pinned installs (``name@version`` / ``name==version``) can match a
    ``dep:{eco}:{name}@{version}`` rule; unpinned installs have no version to
    key on and are skipped here (they surface as advisories elsewhere).
    """
    command = action_parsing.command_text(args)
    if not command:
        return []
    installs = action_parsing.parse_dependency_installs(command)
    # One round trip asks for every candidate of every install at once.
    rules = dependency_rules(ruleset, [c for dep in installs for c in _dependency_candidates(dep)])
    out: List[Finding] = []
    seen: set = set()
    for dep in installs:
        version = dep.get("version") or ""
        eco = dep["ecosystem"].lower()
        name = threat_ids.canonical_package_name(eco, dep["name"])
        keys = [threat_ids.dependency_key(*candidate) for candidate in _dependency_candidates(dep)]
        key = next((k for k in keys if k in rules), None)
        if key is None or key in seen:
            continue
        seen.add(key)
        rule = rules[key]
        src = _rule_source(rule)
        shown = version or "*"
        out.append(
            Finding(
                identifier=rule.get("identifier") or f"dep:{key}",
                category="dependency",
                severity=rule.get("severity", "high"),
                title=rule.get("name") or f"Vulnerable dependency {name}@{shown}",
                tool_name=tool_name or "",
                matched=key,
                evidence=f"{dep['ecosystem']}:{dep['name']}@{shown}"
                + (f" ({rule.get('advisoryId')})" if rule.get("advisoryId") else ""),
                confirmed=src == "public",
                source=src,
                kind=rule.get("kind"),
                fields={
                    "ecosystem": eco,
                    "package_name": name,
                    "package_version": key.rsplit("@", 1)[1],   # the matched rule's version (or "*")
                    "advisory_id": rule.get("advisoryId"),
                    "kind": rule.get("kind"), "reason": osv.advisory_reason(rule.get("advisoryId")),
                    **({"answered_by": rule["answered_by"]} if rule.get("answered_by") else {}),
                },
            )
        )
    return out


def detect_fileaccess(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Detect access to a sensitive-path category (graph rule or built-in).

    A file-access tool call whose path falls in a sensitive category is a
    finding. If a curated ``fileaccess:{tool}:{category}`` graph rule matches it
    is CONFIRMED; otherwise the built-in category detector nominates a
    candidate. PRIVACY: the finding carries ONLY the category + tool — never
    the exact path or file contents.
    """
    access = action_parsing.file_access_arg(tool_name, args)
    if not access:
        return []
    hit = action_parsing.sensitive_path_category(access["path"], args)
    if not hit:
        return []
    tool = access["tool"]
    category = hit["category"]
    identifier = threat_ids.fileaccess_identifier(tool, category)
    severity = hit["severity"]
    source = "heuristic"
    name = None
    for rule in getattr(ruleset, "fileaccess", []) or []:
        if str(rule.get("toolName", "")).lower() == tool and str(rule.get("category", "")).lower() == category:
            source = _rule_source(rule)
            severity = rule.get("severity", severity)
            name = rule.get("name")
            identifier = rule.get("identifier", identifier)
            break
    return [
        Finding(
            identifier=identifier,
            category="fileaccess",
            severity=severity,
            title=name or f"Sensitive file access ({category})",
            tool_name=tool,
            matched=category,
            evidence=f"{access['mode']} {category}",
            confirmed=source == "public",
            source=source,
            fields={"tool_name": tool, "file_category": category},
        )
    ]


def discover_dependency_candidates(tool_name: str, args: Any, ruleset: Any, osv_lookup: Any) -> List[Finding]:
    """Best-effort OSV auto-discovery of bad installs not in the graph.

    Parses install commands, skips pinned deps a graph rule covers, and calls
    *osv_lookup(ecosystem, name, version)* (``{advisory_id, severity, kind}``
    or ``None``, see :func:`.osv.lookup`). Only OSV-flagged installs become
    candidates; clean deps never surface (privacy). Runs OFF the blocking path.
    """
    command = action_parsing.command_text(args)   # "" parses to no installs
    pinned = [dep for dep in action_parsing.parse_dependency_installs(command) if dep.get("version")]
    covered = dependency_rules(ruleset, [(dep["ecosystem"].lower(), dep["name"], dep["version"]) for dep in pinned])
    out: List[Finding] = []
    seen: set = set()
    for dep in pinned:
        version = dep["version"]
        eco = dep["ecosystem"].lower()
        name = dep["name"]
        key = threat_ids.dependency_key(eco, name, version)   # the same key the graph rule has (PyPI names canonical)
        if key in covered or key in seen:
            continue  # already a graph rule (confirmed elsewhere) or duped
        seen.add(key)
        try:
            hit = osv_lookup(eco, name, version)
        except Exception:  # pragma: no cover - fail open
            hit = None
        if not hit:
            continue
        identifier = threat_ids.dependency_identifier(eco, name, version)
        out.append(
            Finding(
                identifier=identifier,
                category="dependency",
                severity=hit.get("severity", "high"),
                title=f"OSV-vulnerable dependency {name}@{version}",
                tool_name=tool_name or "",
                matched=key,
                evidence=f"{eco}:{name}@{version} ({hit.get('advisory_id')})",
                confirmed=False,
                source="heuristic",
                kind=hit.get("kind"),
                fields={
                    "ecosystem": eco,
                    "package_name": name,
                    "package_version": version,
                    "advisory_id": hit.get("advisory_id"),
                    "kind": hit.get("kind"),   # malware shares; a vulnerability stays local (decision 22)
                    "reason": osv.advisory_reason(hit.get("advisory_id")),
                },
            )
        )
    return out


def _protected_path_match(path: str, pattern: str) -> bool:
    """True when *path* matches a user's protected-path *pattern*.

    Patterns are matched three ways so plain paths, directories, and globs all
    behave intuitively: exact/glob match on the full expanded path, glob match
    on the basename (``*.pem``), and prefix match when the pattern names a
    directory (``~/secrets`` protects everything under it).
    """
    try:
        norm_path = os.path.normpath(os.path.expanduser(str(path or "")))
        norm_pat = os.path.normpath(os.path.expanduser(str(pattern or "")))
        if not norm_path or not norm_pat:
            return False
        if fnmatch.fnmatch(norm_path, norm_pat):
            return True
        if fnmatch.fnmatch(os.path.basename(norm_path), norm_pat):
            return True
        # Directory-prefix semantics for glob-free patterns.
        if not any(ch in norm_pat for ch in "*?[") and (
            norm_path == norm_pat or norm_path.startswith(norm_pat.rstrip(os.sep) + os.sep)
        ):
            return True
    except Exception:  # pragma: no cover - fail open
        return False
    return False


def detect_custom_fileaccess(
    tool_name: str, args: Any, protected_paths: Iterable[str]
) -> List[Finding]:
    """Match file-access tool calls against the USER'S protected-path list.

    These are personal, locally-configured rules (``source="custom"``): they
    always flag, they block in block mode (the user wrote the rule), and they
    are NEVER reported to the community graph — the matched pattern is the
    user's own configuration, not shared threat intel.
    """
    patterns = [p for p in (protected_paths or []) if str(p or "").strip()]
    if not patterns:
        return []
    access = action_parsing.file_access_arg(tool_name, args)
    if not access:
        return []
    for pattern in patterns:
        if _protected_path_match(access["path"], pattern):
            tool = access["tool"]
            return [
                Finding(
                    identifier=threat_ids.fileaccess_identifier(tool, "user-protected"),
                    category="fileaccess",
                    severity="critical",
                    title="Access to a user-protected path",
                    tool_name=tool,
                    matched="user-protected",
                    evidence=f"{access['mode']} path matching protected pattern {str(pattern)[:120]}",
                    confirmed=False,
                    source="custom",
                    fields={},
                )
            ]
    return []


def detect_secret_exposure(tool_name: str, args: Any) -> List[Finding]:
    """Flag a real secret VALUE (API key, token, private key) in the tool args.

    Complements the sensitive-FILE detection: this fires when the agent is
    actually *handling* a recognizable secret — e.g. passing an ``sk-…`` key in a
    command, or a private-key block. If the same call also sends data off-box
    (``curl --data``, ``nc``, …), it is treated as exfiltration and escalated to
    critical (blockable). Findings are ``source="secret"``: local-only (the
    value never leaves the machine — only the TYPE is recorded) and blockable.
    """
    text = injection_scan_text(args)
    if not text:
        return []
    hits = content_scanners.scan_secret_values(text)
    if not hits:
        return []
    egress = content_scanners.looks_like_egress(text)
    out: List[Finding] = []
    for hit in hits:
        severity = "critical" if (egress and hit["severity"] != "critical") else hit["severity"]
        prefix = "Secret exfiltration" if egress else "Secret exposed"
        out.append(
            Finding(
                identifier=f"secret:{hit['type']}",
                category="secret",
                severity=severity,
                title=f"{prefix}: {hit['type']}",
                tool_name=tool_name or "",
                matched=hit["type"],   # TYPE only — never the secret value
                evidence=hit["type"],
                confirmed=False,
                source="secret",
            )
        )
    return out


def detect_all(tool_name: str, args: Any, ruleset: Any, discover: bool = True) -> List[Finding]:
    """Run every detector (graph rules + built-in discovery) across categories.

    Graph-backed detection (public + community rules) ALWAYS runs for every
    category. When *discover* is False only the built-in heuristic candidates
    are suppressed — a curated fileaccess/skill/escalation rule keeps firing.
    Dependency OSV auto-discovery is NOT run here — it is best-effort and runs
    off the blocking path (see :mod:`hooks`).
    """
    findings: List[Finding] = []
    findings.extend(detect_escalation(tool_name, args, ruleset))
    findings.extend(detect_dependency(tool_name, args, ruleset))
    args_text = injection_scan_text(args)
    # Text in a skill being installed is "in-skill"; other arguments have no context (stays local).
    context = "in-skill" if action_parsing.skill_install_arg(tool_name, args) else None
    findings.extend(detect_injection(args_text, ruleset, context))
    if discover:
        findings.extend(discover_injection(args_text, ruleset, context))
    findings.extend(detect_fileaccess(tool_name, args, ruleset))
    findings.extend(detect_skill(tool_name, args, ruleset))
    findings.extend(detect_ioc(tool_name, args, ruleset, ioc_context(tool_name, args)))
    # Secret exposure always runs (not gated by discovery): personal, never a graph candidate.
    findings.extend(detect_secret_exposure(tool_name, args))
    if not discover:
        findings = [f for f in findings if f.source != "heuristic"]
    return findings
