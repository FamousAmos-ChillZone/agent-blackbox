"""Pure, testable matcher over a :class:`~plugins.blackbox.ruleset.Ruleset`.

No hardcoded threat rules act as truth: every rule comes from the graph-synced
ruleset, in two trust tiers. Rules tagged ``source: "public"`` come from the
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
import json
import logging
import os
from typing import Any, Iterable, List

from . import action_parsing
from . import content_scanners
from . import shell_shapes
from .finding import Finding, _rule_source
from .injection_detection import detect_injection, discover_injection, injection_scan_text
from ..kernel import threat_ids

logger = logging.getLogger(__name__)

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
                    fields={"tool_name": tool_lower, "arg_shape": arg_shape} if src == "community" else {},
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


def _command_text(args: Any) -> str:
    if isinstance(args, str):
        return args
    if isinstance(args, dict):
        for key in ("command", "cmd", "shell", "script", "input"):
            val = args.get(key)
            if isinstance(val, str) and val:
                return val
        # Fall back to any string values joined.
        return " ".join(v for v in args.values() if isinstance(v, str))
    return ""


def detect_dependency(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Parse install commands, then look each package up in the ruleset.

    Only pinned installs (``name@version`` / ``name==version``) can match a
    ``dep:{eco}:{name}@{version}`` rule; unpinned installs have no version to
    key on and are skipped here (they surface as advisories elsewhere).
    """
    command = _command_text(args)
    if not command:
        return []
    dependency_rules = getattr(ruleset, "dependency", {}) or {}
    if not dependency_rules:
        return []
    out: List[Finding] = []
    seen: set = set()
    for dep in action_parsing.parse_dependency_installs(command):
        version = dep.get("version") or ""
        eco = dep["ecosystem"].lower()
        name = threat_ids.canonical_package_name(eco, dep["name"])
        # Exact pinned version first, then a package-level ``@*`` rule — whole-package
        # malware / typosquats where EVERY version is bad, including an unpinned
        # ``install <pkg>`` (which has no version to key on).
        candidates = [threat_ids.dependency_key(eco, dep["name"], version)] if version else []
        candidates.append(threat_ids.dependency_key(eco, dep["name"], "*"))
        key = next((k for k in candidates if k in dependency_rules), None)
        if key is None or key in seen:
            continue
        seen.add(key)
        rule = dependency_rules[key]
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
                    "package_version": version or "*",
                    "advisory_id": rule.get("advisoryId"),
                    "kind": rule.get("kind"),
                } if src == "community" else {},
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


def detect_skill(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Detect a suspicious skill install/modify (graph known-bad or built-in).

    Three signals: known-bad ``skill:{name}@{version}`` from the graph;
    dangerous-code shapes; and over-broad permission grants. PRIVACY: a finding
    carries the skill name + matched danger shape — never the full skill source.
    """
    skill = action_parsing.skill_install_arg(tool_name, args)
    if not skill:
        return []
    out: List[Finding] = []
    seen: set = set()
    name = skill["name"]
    version = skill["version"]
    # (a) known-bad from graph: match name@version or name against skill: rules.
    for rule in getattr(ruleset, "skill", []) or []:
        rule_name = str(rule.get("skillName", "")).strip().lower()
        rule_ver = str(rule.get("skillVersion", "")).strip()
        if rule_name and rule_name == name.lower() and (not rule_ver or rule_ver == version):
            ident = rule.get("identifier") or threat_ids.skill_version_identifier(name, version)
            if ident in seen:
                continue
            seen.add(ident)
            src = _rule_source(rule)
            historical = not rule_ver
            out.append(
                Finding(
                    identifier=ident,
                    category="skill",
                    severity="medium" if historical else rule.get("severity", "high"),
                    title=(
                        f"Historical threat report for {name} (version unspecified)"
                        if historical else rule.get("name") or f"Known-bad skill {name}"
                    ),
                    tool_name=skill.get("tool", "") or (tool_name or "").lower(),
                    matched=name,
                    evidence=(
                        f"Skill {name} was exploited in the past; the graph does not specify "
                        "an affected version, so the issue may be fixed in newer releases."
                        if historical else f"known-bad skill {name}"
                    ),
                    confirmed=src == "public",
                    source=src,
                    kind="historical" if historical else rule.get("kind"),
                    fields={"skill_name": name, "skill_version": version},
                )
            )
    # (b)+(c) built-in dangerous-code / over-broad-permission discovery.
    for danger in content_scanners.scan_skill_dangers(skill["code"], skill["permissions"]):
        shape = danger["dangerShape"]
        ident = threat_ids.skill_shape_identifier(name, shape)
        if ident in seen:
            continue
        seen.add(ident)
        out.append(
            Finding(
                identifier=ident,
                category="skill",
                severity=danger.get("severity", "high"),
                title=f"Suspicious skill {name} ({shape})",
                tool_name=(tool_name or "").lower(),
                matched=shape,
                evidence=f"skill {name}: {shape}",
                confirmed=False,
                source="heuristic",
                fields={"skill_name": name, "skill_version": version, "danger_shape": shape},
            )
        )
    return out


def detect_ioc(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Match indicators (domain/url/ip/hash/wallet/contract) in the tool args.

    Extracts candidate indicators from the flattened args and looks each up in
    the synced ``ioc`` rules. Only KNOWN-BAD values match, so extraction can be
    broad without raising false positives on unrelated tokens. IOC findings
    ALWAYS flag but never auto-block in this rollout (see :mod:`hooks`) — network
    and address blocklists are higher-churn than pinned package versions, so we
    alert first while the false-positive rate is being validated.
    """
    ioc_rules = getattr(ruleset, "ioc", {}) or {}
    if not ioc_rules:
        return []
    text = injection_scan_text(args)
    if not text:
        return []
    out: List[Finding] = []
    seen: set = set()
    for ident in content_scanners.iter_ioc_candidates(text):
        rule = ioc_rules.get(ident)
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
                fields={"ioc_type": ioc_type} if src == "community" else {},
            )
        )
    return out


def discover_dependency_candidates(tool_name: str, args: Any, ruleset: Any, osv_lookup: Any) -> List[Finding]:
    """Best-effort OSV auto-discovery of vulnerable installs not in the graph.

    Parses install commands, skips any pinned dep already covered by a graph
    rule, and calls *osv_lookup(ecosystem, name, version)* — which returns
    ``{advisory_id, severity}`` when OSV knows it vulnerable, else ``None``.
    Only OSV-VULNERABLE installs become candidates; clean deps are never
    surfaced (privacy). Runs OFF the blocking path — callers invoke this
    best-effort so it never delays or breaks the tool call.
    """
    command = _command_text(args)
    if not command:
        return []
    dependency_rules = getattr(ruleset, "dependency", {}) or {}
    out: List[Finding] = []
    seen: set = set()
    for dep in action_parsing.parse_dependency_installs(command):
        version = dep.get("version") or ""
        if not version:
            continue
        eco = dep["ecosystem"].lower()
        name = dep["name"]
        key = f"{eco}:{name.lower()}@{version}"
        if key in dependency_rules or key in seen:
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
                fields={
                    "ecosystem": eco,
                    "package_name": name,
                    "package_version": version,
                    "advisory_id": hit.get("advisory_id"),
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
    findings.extend(detect_injection(args_text, ruleset))
    if discover:
        findings.extend(discover_injection(args_text, ruleset))
    findings.extend(detect_fileaccess(tool_name, args, ruleset))
    findings.extend(detect_skill(tool_name, args, ruleset))
    findings.extend(detect_ioc(tool_name, args, ruleset))
    # Secret-value exposure always runs (not gated by discovery) — a real secret
    # in the tool args is a personal, always-on signal, never a graph candidate.
    findings.extend(detect_secret_exposure(tool_name, args))
    if not discover:
        findings = [f for f in findings if f.source != "heuristic"]
    return findings
