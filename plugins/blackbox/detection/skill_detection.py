"""Skill detection: known-bad skill versions from the graph, and dangerous
code or over-broad permissions in a skill being installed or modified.

Split out of :mod:`.detectors` (which runs it inside ``detect_all``).
"""

from __future__ import annotations

from typing import Any, List

from . import action_parsing
from . import content_scanners
from .finding import Finding, _rule_source
from ..kernel import threat_ids


def detect_skill(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Detect a suspicious skill install/modify (graph known-bad or built-in).

    Three signals: known-bad ``skill:{name}@{version}`` from the graph;
    dangerous-code shapes; and over-broad permission grants. PRIVACY: heuristic
    fields carry the code's sha256 + danger shape, never source or name (KI-159).
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
        ident = threat_ids.skill_artifact_identifier(skill["artifact_hash"], shape)   # never the name (KI-159)
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
                fields={"artifact_hash": skill["artifact_hash"], "danger_shape": shape},
            )
        )
    return out
