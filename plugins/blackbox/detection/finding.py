"""The detection result type, shared by every detector.

:class:`Finding` is what each detector returns and what the guard reports,
audits and (through ``fields``) shares; :func:`_rule_source` reads a graph
rule's trust tier. Kept apart from the detectors so a detector can live in its
own file without an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Finding:
    """One detected threat. ``evidence`` is expected to already be redacted.

    ``source`` says which trust tier raised the finding:

    * ``"public"`` — matched the verified public threat graph (the source of
      truth). ``confirmed`` is True; blockable in block mode.
    * ``"community"`` — matched a rule seen only in the shared community pool.
      Flagged (and re-reported to strengthen the consensus signal) but NEVER
      blocks: anyone can write to the community pool.
    * ``"heuristic"`` — raised only by a built-in discovery heuristic; a
      *candidate* nominated to the community graph.
    * ``"custom"`` — matched a user-configured local rule (e.g. a protected
      path). Always flags, blocks in block mode, never shared to SWM.

    ``confirmed`` is kept as the strict "public graph says so" bit — only
    confirmed findings can block. ``fields`` carries the privacy-safe threat
    attributes (pattern/toolName/category/skillName/...) that the auto-submit
    path forwards to ``build_report_quads``. It NEVER contains raw prompts,
    paths, or file/skill source.
    """

    identifier: str
    category: str  # injection | escalation | dependency | fileaccess | skill
    severity: str
    title: str
    tool_name: str = ""
    matched: str = ""
    evidence: str = ""
    confirmed: bool = True
    source: str = "public"  # public | community | heuristic | custom
    # malware | vulnerability | historical; vulnerability/historical never block
    kind: Optional[str] = None
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "tool_name": self.tool_name,
            "matched": self.matched,
            "evidence": self.evidence,
            "confirmed": self.confirmed,
            "candidate": not self.confirmed,
            "source": self.source,
            "kind": self.kind,
            "fields": dict(self.fields),
        }


def _rule_source(rule: Dict[str, Any]) -> str:
    """Trust tier of a graph rule. Untagged rules default to ``public`` —
    rules built before tier tagging (or handed in directly by tests) were
    always treated as verified."""
    src = str(rule.get("source") or "public").lower()
    return src if src in ("public", "community") else "public"


#: What a lookup answer says about itself when the graph store could not answer and
#: the operator's opt-in local index did (the finding then carries ``answered_by``).
FALLBACK_REASON = "fallback index"
ANSWERED_BY_FALLBACK = "local index (graph store down)"


def mark_answered_by(answer: Any) -> Dict[str, Dict[str, Any]]:
    """The answer's rules; when the graph store was down and the local index answered,
    each rule is copied with ``answered_by`` set so the finding and the audit row say so."""
    rules = getattr(answer, "rules", {}) or {}
    if getattr(answer, "reason", "") != FALLBACK_REASON:
        return rules
    return {key: {**rule, "answered_by": ANSWERED_BY_FALLBACK} for key, rule in rules.items()}
