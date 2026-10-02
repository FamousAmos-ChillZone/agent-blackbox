"""Prompt-injection detection: graph patterns, built-in heuristics, and the
text a tool call is scanned as.

* :func:`detect_injection` — match the ruleset's injection patterns (curated
  or community regexes, untrusted: each compiled and run defensively).
* :func:`discover_injection` — nominate built-in heuristic matches that the
  graph does not know yet.
* :func:`injection_scan_text` — flatten tool-call arguments into the text the
  two above scan.

Split out of :mod:`.detectors` (which runs them inside ``detect_all``).
"""

from __future__ import annotations

import logging
from typing import Any, List

from . import content_scanners
from .finding import Finding, _rule_source
from ..kernel import threat_ids

logger = logging.getLogger(__name__)

_MAX_INJECTION_TEXT = 50_000


def detect_injection(text: str, ruleset: Any) -> List[Finding]:
    """Match each cached injection regex against *text*.

    Patterns are peer-supplied and therefore untrusted: each is wrapped so a
    bad regex is skipped rather than raising. Text is capped for performance.
    """
    if not text:
        return []
    if len(text) > _MAX_INJECTION_TEXT:
        text = text[:_MAX_INJECTION_TEXT]
    out: List[Finding] = []
    seen: set = set()
    for rule in getattr(ruleset, "injection", []) or []:
        pattern = rule.get("pattern")
        identifier = rule.get("identifier", "")
        if pattern is None or identifier in seen:
            continue
        try:
            match = pattern.search(text)
        except Exception:  # pragma: no cover - untrusted regex
            continue
        if match:
            seen.add(identifier)
            src = _rule_source(rule)
            out.append(
                Finding(
                    identifier=identifier,
                    category="injection",
                    severity=rule.get("severity", "high"),
                    title=rule.get("name") or "Prompt injection pattern matched",
                    matched=str(match.group(0))[:200],
                    evidence=str(match.group(0))[:200],
                    confirmed=src == "public",
                    source=src,
                    # Community matches carry the fields needed for review.
                    fields={"pattern": rule.get("pattern_src")} if src == "community" else {},
                )
            )
    return out


def discover_injection(text: str, ruleset: Any) -> List[Finding]:
    """Built-in injection discovery: heuristic matches not already in the graph.

    Runs the built-in OWASP LLM01/LLM06 heuristics over *text* and nominates a
    candidate for each match whose identifier is not already a graph rule. The
    identifier is the hash of the heuristic's own regex source (a fixed
    signature; R1 never shares the text), so identical attacks dedupe to one
    candidate. PRIVACY: the matched user substring is kept ONLY as local
    ``evidence``/``matched`` and is NEVER placed in ``fields`` (the sole part of
    a finding forwarded to the community graph).
    """
    known: set = set()
    for rule in getattr(ruleset, "injection", []) or []:
        ident = rule.get("identifier")
        if ident:
            known.add(ident)
    out: List[Finding] = []
    seen: set = set()
    for hit in content_scanners.scan_injection_heuristics(text or ""):
        signature = hit["pattern"]                 # heuristic regex source (shareable)
        phrase = hit.get("phrase", "")             # matched user text (local only)
        identifier = threat_ids.injection_identifier(signature)
        if identifier in known or identifier in seen:
            continue
        seen.add(identifier)
        out.append(
            Finding(
                identifier=identifier,
                category="injection",
                severity=hit.get("severity", "high"),
                title="Suspicious prompt-injection phrase",
                matched=phrase,
                evidence=phrase,
                confirmed=False,
                source="heuristic",
                fields={"owasp_category": hit.get("owasp")},   # R1: the identifier is the hash; no pattern text
            )
        )
    return out


def injection_scan_text(args: Any) -> str:
    """Flatten tool-call *args* into raw text for injection scanning.

    ``json.dumps`` escapes real newlines/tabs inside string values to the
    literal two-character sequences (``\\n``), which defeats the ``\\s`` in
    injection patterns and lets a multi-line payload slip past even a curated,
    blockable rule. This instead concatenates every nested string value with
    real newlines preserved, so whitespace-tolerant patterns still match.
    """
    if isinstance(args, str):
        return args
    parts: List[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)

    walk(args)
    return "\n".join(parts)
