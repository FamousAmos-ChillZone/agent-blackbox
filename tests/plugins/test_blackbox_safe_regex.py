"""G6 — a scanning regex is compiled only when it cannot blow up (ReDoS hardening).

Python's ``re`` has no timeout, so patterns from the graph are refused BEFORE
compile when a repeat could backtrack exponentially. Blackbox's own built-in
heuristics pass the same checker, and every scanner finishes crafted
pathological inputs within a time budget.
"""

from __future__ import annotations

import re
import time

import pytest

from plugins.blackbox.detection import action_parsing, content_scanners, shell_shapes
from plugins.blackbox.ruleset import safe_regex


@pytest.mark.parametrize("pattern", [
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",   # the old domain extractor (FIX-0025)
    r"(a+)+$",                         # the classic
    r"(\w+\s?)*$",
    r"(?:ignore|skip)(\s*\w+)*previous",
    r"([a-z]+)*b",
    r"(?:.*a){10}",                    # bounded outer, unbounded inner
    r"(?:a|aa)+",
])
def test_patterns_that_can_backtrack_exponentially_are_refused(pattern):
    with pytest.raises(safe_regex.UnsafePattern):
        safe_regex.compile_bounded(pattern)


@pytest.mark.parametrize("pattern", [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?:reveal|show)\b[\s\S]{0,40}\bsystem\s+prompt",
    r"<\|endoftext\|>",
    r"\b(?:curl|wget)\b[\s\S]{0,300}--data",
    r"https?://[^\s'\"<>|\\)}\]]+",
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z]{2,24}\b",
])
def test_linear_scanning_patterns_pass(pattern):
    assert safe_regex.compile_bounded(pattern, re.IGNORECASE)


def test_oversized_and_invalid_patterns_are_refused():
    with pytest.raises(safe_regex.UnsafePattern):
        safe_regex.compile_bounded("a" * 600)
    with pytest.raises(safe_regex.UnsafePattern):
        safe_regex.compile_bounded("(unclosed")
    with pytest.raises(safe_regex.UnsafePattern):
        safe_regex.compile_bounded("(?:ab){0,5000}")   # a group repeated past the cap


def _builtin_patterns():
    found = []
    for module in (content_scanners, action_parsing, shell_shapes):
        for name in dir(module):
            value = getattr(module, name)
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                parts = item if isinstance(item, tuple) else (item,)
                for part in parts:
                    if isinstance(part, re.Pattern):
                        found.append((f"{module.__name__}.{name}", part.pattern))
    return found


def test_every_built_in_scanning_regex_passes_the_same_checker():
    patterns = _builtin_patterns()
    assert len(patterns) >= 20
    for where, pattern in patterns:
        safe_regex.check_bounded(pattern)   # raises with the location in the message on failure


@pytest.mark.parametrize("payload", [
    "a" * 50_000,
    "ignore " * 8_000,
    "reveal " * 7_000 + "x",
    ("curl " + "-" * 40 + " ") * 1_000,
    "http://" + "a" * 60_000,
    "." * 50_000,
    "aaa.bbb.ccc" * 5_000,
])
def test_the_scanners_finish_pathological_inputs_quickly(payload):
    started = time.monotonic()
    content_scanners.scan_injection_heuristics(payload)
    content_scanners.iter_ioc_candidates(payload)
    content_scanners.scan_skill_dangers(payload, payload[:2_000])
    action_parsing.parse_dependency_installs(payload)
    assert time.monotonic() - started < 1.5
