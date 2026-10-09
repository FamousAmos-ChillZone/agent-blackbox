"""Compile a scanning regex only if it cannot blow up (G6 — ReDoS hardening).

Injection patterns come from the verified graph and are RUN on every tool
call and every model request. Python's ``re`` has no timeout, so a single
pattern with nested unbounded repetition (``(a+)+``, ``(\\w+\\s?)*``) could hang
the scanner on a crafted input — a security scanner that can be hung by its
own regex. The one defence that works without a timeout is to refuse such
patterns BEFORE they are compiled, with a conservative structural rule:

* a repeat may be unbounded (``*``, ``+``, ``{n,}``) only when it repeats a
  single atom (a literal, a class, ``.``, ``\\s``, ``\\S``…) — linear scans;
* a repeat of a GROUP must be bounded, and the bound is capped
  (:data:`MAX_GROUP_REPEAT`); an unbounded single-atom repeat INSIDE a group
  is allowed only when every enclosing repeat is optional (``(?:all\\s+)?``),
  never under a group that can iterate (``(\\s+a){0,5}`` backtracks
  combinatorially);
* the pattern is capped in length and in the number of repeats.

Everything else the scanners need (``[\\s\\S]{0,40}``, ``\\s+``, ``(?:a|b)``,
``\\b``) passes. The same compiler also checks Blackbox's own built-in
heuristics in tests, so a careless edit cannot ship a pathological pattern.

Usage::

    compiled = safe_regex.compile_bounded(pattern_src, re.IGNORECASE)   # or raises UnsafePattern
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Pattern

try:  # Python 3.11+
    from re import _parser as _sre_parser  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - older interpreters
    import sre_parse as _sre_parser  # type: ignore[no-redef]

#: Longest pattern source accepted (the graph's literal cap is 512).
MAX_PATTERN_CHARS = 512
#: Most repeat operators one pattern may contain.
MAX_REPEATS = 40
#: Highest bound a repeat of a GROUP may carry (``(?:…){0,400}``).
MAX_GROUP_REPEAT = 400

_REPEAT_OPS = {getattr(_sre_parser, name) for name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(_sre_parser, name)}
_SINGLE_ATOM_OPS = {_sre_parser.LITERAL, _sre_parser.NOT_LITERAL, _sre_parser.IN, _sre_parser.ANY, _sre_parser.CATEGORY}
_MAXREPEAT = _sre_parser.MAXREPEAT


class UnsafePattern(ValueError):
    """A pattern the scanner must not run; the message says which rule it broke."""


def compile_bounded(pattern_src: str, flags: int = 0) -> Pattern[str]:
    """Compile *pattern_src* after :func:`check_bounded`."""
    check_bounded(pattern_src)
    return re.compile(pattern_src, flags)


def check_bounded(pattern_src: str) -> None:
    """Raise :class:`UnsafePattern` unless every repeat is linear-safe."""
    if len(pattern_src) > MAX_PATTERN_CHARS:
        raise UnsafePattern(f"pattern longer than {MAX_PATTERN_CHARS} characters")
    try:
        tree = _sre_parser.parse(pattern_src)
    except re.error as exc:
        raise UnsafePattern(f"not a valid regex: {exc}") from exc
    if _count_repeats(tree) > MAX_REPEATS:
        raise UnsafePattern(f"more than {MAX_REPEATS} repeat operators")
    _walk(tree, iterating=False)


def _items(node: Any) -> Iterable[Any]:
    """The (op, arg) items of a parsed sub-pattern (a SubPattern or a list)."""
    return list(node) if node is not None else []


def _walk(node: Any, *, iterating: bool) -> None:
    """*iterating*: some enclosing repeat can run more than once."""
    for op, arg in _items(node):
        if op in _REPEAT_OPS:
            low, high, body = arg
            single = len(body) == 1 and body[0][0] in _SINGLE_ATOM_OPS
            if high == _MAXREPEAT and iterating:
                raise UnsafePattern("an unbounded repeat inside a repeating group (nested quantifiers)")
            if not single:
                if high == _MAXREPEAT:
                    raise UnsafePattern("an unbounded repeat of a group — bound it, e.g. {0,40}")
                if high > MAX_GROUP_REPEAT:
                    raise UnsafePattern(f"a group repeated more than {MAX_GROUP_REPEAT} times")
            _walk(body, iterating=iterating or high > 1)
        elif op == _sre_parser.SUBPATTERN:
            _walk(arg[-1], iterating=iterating)
        elif op == _sre_parser.BRANCH:
            for branch in arg[1]:
                _walk(branch, iterating=iterating)
        elif op in (_sre_parser.ASSERT, _sre_parser.ASSERT_NOT):
            _walk(arg[1], iterating=iterating)
        elif op == getattr(_sre_parser, "ATOMIC_GROUP", object()):
            _walk(arg, iterating=iterating)


def _count_repeats(node: Any) -> int:
    total = 0
    for op, arg in _items(node):
        if op in _REPEAT_OPS:
            total += 1 + _count_repeats(arg[2])
        elif op == _sre_parser.SUBPATTERN:
            total += _count_repeats(arg[-1])
        elif op == _sre_parser.BRANCH:
            total += sum(_count_repeats(b) for b in arg[1])
        elif op in (_sre_parser.ASSERT, _sre_parser.ASSERT_NOT):
            total += _count_repeats(arg[1])
    return total
