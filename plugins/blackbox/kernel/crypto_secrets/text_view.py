"""A normalised reading of a text that remembers where every character came from.

An attacker who wants a seed phrase past a word matcher changes how the words are
WRITTEN, not what they are: percent-encoding (``%2C``, ``%0A``, even ``%61`` for "a",
double-encoded ``%2520``), invisible characters inside or between words (zero-width
space, soft hyphen, bidi marks), fullwidth letters, HTML entities, or CamelCase with no
separator at all. :func:`normalised` undoes those spellings in one linear pass and keeps
a map back to the original offsets, so a match found in the reading is redacted in the
original text exactly where it stood.

Pattern: Adapter — the recogniser reads one clean text; :meth:`TextView.original_span`
translates its answer back. The same rules are mirrored in the OpenClaw bridge
(``integrations/openclaw/src/seedPhrase.ts``) and checked byte-for-byte by the parity test.

Usage::

    view = normalised("abandon%2CabilityAble")
    view.text                      # "abandon,ability Able" (escape decoded, CamelCase split)
    view.original_span(0, 20)      # (0, 21): where that reading came from
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

#: One edit per match: a percent escape (any number of ``25`` layers) -> its character; an
#: invisible format character -> nothing (or a space, see :func:`readings`); a fullwidth ASCII character -> its ASCII form; an
#: HTML entity -> a space; a lower->Upper boundary (CamelCase) -> an inserted space.
_EDITS = re.compile(
    r"%(?:25)*([0-9A-Fa-f]{2})"
    r"|([\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff])"
    r"|([\uff01-\uff5e])"
    r"|(&(?:[A-Za-z]{2,8}|#[0-9]{1,6}|#[xX][0-9A-Fa-f]{1,6});)"
    r"|(?<=[a-z])(?=[A-Z])"
)
_FULLWIDTH_OFFSET = 0xFEE0


@dataclass(frozen=True)
class TextView:
    """``text`` — the normalised reading. ``_starts`` / ``_segments`` map it back: each
    segment is ``(view_start, view_length, original_start, original_length)``; a copied
    segment has equal lengths, an edited one is one view character for its whole edit."""

    text: str
    _starts: tuple[int, ...]
    _segments: tuple[tuple[int, int, int, int], ...]

    def _segment(self, view_offset: int) -> tuple[int, int, int, int]:
        return self._segments[bisect.bisect_right(self._starts, view_offset) - 1]

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """The original ``(start, end)`` that the reading's ``[start, end)`` came from
        (``end > start``): an edited character maps to its whole edit."""
        view_start, view_length, original_start, original_length = self._segment(start)
        copied = view_length == original_length
        begin = original_start + (start - view_start) if copied else original_start
        view_start, view_length, original_start, original_length = self._segment(end - 1)
        copied = view_length == original_length
        finish = original_start + (end - 1 - view_start) + 1 if copied else original_start + original_length
        return begin, finish


_PERCENT = re.compile(r"%(?:25)*([0-9A-Fa-f]{2})")


def percent_decoded(text: str) -> str:
    """*text* with every percent escape (any number of ``25`` layers) replaced by its
    character — the same decoding :func:`normalised` applies, for callers that want the
    decoded text itself (redaction reads a URL the way its receiver will)."""
    return _PERCENT.sub(lambda match: chr(int(match.group(1), 16)), text) if "%" in text else text


_INVISIBLE = re.compile(r"[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]")


def _replacement(match: re.Match[str], invisible: str) -> str:
    percent, hidden, fullwidth = match.group(1, 2, 3)
    if percent is not None:
        return chr(int(percent, 16))
    if fullwidth is not None:
        return chr(ord(fullwidth) - _FULLWIDTH_OFFSET)
    if hidden is not None:
        return invisible                               # an invisible character
    return " "                                         # an entity, or the CamelCase boundary


def readings(text: str) -> list[TextView]:
    """Every normalised reading of *text* a matcher should look at: one, or two when the
    text holds an invisible character — it may hide INSIDE a word ("aban\u200bdon": drop
    it) or stand BETWEEN words ("abandon\u200bability": a separator), and only reading
    it both ways finds both."""
    if _INVISIBLE.search(text):
        return [normalised(text), normalised(text, invisible=" ")]
    return [normalised(text)]


def normalised(text: str, invisible: str = "") -> TextView:
    """The normalised reading of *text* (see module doc), invisible characters replaced
    by *invisible* (dropped by default). Linear in ``len(text)``."""
    pieces: list[str] = []
    segments: list[tuple[int, int, int, int]] = []
    view = original = 0
    for match in _EDITS.finditer(text):
        if match.start() > original:                   # the untouched stretch before this edit
            length = match.start() - original
            pieces.append(text[original:match.start()])
            segments.append((view, length, original, length))
            view += length
        replacement = _replacement(match, invisible)
        if replacement:
            pieces.append(replacement)
            segments.append((view, 1, match.start(), match.end() - match.start()))
            view += 1
        original = match.end()
    if original < len(text) or not segments:
        length = len(text) - original
        pieces.append(text[original:])
        segments.append((view, length, original, length))
    return TextView("".join(pieces), tuple(segment[0] for segment in segments), tuple(segments))
