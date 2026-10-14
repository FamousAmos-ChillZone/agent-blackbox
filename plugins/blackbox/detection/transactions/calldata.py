"""Approvals written as raw calldata: a selector from :data:`.approval_calls.APPROVAL_CALLS`
followed by its ABI-encoded 32-byte argument words.

Recognised however the hex is written: with ``0x`` or ``0X`` or none (a JSON
``"data":"095ea7b3…"``), upper or lower case, and split across lines (with or without
a ``\\`` continuation). An argument word that should hold an address but does not
start with 12 zero bytes is not that call (random hex that happens to begin with a
selector), so it is skipped.

Pure function over the call's text.

Usage::

    from_text("cast send 0xA0b8… 0x095ea7b3" + "00" * 12 + "dead…" + "ff" * 32)
    # -> [Approval(spender="0x…dead", unlimited=True, kind="approve")]
"""

from __future__ import annotations

import re

from .amounts import UNLIMITED_FLOOR
from .approval_calls import APPROVAL_CALLS, Approval

_CALLS_BY_SELECTOR = {call.selector: call for call in APPROVAL_CALLS.values()}
_MAX_WORDS = 1 + max(max(call.spender_at, call.amount_at) for call in APPROVAL_CALLS.values())
#: A line break inside a run of hex (indentation and a ``\\`` continuation included).
_HEX_LINE_BREAK = re.compile(r"(?<=[0-9a-fA-F])(?:[ \t]*\\?[ \t]*\r?\n[ \t]*)+(?=[0-9a-fA-F])")
_CALLDATA = re.compile(
    rf"(?<![0-9a-fA-F])(?:0x)?({'|'.join(_CALLS_BY_SELECTOR)})((?:[0-9a-f]{{64}}){{1,{_MAX_WORDS}}})",
    re.IGNORECASE)
_ADDRESS_PADDING = "0" * 24


def from_text(text: str) -> list[Approval]:
    """Every approval the raw calldata in *text* would send (see the module doc)."""
    out: list[Approval] = []
    for match in _CALLDATA.finditer(_HEX_LINE_BREAK.sub("", text)):
        call = _CALLS_BY_SELECTOR[match.group(1).lower()]
        body = match.group(2).lower()
        words = [body[start:start + 64] for start in range(0, len(body), 64)]
        if len(words) <= max(call.spender_at, call.amount_at):
            continue
        spender_word = words[call.spender_at]
        if not spender_word.startswith(_ADDRESS_PADDING):
            continue
        amount = int(words[call.amount_at], 16)
        unlimited = amount == 1 if call.kind == "approve-all" else amount >= UNLIMITED_FLOOR
        out.append(Approval("0x" + spender_word[24:], unlimited, call.kind))
    return out
