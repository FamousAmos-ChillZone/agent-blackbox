"""Every form a token approval is written in — the parsing half of :mod:`.approvals`.

:func:`approvals_in` reads a tool call's text and returns each approval it would
send as an :class:`Approval`: who may spend, whether the amount is unlimited, and
which kind. Pure: no I/O, no ruleset; :mod:`.approvals` decides what a found
approval means.

Usage::

    approvals_in("cast send 0xA0b8… 'approve(address,uint256)' 0xdead… 1157920…935")
    # -> [Approval(spender="0x…dead", unlimited=True, kind="approve")]
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

MAX_UINT256 = 2 ** 256 - 1
#: An amount this large is unlimited in practice (drainers use MAX; nobody holds 2^255).
_UNLIMITED_FLOOR = 2 ** 255
_MAX_WORDS = re.compile(r"MaxUint256|MAX_UINT(?:256)?|maxUint256|type\(uint256\)\.max|2\s*\*\*\s*256\s*-\s*1|\$\(cast max-uint\)|constants\.MaxUint256")
_ADDRESS = r"0x[0-9a-fA-F]{40}"
_SIGNATURES = {"approve(address,uint256)": "approve", "increaseallowance(address,uint256)": "approve",
               "setapprovalforall(address,bool)": "approve-all"}
_SELECTORS = re.compile(r"0x(095ea7b3|39509351|a22cb465)([0-9a-fA-F]{64})([0-9a-fA-F]{64})")
_SELECTOR_KIND = {"095ea7b3": "approve", "39509351": "approve", "a22cb465": "approve-all"}
_SCRIPT_APPROVE = re.compile(rf"\.approve\(\s*['\"]?({_ADDRESS})['\"]?\s*,\s*([^)]+)\)")
_SCRIPT_APPROVE_ALL = re.compile(rf"setApprovalForAll\(\s*['\"]?({_ADDRESS})['\"]?\s*,\s*(true|True|1)\s*\)")


@dataclass(frozen=True)
class Approval:
    """One approval a call would send: who may spend (lower-case address), whether it
    is unlimited, and ``kind`` — ``approve`` (an amount) or ``approve-all`` (every NFT)."""

    spender: str
    unlimited: bool
    kind: str


def _amount_unlimited(text: str) -> bool:
    text = text.strip().strip("'\"")
    if _MAX_WORDS.search(text):
        return True
    try:
        return int(text, 0) >= _UNLIMITED_FLOOR
    except ValueError:
        return False


def _from_cast(words: list[str]) -> list[Approval]:
    out: list[Approval] = []
    for index, word in enumerate(words):
        kind = _SIGNATURES.get(word.replace(" ", "").lower())
        if not kind or index + 2 >= len(words) or not re.fullmatch(_ADDRESS, words[index + 1]):
            continue
        value = words[index + 2]
        written = " ".join(words[index + 2:index + 4])   # "$(cast max-uint)" splits into two words
        unlimited = value.lower() in ("true", "1") if kind == "approve-all" else (
            _amount_unlimited(value) or bool(_MAX_WORDS.search(written)))
        out.append(Approval(words[index + 1].lower(), unlimited, kind))
    return out


def approvals_in(text: str) -> list[Approval]:
    """Every token approval *text* would send (see the module doc), each once."""
    if not text:
        return []
    try:
        words = shlex.split(text, posix=True)
    except ValueError:
        words = text.split()
    found = _from_cast(words)
    for selector, spender_word, amount_word in _SELECTORS.findall(text):
        kind = _SELECTOR_KIND[selector.lower()]
        amount = int(amount_word, 16)
        found.append(Approval("0x" + spender_word[-40:].lower(), amount == 1 if kind == "approve-all" else amount >= _UNLIMITED_FLOOR, kind))
    for spender, amount in _SCRIPT_APPROVE.findall(text):
        found.append(Approval(spender.lower(), _amount_unlimited(amount), "approve"))
    for operator, _flag in _SCRIPT_APPROVE_ALL.findall(text):
        found.append(Approval(operator.lower(), True, "approve-all"))
    return list(dict.fromkeys(found))
