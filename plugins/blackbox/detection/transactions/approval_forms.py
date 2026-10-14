"""Every form a token approval is written in — the parsing half of :mod:`.approvals`.

:func:`approvals_in` reads a tool call's text and returns each approval it would
send as an :class:`~.approval_calls.Approval`: who may spend, whether the amount is
unlimited, and which kind. Pure: no I/O, no ruleset; :mod:`.approvals` decides what
a found approval means. Each form has its own parser:

* :mod:`.cast_forms` — Foundry ``cast`` and ``spl-token`` command lines;
* :mod:`.calldata` — raw ABI calldata, however its hex is written;
* :mod:`.script_forms` — ethers / web3.py / viem code, variables followed;
* :mod:`.permits` — EIP-712 permit signatures (EIP-2612 and Permit2).

Usage::

    approvals_in("cast send 0xA0b8… 'approve(address,uint256)' 0xdead… 1157920…935")
    # -> [Approval(spender="0x…dead", unlimited=True, kind="approve")]
"""

from __future__ import annotations

import re
import shlex

from . import calldata, cast_forms, permits, script_forms
from .approval_calls import Approval

__all__ = ["Approval", "approvals_in"]

_CONTINUATION = re.compile(r"\\\r?\n")


def _shell_words(text: str) -> list[str]:
    """The call's shell words (quotes and ``\\``-newline continuations resolved)."""
    text = _CONTINUATION.sub(" ", text)   # shlex would keep the escaped newline inside a word
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def approvals_in(text: str) -> list[Approval]:
    """Every token approval *text* would send (see the module doc), each once."""
    if not text:
        return []
    found = (cast_forms.from_words(_shell_words(text)) + calldata.from_text(text)
             + script_forms.from_text(text) + permits.from_text(text))
    return list(dict.fromkeys(found))
