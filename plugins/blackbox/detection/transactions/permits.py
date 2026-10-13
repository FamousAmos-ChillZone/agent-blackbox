"""Approvals by signature: EIP-712 typed data whose primary type is a permit.

A permit needs no transaction from the victim — only a signature
(``eth_signTypedData_v4``, ``cast wallet sign --data '…'``, viem ``signTypedData``),
which the drainer then submits. Recognised primary types: EIP-2612 ``Permit``
(``message.spender`` + ``message.value``) and Uniswap Permit2's ``PermitSingle`` /
``PermitBatch`` (``spender`` + ``details.amount``) and ``PermitTransferFrom`` /
``PermitBatchTransferFrom`` / ``PermitWitnessTransferFrom`` (``spender`` +
``permitted.amount``). The permit EIP-2612 sends as a transaction,
``permit(owner, spender, value, …)``, is in :data:`.approval_calls.APPROVAL_CALLS`.

The typed data may be JSON (quoted once more inside a JSON-RPC body or a shell
argument), a Python dict or a JavaScript object, so it is read by its keys rather
than parsed: the ``spender`` nearest the ``primaryType``, and every ``value`` /
``amount`` near it (unlimited when any is). A spender held in a variable is followed
like a script argument (:func:`.script_forms.resolve`).

Pure function over the call's text.

Usage::

    from_text('{"primaryType":"Permit","message":{"spender":"0x…dead","value":"1157…935"}}')
    # -> [Approval(spender="0x…dead", unlimited=True, kind="permit")]
"""

from __future__ import annotations

import re
from itertools import islice

from . import amounts
from .approval_calls import Approval
from .script_forms import resolve, spender_in

_PERMIT_TYPES = ("Permit", "PermitSingle", "PermitBatch", "PermitTransferFrom", "PermitBatchTransferFrom",
                 "PermitWitnessTransferFrom", "PermitBatchWitnessTransferFrom")
_PRIMARY_TYPE = re.compile(rf"""["']?primaryType["']?\s*:\s*["'`]({'|'.join(_PERMIT_TYPES)})["'`]""")
#: A key followed by a colon and its value; in the ``types`` section ``"spender"`` is a
#: field NAME (followed by a comma), so it never matches.
_SPENDER = re.compile(r"""["']?\bspender["']?\s*:\s*["'`]?([^"'`,}\s]+)""")
_AMOUNT = re.compile(r"""["']?\b(?:value|amount)["']?\s*:\s*["'`]?([^"'`,}\]\s]+)""")
#: How far around a primaryType its message may sit (the domain and types come between).
_REACH = 4000
_MAX_PERMITS = 20


def from_text(text: str) -> list[Approval]:
    """Every permit the typed data in *text* would sign (see the module doc)."""
    text = text.replace('\\"', '"')   # JSON quoted inside a JSON string or a shell argument
    out: list[Approval] = []
    for primary in islice(_PRIMARY_TYPE.finditer(text), _MAX_PERMITS):
        low, high = max(0, primary.start() - _REACH), primary.end() + _REACH
        spenders = list(_SPENDER.finditer(text, low, high))
        if spenders:
            nearest = min(spenders, key=lambda match: abs(match.start() - primary.start()))
            spender = spender_in(resolve(nearest.group(1), text, nearest.start()))
        else:
            spender = ""
        unlimited = any(amounts.is_unlimited(resolve(match.group(1), text, match.start()))
                        for match in _AMOUNT.finditer(text, low, high))
        if spender or unlimited:
            out.append(Approval(spender, unlimited, "permit"))
    return out
