"""What an approval is, and the contract calls that make one — shared by every form parser.

:class:`Approval` is what each parser returns. :data:`APPROVAL_CALLS` is THE table of
calls that grant a spender a token allowance, keyed by their canonical signature, with
where the spender and the amount sit among the arguments and the 4-byte selector raw
calldata starts with (a test checks each selector against Keccak-256 of its signature).
The Foundry parser, the calldata scanner and the script parser all read it, so adding a
call here teaches all three.

Usage::

    call = APPROVAL_CALLS[signature_key("function approve(address spender, uint256 amount)")]
    call.kind, call.spender_at, call.amount_at    # "approve", 0, 1
    spender_from("'0xAbC…'")                      # "0xabc…" (lower-case), or an ENS name, or None
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Approval:
    """One approval a call would send.

    ``spender`` — who may spend: a lower-case ``0x`` address, a Solana address (base58,
    case kept), an ENS name (``name.eth``, which cannot be resolved offline), or ``""``
    when the call names it through an expression the parser could not trace;
    ``unlimited`` — the amount (or the approve-all flag) gives everything;
    ``kind`` — ``approve`` (an amount), ``approve-all`` (every NFT of a collection),
    ``permit`` (a signed approval) or ``delegate`` (a Solana token delegate)."""

    spender: str
    unlimited: bool
    kind: str


@dataclass(frozen=True)
class ApprovalCall:
    """One contract call that grants an allowance: its ``kind`` (see :class:`Approval`),
    the argument positions of the spender and the amount, and its 4-byte ``selector``."""

    kind: str
    spender_at: int
    amount_at: int
    selector: str


#: Canonical signature (lower-case name, argument types only) -> the call.
APPROVAL_CALLS: dict[str, ApprovalCall] = {
    "approve(address,uint256)": ApprovalCall("approve", 0, 1, "095ea7b3"),
    "increaseallowance(address,uint256)": ApprovalCall("approve", 0, 1, "39509351"),
    "increaseapproval(address,uint256)": ApprovalCall("approve", 0, 1, "d73dd623"),   # older OpenZeppelin tokens
    "setapprovalforall(address,bool)": ApprovalCall("approve-all", 0, 1, "a22cb465"),
}
#: Method name (lower-case) -> its call, for scripts that call the method by name.
CALLS_BY_NAME: dict[str, ApprovalCall] = {signature.split("(", 1)[0]: call for signature, call in APPROVAL_CALLS.items()}

#: ``name(type name, …)`` with an optional ``function`` keyword; a return type or
#: modifiers after the closing parenthesis are ignored.
_SIGNATURE = re.compile(r"\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(([^()]*)\)")
#: Solidity's short type names, spelled out as a selector is computed.
_TYPE_ALIASES = {"uint": "uint256", "int": "int256"}
EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_ENS_NAME = re.compile(r"(?:[a-z0-9-]+\.)+eth", re.IGNORECASE)
#: Characters shell or script syntax leaves stuck to an argument: quotes, a closing
#: ``)`` of ``$(…)``, a separating comma or semicolon.
_STUCK = "'\"`,;)"


def signature_key(text: str) -> Optional[str]:
    """The canonical signature *text* spells, e.g. ``approve(address,uint256)`` for
    ``'function approve(address spender, uint256 amount)'`` or
    ``'approve(address,uint256)(bool)'``; None when *text* is not a signature."""
    match = _SIGNATURE.match(text)
    if not match:
        return None
    types = [part.split()[0].lower() for part in match.group(2).split(",") if part.strip()]
    return f"{match.group(1).lower()}({','.join(_TYPE_ALIASES.get(t, t) for t in types)})"


def strip_stuck(word: str) -> str:
    """*word* without the quotes and punctuation shell or script syntax leaves on it."""
    return word.strip().strip(_STUCK).strip()


def spender_from(word: str) -> Optional[str]:
    """The spender *word* names: a ``0x`` address (lower-case) or an ENS name (lower-case);
    None for anything else."""
    word = strip_stuck(word)
    if EVM_ADDRESS.fullmatch(word):
        return word.lower()
    if _ENS_NAME.fullmatch(word):
        return word.lower()
    return None


def is_ens_name(spender: str) -> bool:
    """Whether *spender* (from :func:`spender_from`) is an ENS name, not an address."""
    return bool(_ENS_NAME.fullmatch(spender))
