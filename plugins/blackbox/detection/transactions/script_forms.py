"""Approvals written as script code: ethers, web3.py and viem.

Three call shapes, each naming a call in :data:`.approval_calls.CALLS_BY_NAME`:

* a method call — ``token.approve(s, MAX)``, ``contract.functions.setApprovalForAll(op, True)``,
  ``token.permit(owner, spender, value, …)``, ``token.approve.populateTransaction(…)``;
* viem — ``writeContract({ functionName: 'approve', args: [spender, maxUint256] })``;
* ethers' Interface — ``iface.encodeFunctionData("approve", [spender, MAX])``.

An argument may be a literal or a variable assigned earlier in the same text
(``s = '0x…'`` … ``token.approve(s, …)``), possibly wrapped in a conversion
(``Web3.to_checksum_address(s)``, ``getAddress(s)``): :func:`resolve` follows the
assignment (a few hops at most). A spender that cannot be traced still counts when
the amount gives everything. Solidity-style declarations (``function approve(address
spender, uint256 amount)``) and signature strings are not calls and are skipped.

Pure functions over the call's text.

Usage::

    from_text("s = '0x…dead'\\nawait token.approve(s, ethers.MaxUint256)")
    # -> [Approval(spender="0x…dead", unlimited=True, kind="approve")]
"""

from __future__ import annotations

import re
from itertools import islice
from typing import Optional

from . import amounts
from .approval_calls import CALLS_BY_NAME, EVM_ADDRESS, Approval, ApprovalCall, spender_from

_NAMES = "|".join(CALLS_BY_NAME)
_METHOD_CALL = re.compile(rf"(?<![\w$])({_NAMES})(?:\.(?:populateTransaction|estimateGas|staticCall|send))?\s*\(", re.IGNORECASE)
_VIEM_NAME = re.compile(rf"functionName\s*:\s*['\"`]({_NAMES})['\"`]", re.IGNORECASE)
_VIEM_ARGS = re.compile(r"\bargs\s*:\s*\[")
_ENCODE_CALL = re.compile(rf"encodeFunctionData\(\s*['\"`]({_NAMES})['\"`]\s*,\s*\[", re.IGNORECASE)
_DECLARATION = re.compile(r"(?:function|def)\s+$")
_TYPE_NAME = re.compile(r"(?:address|bool|string|u?int\d*|bytes\d*)(?:\s+(?:calldata|memory)?\s*\w+)?")
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
_WRAPPED = re.compile(r"[\w$.]+\(\s*(.+?)\s*\)")
_CLOSERS = {"(": ")", "[": "]", "{": "}"}
#: How far a viem ``args`` array may sit from its ``functionName`` (same object literal).
_VIEM_REACH = 600
#: Bounds that keep a huge tool call linear: characters read for one argument list,
#: assignments followed, how far back an assignment is looked for, calls read per shape.
_MAX_ARGUMENT_TEXT = 4000
_MAX_HOPS = 3
_ASSIGNMENT_REACH = 20_000
_MAX_CALLS = 50


def split_arguments(text: str, open_at: int) -> Optional[list[str]]:
    """The top-level, comma-separated arguments of the bracket that opens at *open_at*,
    stripped; None when it does not close within reach."""
    closer, depth, quote = _CLOSERS[text[open_at]], 0, ""
    parts, start = [], open_at + 1
    for index in range(open_at + 1, min(len(text), open_at + _MAX_ARGUMENT_TEXT)):
        char = text[index]
        if quote:
            quote = "" if char == quote and text[index - 1] != "\\" else quote
        elif char in "'\"`":
            quote = char
        elif char in _CLOSERS:
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == closer:
            parts.append(text[start:index].strip())
            return [part for part in parts if part]
        elif char == "," and not depth:
            parts.append(text[start:index].strip())
            start = index + 1
    return None


def _assigned(name: str, text: str, before: int) -> Optional[str]:
    """The value last assigned to variable *name* before position *before*, as written."""
    assignment = re.compile(rf"(?<![\w$.]){re.escape(name)}\s*(?::\s*[^=\n]+?)?=(?![=>])\s*([^\n;]+)")
    values = [match.group(1) for match in assignment.finditer(text, max(0, before - _ASSIGNMENT_REACH), before)]
    return values[-1].strip() if values else None


def resolve(expression: str, text: str, before: int) -> str:
    """What an argument *expression* stands for: itself, or — when it is a variable,
    bare or wrapped in a conversion call — the value assigned to it before *before*."""
    for _hop in range(_MAX_HOPS):
        wrapped = _WRAPPED.fullmatch(expression)
        name = wrapped.group(1) if wrapped else expression
        value = _assigned(name, text, before) if _IDENTIFIER.fullmatch(name) else None
        if value is None:
            break
        expression = value
    return expression


def spender_in(expression: str) -> str:
    """The address (or ENS name) a resolved spender expression holds, else ``""``."""
    literal = EVM_ADDRESS.search(expression)
    return literal.group(0).lower() if literal else (spender_from(expression) or "")


def _approval(call: ApprovalCall, arguments: list[str], text: str, at: int) -> Optional[Approval]:
    if len(arguments) <= max(call.spender_at, call.amount_at) or all(_TYPE_NAME.fullmatch(a) for a in arguments):
        return None
    spender = spender_in(resolve(arguments[call.spender_at], text, at))
    amount = resolve(arguments[call.amount_at], text, at)
    unlimited = amounts.is_on(amount) if call.kind == "approve-all" else amounts.is_unlimited(amount)
    return Approval(spender, unlimited, call.kind) if spender or unlimited else None


def _viem_arguments(text: str, at: int) -> Optional[list[str]]:
    """The ``args: [...]`` nearest to the ``functionName`` at *at* (same object literal)."""
    nearby = [match for match in _VIEM_ARGS.finditer(text, max(0, at - _VIEM_REACH), at + _VIEM_REACH)]
    if not nearby:
        return None
    nearest = min(nearby, key=lambda match: abs(match.start() - at))
    return split_arguments(text, nearest.end() - 1)


def from_text(text: str) -> list[Approval]:
    """Every approval the script code in *text* would send (see the module doc)."""
    found: list[Optional[Approval]] = []
    for match in islice(_METHOD_CALL.finditer(text), _MAX_CALLS):
        if _DECLARATION.search(text, max(0, match.start() - 12), match.start()):
            continue
        arguments = split_arguments(text, match.end() - 1)
        if arguments is not None:
            found.append(_approval(CALLS_BY_NAME[match.group(1).lower()], arguments, text, match.start()))
    for match in islice(_VIEM_NAME.finditer(text), _MAX_CALLS):
        arguments = _viem_arguments(text, match.start())
        if arguments is not None:
            found.append(_approval(CALLS_BY_NAME[match.group(1).lower()], arguments, text, match.start()))
    for match in islice(_ENCODE_CALL.finditer(text), _MAX_CALLS):
        arguments = split_arguments(text, match.end() - 1)
        if arguments is not None:
            found.append(_approval(CALLS_BY_NAME[match.group(1).lower()], arguments, text, match.start()))
    return [approval for approval in found if approval is not None]
