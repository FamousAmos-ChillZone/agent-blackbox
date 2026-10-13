"""Approvals written as command-line tools write them: Foundry's ``cast`` and ``spl-token``.

Foundry: ``cast send|mktx|calldata|estimate <token> <signature> <args…>`` where the
signature is any spelling :func:`.approval_calls.signature_key` reads —
``'approve(address,uint256)'``, ``'approve(address,uint256)(bool)'``,
``'function approve(address spender, uint256 amount)'`` — and options may sit anywhere
among the arguments (``--gas-limit 100000``). The words come from ``shlex``, so quoting
and ``\\``-newline continuations are already resolved.

Solana: ``spl-token approve <token account> <amount> <delegate>`` — the delegate is
looked up like any wallet; an amount of ``ALL`` or u64::MAX is unlimited
(:func:`.amounts.is_unlimited_solana`).

Pure functions over the call's words.

Usage::

    from_words(shlex.split("cast send 0xA0b8… 'approve(address,uint256)' --gas-limit 9 0xdead… 5"))
    # -> [Approval(spender="0x…dead", unlimited=False, kind="approve")]
"""

from __future__ import annotations

import re
from typing import Optional

from . import amounts
from .approval_calls import APPROVAL_CALLS, Approval, signature_key, spender_from, strip_stuck

#: Words that end one shell command: what follows belongs to the next.
_COMMAND_ENDS = frozenset({"&&", "||", ";", "|", "&"})
#: cast / spl-token options that take no value (every other option consumes the next word).
_FLAGS = frozenset({"--async", "--cast-async", "--legacy", "--unlocked", "--json", "--interactive", "-i",
                    "--ledger", "-l", "--trezor", "-t", "--aws", "--gcp", "--blob", "--flashbots",
                    "--verbose", "-v", "--dump-transaction-message", "--sign-only", "--no-wait"})
_NEGATIVE_NUMBER = re.compile(r"-\d")
_SOLANA_ADDRESS = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")


def _shell_expression(words: list[str], index: int) -> tuple[str, int]:
    """The word at *index*, joined with the words after it while it is an open ``$(…)``
    (``$(cast max-uint)`` splits into two words); returns ``(text, next index)``."""
    text, index = words[index], index + 1
    while text.startswith("$(") and text.count("(") > text.count(")") and index < len(words):
        text, index = f"{text} {words[index]}", index + 1
    return text, index


def positional_arguments(words: list[str], start: int) -> list[str]:
    """The arguments after *start* up to the end of the command, options and their
    values left out (``--gas-limit 100000`` is not an argument)."""
    out: list[str] = []
    index = start
    while index < len(words):
        word = words[index]
        if word in _COMMAND_ENDS:
            break
        if word.startswith("-") and not _NEGATIVE_NUMBER.match(word):
            index += 1 if ("=" in word or word in _FLAGS) else 2
            continue
        text, index = _shell_expression(words, index)
        out.append(text)
        if word.endswith(";"):
            break
    return out


def _from_signature(words: list[str], index: int) -> Optional[Approval]:
    call = APPROVAL_CALLS.get(signature_key(words[index]) or "")
    if call is None:
        return None
    arguments = positional_arguments(words, index + 1)
    if len(arguments) <= max(call.spender_at, call.amount_at):
        return None
    amount = arguments[call.amount_at]
    unlimited = amounts.is_on(amount) if call.kind == "approve-all" else amounts.is_unlimited(amount)
    # A spender in a variable ($SPENDER) cannot be looked up, but giving it everything still shows.
    spender = spender_from(arguments[call.spender_at]) or ""
    return Approval(spender, unlimited, call.kind) if spender or unlimited else None


def _from_spl_token(words: list[str], index: int) -> Optional[Approval]:
    """``spl-token … approve <account> <amount> <delegate>`` starting at the word ``spl-token``."""
    arguments = positional_arguments(words, index + 1)
    if len(arguments) < 4 or arguments[0] != "approve":
        return None
    delegate = strip_stuck(arguments[3])
    if not _SOLANA_ADDRESS.fullmatch(delegate):
        return None
    return Approval(delegate, amounts.is_unlimited_solana(arguments[2]), "delegate")


def from_words(words: list[str]) -> list[Approval]:
    """Every approval the shell words of a call would send (see the module doc)."""
    out: list[Approval] = []
    for index, word in enumerate(words):
        found = _from_spl_token(words, index) if word.endswith("spl-token") else _from_signature(words, index)
        if found is not None:
            out.append(found)
    return out
