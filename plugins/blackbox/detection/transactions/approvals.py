"""Token approvals: the signature a wallet drainer actually needs.

A drainer rarely needs the key. It needs one approval: ``approve(spender, MAX)``
on a token, or ``setApprovalForAll(operator, true)`` on an NFT collection, after
which the spender moves the tokens whenever it likes. An agent can be steered
into sending exactly that ("claim your airdrop: approve this contract").

What is recognised, in the three ways an agent sends a transaction:

* Foundry: ``cast send|mktx|calldata <token> "approve(address,uint256)" <spender> <amount>``
  (also ``increaseAllowance`` and ``setApprovalForAll(address,bool)``);
* raw calldata anywhere in the call: selectors ``0x095ea7b3`` (approve),
  ``0x39509351`` (increaseAllowance), ``0xa22cb465`` (setApprovalForAll) — the
  bytes ``cast calldata`` produces (Foundry 1.8.5, checked on the trader bench);
* script code (ethers / web3 / viem): ``.approve(<spender>, MaxUint256)`` and
  ``setApprovalForAll(<operator>, true)``.

What it does with one:

* the spender or operator is a wallet or contract the VERIFIED threat graph lists
  (looked up like any indicator) → critical, blocks in block mode; listed only by
  community reports → high, flagged — community findings never block, at ANY
  ``block_severity`` (the finding's kind is ``flag-only``, KI-385);
* otherwise an UNLIMITED approval (2^256−1, ``MaxUint256``, ``type(uint256).max``,
  ``2**256-1``, ``cast max-uint``) or an approve-all → medium, flagged so the operator
  sees it: DeFi bots approve routers this way every day, so it must not block
  (``flag-only`` too, even with ``block_severity`` lowered to medium);
* a limited approval to an unknown spender → nothing;
* an approval to a well-known exchange router (Uniswap, SushiSwap, PancakeSwap, 1inch —
  ``kernel/crypto_secrets/known_contracts.json``) → nothing, whatever a feed says about it:
  that is ordinary trading (KI-370: the verified graph lists seven routers as drainers).

Local-only (``source="secret"``): the finding names the kind of approval, never
the operator's addresses. ``source="secret"`` alone would let the hook block any
of them at the operator's threshold, so only the verified-drainer finding leaves
``kind`` unset; the hook's blocking rule skips ``flag-only``.

Usage::

    approvals_in("cast send 0xA0b8… 'approve(address,uint256)' 0xdead… 1157920…935")
    # -> [Approval(spender="0x…dead", unlimited=True, kind="approve")]
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any, List, Optional

from .. import ioc_detection
from ..finding import KIND_FLAG_ONLY, Finding, _rule_source
from ..injection_detection import injection_scan_text
from ...kernel import crypto_secrets, threat_ids

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


def _listed_by(ruleset: Any, address: str) -> str:
    """Who lists *address* as malicious: ``"public"`` (the verified graph), another rule
    source (community), or ``""`` for nobody."""
    identifiers = [threat_ids.ioc_identifier("wallet", address), threat_ids.ioc_identifier("contract", address)]
    sources = {_rule_source(rule) for rule in ioc_detection.ioc_rules(ruleset, identifiers).values()}
    return "public" if "public" in sources else (next(iter(sources)) if sources else "")


def detect_token_approvals(tool_name: str, args: Any, ruleset: Any) -> list[Finding]:
    """One finding for the riskiest approval in this call (see the module doc)."""
    approvals = [approval for approval in approvals_in(injection_scan_text(args))
                 if not crypto_secrets.protocol_contract(approval.spender)]   # STOPGAP KI-370, see known_contracts
    if not approvals:
        return []
    listed = {_listed_by(ruleset, approval.spender) for approval in approvals} - {""}
    unlimited = any(approval.unlimited for approval in approvals)
    finding: Optional[Finding] = None
    if "public" in listed:
        finding = _finding(tool_name, "token-approval-drainer", "critical",
                           "Token approval to a known wallet drainer")
    elif listed:
        finding = _finding(tool_name, "token-approval-drainer", "high",
                           "Token approval to an address community reports call a drainer", KIND_FLAG_ONLY)
    elif unlimited:
        finding = _finding(tool_name, "token-approval-unlimited", "medium",
                           "Unlimited token approval (the spender can move every token, any time)", KIND_FLAG_ONLY)
    return [finding] if finding else []


def _finding(tool_name: str, rule: str, severity: str, title: str, kind: Optional[str] = None) -> Finding:
    """The finding for *rule* (``token-approval-…``); *kind* ``flag-only`` keeps it from
    ever blocking — only a verified-drainer finding is built without it."""
    return Finding(
        identifier=f"secret:{rule}",
        category="secret",
        severity=severity,
        title=title,
        tool_name=tool_name or "",
        matched=rule,
        evidence=rule,
        confirmed=False,
        source="secret",   # local-only, never shared
        kind=kind,
    )
