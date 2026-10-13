"""Token approvals: the signature a wallet drainer actually needs.

A drainer rarely needs the key. It needs one approval: ``approve(spender, MAX)``
on a token, or ``setApprovalForAll(operator, true)`` on an NFT collection, after
which the spender moves the tokens whenever it likes. An agent can be steered
into sending exactly that ("claim your airdrop: approve this contract").

What is recognised — Foundry ``cast`` and ``spl-token`` command lines, raw calldata
however its hex is written, and ethers / web3 / viem script code, in every spelling of
the signature and of "unlimited" — is listed in :mod:`.approval_forms`.

What it does with one (a permit — an approval by signature — and a Solana token
delegate are treated exactly like an approval):

* the spender or operator is a wallet or contract the VERIFIED threat graph lists
  (looked up like any indicator) → critical, blocks in block mode; listed only by
  community reports → high, flagged — community findings never block, at ANY
  ``block_severity`` (the finding's kind is ``flag-only``, KI-385);
* otherwise an UNLIMITED approval (2^256−1, ``MaxUint256``, ``type(uint256).max``,
  ``2**256-1``, ``cast max-uint``) or an approve-all → medium, flagged so the operator
  sees it: DeFi bots approve routers this way every day, so it must not block
  (``flag-only`` too, even with ``block_severity`` lowered to medium);
* a spender written as an ENS name (``drainer.eth``) → medium, flagged: the name
  cannot be resolved to an address offline, so it cannot be looked up — saying so
  beats saying nothing;
* a limited approval to an unknown spender → nothing;
* an approval to a well-known exchange router (Uniswap, SushiSwap, PancakeSwap, 1inch —
  ``kernel/crypto_secrets/known_contracts.json``) on a chain it is a router on → nothing,
  whatever a feed says about it: that is ordinary trading (KI-370: the verified graph
  lists seven routers as drainers). The chain is the one the call names (``--chain``,
  the RPC host, a typed-data ``chainId`` — :mod:`.chains`). Naming ANOTHER chain, the
  address is treated like any spender. Naming none, a router deployed at that address
  on every major chain stays exempt; for the others the rules cannot tell which chain
  it is, so a feed listing or an unlimited amount flags (medium) and never blocks (KI-388).

Local-only (``source="secret"``): the finding names the kind of approval, never
the operator's addresses. ``source="secret"`` alone would let the hook block any
of them at the operator's threshold, so only the verified-drainer finding leaves
``kind`` unset; the hook's blocking rule skips ``flag-only``.

Usage::

    approvals_in("cast send 0xA0b8… 'approve(address,uint256)' 0xdead… 1157920…935")
    # -> [Approval(spender="0x…dead", unlimited=True, kind="approve")]
"""

from __future__ import annotations

from typing import Any, Optional

from .. import ioc_detection
from ..finding import KIND_FLAG_ONLY, Finding, _rule_source
from ..injection_detection import injection_scan_text
from ...kernel import crypto_secrets, threat_ids
from ...kernel.crypto_secrets import RouterMatch
from .approval_calls import is_ens_name
from .chains import chain_named
from .approval_forms import Approval, approvals_in

__all__ = ["Approval", "approvals_in", "detect_token_approvals"]


def _listed_by(ruleset: Any, address: str) -> str:
    """Who lists *address* as malicious: ``"public"`` (the verified graph), another rule
    source (community), or ``""`` for nobody (or for a spender that is no address)."""
    if not address or is_ens_name(address):
        return ""
    identifiers = [threat_ids.ioc_identifier("wallet", address), threat_ids.ioc_identifier("contract", address)]
    sources = {_rule_source(rule) for rule in ioc_detection.ioc_rules(ruleset, identifiers).values()}
    return "public" if "public" in sources else (next(iter(sources)) if sources else "")


def detect_token_approvals(tool_name: str, args: Any, ruleset: Any) -> list[Finding]:
    """One finding for the riskiest approval in this call (see the module doc)."""
    text = injection_scan_text(args)
    approvals = approvals_in(text)
    if not approvals:
        return []
    chain = chain_named(text)
    # STOPGAP KI-370 (see known_contracts): a router on its own chain is ordinary trading.
    # On a chain the call does not name, a feed's listing of it may be that stale entry:
    # it can flag, never block (KI-388).
    routers = {approval: crypto_secrets.router_match(approval.spender, chain) for approval in approvals}
    approvals = [approval for approval in approvals if routers[approval] is not RouterMatch.ON_ITS_CHAIN]
    checked = [approval for approval in approvals if routers[approval] is not RouterMatch.CHAIN_UNKNOWN]
    listed = {_listed_by(ruleset, approval.spender) for approval in checked} - {""}
    unchecked = any(is_ens_name(approval.spender) or (routers[approval] is RouterMatch.CHAIN_UNKNOWN
                                                      and _listed_by(ruleset, approval.spender))
                    for approval in approvals)
    finding: Optional[Finding] = None
    if "public" in listed:
        finding = _finding(tool_name, "token-approval-drainer", "critical",
                           "Token approval to a known wallet drainer")
    elif listed:
        finding = _finding(tool_name, "token-approval-drainer", "high",
                           "Token approval to an address community reports call a drainer", KIND_FLAG_ONLY)
    elif any(approval.unlimited for approval in approvals):
        finding = _finding(tool_name, "token-approval-unlimited", "medium",
                           "Unlimited token approval (the spender can move every token, any time)", KIND_FLAG_ONLY)
    elif unchecked:
        finding = _finding(tool_name, "token-approval-unchecked-spender", "medium",
                           "Token approval to a spender Blackbox cannot check (an ENS name, or an exchange "
                           "router on a chain the call does not name)", KIND_FLAG_ONLY)
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
