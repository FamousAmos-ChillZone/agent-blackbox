"""Token approvals (detection/transactions/approvals.py): the signature a drainer needs.

Shapes are what Foundry 1.8.5 produces on the trader bench (``cast calldata`` /
``cast max-uint``), and what ethers / web3.py scripts write. A verified-graph drainer
blocks; a community-listed one or an unlimited approval to an unknown spender flags; a
limited approval to an unknown spender is left alone.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import detect_all
from plugins.blackbox.detection.transactions.approvals import approvals_in, detect_token_approvals
from plugins.blackbox.kernel import threat_ids
from plugins.blackbox.kernel.crypto_secrets import wallet_mode
from plugins.blackbox.ruleset import Ruleset

USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
SPENDER = "0x000000000000000000000000000000000000dEaD"
MAX = "115792089237316195423570985008687907853269984665640564039457584007913129639935"   # cast max-uint


class _Graph:
    """A ruleset whose IOC rules list SPENDER (as the verified graph or community reports do)."""

    def __init__(self, source):
        self.ioc = {threat_ids.ioc_identifier("wallet", SPENDER): {"source": source, "severity": "critical"}}


@pytest.mark.parametrize("text, kind", [
    (f"cast send {USDC} 'approve(address,uint256)' {SPENDER} {MAX}", "approve"),
    (f"cast send {USDC} 'approve(address,uint256)' {SPENDER} $(cast max-uint) --private-key $PK", "approve"),
    (f"cast send {USDC} 'increaseAllowance(address,uint256)' {SPENDER} {MAX}", "approve"),
    (f"cast send {USDC} 0x095ea7b3000000000000000000000000000000000000000000000000000000000000dead{'f' * 64}", "approve"),
    (f"cast send 0xBC4C 'setApprovalForAll(address,bool)' {SPENDER} true", "approve-all"),
    ("cast send 0xBC4C 0xa22cb465000000000000000000000000000000000000000000000000000000000000dead" + "0" * 63 + "1", "approve-all"),
    (f"node -e \"await usdc.approve('{SPENDER}', ethers.MaxUint256)\"", "approve"),
    (f"python3 -c \"token.functions.approve('{SPENDER}', 2**256 - 1).transact()\"", "approve"),
    (f"node -e \"await nft.setApprovalForAll('{SPENDER}', true)\"", "approve-all"),
])
def test_unlimited_approvals_are_recognised_in_every_form(text, kind):
    [approval] = approvals_in(text)
    assert (approval.spender, approval.unlimited, approval.kind) == (SPENDER.lower(), True, kind)


@pytest.mark.parametrize("text", [
    f"cast send {USDC} 'approve(address,uint256)' {SPENDER} 1000000",
    f"cast send {USDC} 'approve(address,uint256)' {SPENDER} 0",           # revoking an approval
    f"cast send 0xBC4C 'setApprovalForAll(address,bool)' {SPENDER} false",
])
def test_limited_or_revoking_approvals_are_not_unlimited(text):
    assert [approval.unlimited for approval in approvals_in(text)] == [False]


def test_an_unlimited_approval_to_an_unknown_spender_is_flagged_not_blocked():
    [finding] = detect_token_approvals("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' {SPENDER} {MAX}"}, Ruleset())
    assert (finding.identifier, finding.severity, finding.source) == ("secret:token-approval-unlimited", "medium", "secret")


def test_a_limited_approval_to_an_unknown_spender_is_left_alone():
    assert detect_token_approvals("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' {SPENDER} 5"}, Ruleset()) == []


def test_any_approval_to_a_verified_drainer_is_critical():
    [finding] = detect_token_approvals("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' {SPENDER} 5"}, _Graph("public"))
    assert (finding.identifier, finding.severity) == ("secret:token-approval-drainer", "critical")


def test_a_community_listed_drainer_is_flagged_not_blocked():
    [finding] = detect_token_approvals("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' {SPENDER} {MAX}"}, _Graph("community"))
    assert (finding.identifier, finding.severity) == ("secret:token-approval-drainer", "high")


def test_approvals_run_with_every_detector_under_trader_shield():
    findings = detect_all("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' {SPENDER} {MAX}"}, Ruleset())
    [finding] = [f for f in findings if f.identifier.startswith("secret:token-approval")]
    row = {"identifier": finding.identifier, "fields": finding.fields}
    assert wallet_mode.WalletProtection(enabled=True).allows_finding(row)
    assert not wallet_mode.WalletProtection(enabled=False).allows_finding(row)


ROUTERS = {"0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router 02",
           "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2 Router"}


class _GraphListingTheRouters:
    """The verified graph as it is today (KI-370): Uniswap's and PancakeSwap's routers listed as wallets."""

    def __init__(self):
        self.ioc = {threat_ids.ioc_identifier("wallet", router): {"source": "public"} for router in ROUTERS}


@pytest.mark.parametrize("router", sorted(ROUTERS))
def test_approving_an_exchange_router_is_ordinary_trading_even_when_a_feed_lists_it(router):
    command = f"cast send {USDC} 'approve(address,uint256)' {router} {MAX}"
    assert detect_token_approvals("terminal", {"command": command}, _GraphListingTheRouters()) == []


def test_a_real_drainer_beside_a_router_is_still_caught():
    command = f"cast send {USDC} 'approve(address,uint256)' {SPENDER} 5 && cast send {USDC} 'approve(address,uint256)' 0x7a250d5630b4cf539739df2c5dacb4c659f2488d {MAX}"
    [finding] = detect_token_approvals("terminal", {"command": command}, _Graph("public"))
    assert finding.identifier == "secret:token-approval-drainer"
