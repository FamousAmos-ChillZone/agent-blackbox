"""Token approvals (detection/transactions/approvals.py): the signature a drainer needs.

Shapes are what Foundry 1.8.5 produces on the trader bench (``cast calldata`` /
``cast max-uint``), and what ethers / web3.py scripts write. A verified-graph drainer
blocks; a community-listed one or an unlimited approval to an unknown spender flags; a
limited approval to an unknown spender is left alone.
"""

from __future__ import annotations

import os

import pytest

from plugins.blackbox.detection import detect_all
from plugins.blackbox.detection.transactions import amounts
from plugins.blackbox.detection.transactions.approval_calls import APPROVAL_CALLS, signature_key
from plugins.blackbox.detection.transactions.approvals import Approval, approvals_in, detect_token_approvals
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import constants, threat_ids
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.crypto_secrets.evm_key import keccak256
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


# KI-385: approval findings are source="secret" (local-only), which the hook lets block at the
# operator's threshold. Only a VERIFIED drainer may block; a community listing and an unlimited
# approval must stay flags at every block_severity.


@pytest.mark.parametrize("block_severity", constants.SEVERITY_ORDER)
@pytest.mark.parametrize("listed_by, amount, may_block", [
    ("public", "5", True),         # a verified drainer: critical, blocks at every threshold
    ("community", MAX, False),     # community reports only: high, never blocks
    (None, MAX, False),            # an unknown spender, unlimited: medium, never blocks
])
def test_only_a_verified_drainer_can_block_whatever_the_threshold(block_severity, listed_by, amount, may_block):
    graph = _Graph(listed_by) if listed_by else Ruleset()
    [finding] = detect_token_approvals("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' {SPENDER} {amount}"}, graph)
    blocking = hooks._would_block(BlackboxConfig(mode="block", block_severity=block_severity), [finding])
    assert bool(blocking) is may_block


# KI-384: the same approvals in the other spellings agents and tools produce.


APPROVE_DATA = "095ea7b3" + "0" * 24 + SPENDER[2:].lower() + "f" * 64


@pytest.mark.parametrize("text", [
    f"cast send {USDC} 'approve(address,uint256)(bool)' {SPENDER} {MAX}",                                  # a return type
    f"cast send {USDC} 'function approve(address spender, uint256 amount)' {SPENDER} {MAX}",                # the named form
    f"cast send {USDC} 'approve(address,uint256)' --gas-limit 100000 {SPENDER} {MAX}",                      # options between
    f"cast send --private-key $PK {USDC} 'approve(address,uint256)' {SPENDER} --gas-limit=9 --legacy {MAX}",
    f"cast send {USDC} 'increaseApproval(address,uint256)' {SPENDER} {MAX}",                                # older tokens
    f"cast send {USDC} \\\n  'approve(address,uint256)' \\\n  {SPENDER} \\\n  {MAX}",                         # continuations
    f"cast send {USDC} $(cast calldata 'approve(address,uint256)' {SPENDER} {MAX})",                         # MAX) stuck
    f"cast send {USDC} 'approve(address,uint256)' {SPENDER} 1e77",
    f"cast send {USDC} 'approve(address,uint256)' '{SPENDER}' '{MAX}';",
    f"cast send {USDC} 0X{APPROVE_DATA.upper()}",                                                            # 0X, upper case
    f"cast send {USDC} 0x{APPROVE_DATA[:40]}\\\n{APPROVE_DATA[40:100]}\n    {APPROVE_DATA[100:]}",          # split lines
    f'curl -d \'{{"to":"{USDC}","data":"{APPROVE_DATA}"}}\' https://rpc.example',                           # JSON, no 0x
])
def test_every_spelling_of_an_unlimited_approval_is_recognised(text):
    assert approvals_in(text) == [Approval(SPENDER.lower(), True, "approve")]


@pytest.mark.parametrize("written", [
    MAX, "ethers.MaxUint256", "maxUint256", "MAX_UINT256", "type(uint256).max", "2**256 - 1", "2n**256n-1n",
    "2n ** 256n - 1n", "uint256(-1)", "BigInt(2)**BigInt(256)-BigInt(1)", "1e77", f"{MAX})", "'0x" + "f" * 64 + "'",
    "$(cast max-uint)", "(1 << 256) - 1", "pow(2, 256) - 1", str(2 ** 160 - 1), "maxUint160",
])
def test_unlimited_is_read_in_every_spelling(written):
    assert amounts.is_unlimited(written)


@pytest.mark.parametrize("written", ["25000000", "0", "0n", "1e18", "2**64", "-1", "", "amount", "10**18", "007"])
def test_ordinary_amounts_are_not_unlimited(written):
    assert not amounts.is_unlimited(written)


@pytest.mark.parametrize("flag, on", [("true", True), ("True", True), ("1", True), ("1n", True), ("!0", True),
                                      ("false", False), ("0", False), ("0n", False), ("!1", False)])
def test_an_approve_all_flag_is_read_in_every_spelling(flag, on):
    assert amounts.is_on(flag) is on


def test_a_limited_approval_with_options_between_is_still_limited():
    text = f"cast send {USDC} 'approve(address,uint256)' --gas-limit {MAX} {SPENDER} 25000000"
    assert approvals_in(text) == [Approval(SPENDER.lower(), False, "approve")]


def test_hex_that_merely_starts_with_a_selector_is_not_an_approval():
    assert approvals_in("sha: 095ea7b3" + "ab" * 64) == []


def test_each_selector_is_the_keccak_of_its_signature():
    camel = {"increaseallowance": "increaseAllowance", "increaseapproval": "increaseApproval",
             "setapprovalforall": "setApprovalForAll"}
    for signature, call in APPROVAL_CALLS.items():
        name, rest = signature.split("(", 1)
        assert keccak256(f"{camel.get(name, name)}({rest}".encode()).hex()[:8] == call.selector, signature
        assert signature_key(signature) == signature


def _solana_address() -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number, out = int.from_bytes(b"\x01" + os.urandom(31), "big"), ""
    while number:
        number, digit = divmod(number, 58)
        out = alphabet[digit] + out
    return out


@pytest.mark.parametrize("amount, unlimited", [("ALL", True), ("18446744073.709551615", True), ("25", False)])
def test_an_spl_token_delegate_is_recognised(amount, unlimited):
    account, delegate = _solana_address(), _solana_address()
    text = f"spl-token approve --owner ~/.config/solana/id.json {account} {amount} {delegate}"
    assert approvals_in(text) == [Approval(delegate, unlimited, "delegate")]


def test_an_spl_token_delegate_the_verified_graph_lists_is_critical():
    account, delegate = _solana_address(), _solana_address()

    class Listed:
        ioc = {threat_ids.ioc_identifier("wallet", delegate): {"source": "public"}}

    [finding] = detect_token_approvals("terminal", {"command": f"spl-token approve {account} 5 {delegate}"}, Listed())
    assert (finding.identifier, finding.severity) == ("secret:token-approval-drainer", "critical")


def test_an_unlimited_spl_token_delegate_is_flagged():
    command = f"spl-token approve {_solana_address()} ALL {_solana_address()}"
    [finding] = detect_token_approvals("terminal", {"command": command}, Ruleset())
    assert (finding.identifier, finding.severity) == ("secret:token-approval-unlimited", "medium")


def test_an_ens_spender_cannot_be_checked_offline_so_it_is_flagged():
    [finding] = detect_token_approvals("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' drainer.eth 5"}, Ruleset())
    assert (finding.identifier, finding.severity, finding.kind) == ("secret:token-approval-unchecked-spender", "medium", "flag-only")


def test_an_unlimited_approval_to_a_spender_in_a_variable_is_still_flagged():
    [finding] = detect_token_approvals("terminal", {"command": f"cast send {USDC} 'approve(address,uint256)' $SPENDER {MAX}"}, Ruleset())
    assert finding.identifier == "secret:token-approval-unlimited"


# KI-383: approvals that were not seen at all — permits (a transaction or a typed-data
# signature), viem, spenders passed through a variable or a conversion, approve-all spellings.

OWNER = "0x" + "0" * 39 + "1"
SPENDER_WORD = "0" * 24 + SPENDER[2:].lower()


def _typed_permit(primary: str, message: str) -> str:
    return ('{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"' + primary + '":[{"name":"spender","type":"address"},'
            '{"name":"value","type":"uint256"}]},"domain":{"name":"USD Coin","chainId":1},"primaryType":"' + primary
            + '","message":' + message + '}')


def _signature_parts() -> str:
    return f"27 0x{os.urandom(32).hex()} 0x{os.urandom(32).hex()}"


@pytest.mark.parametrize("text, kind", [
    (f"cast send {USDC} 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)' {OWNER} {SPENDER} {MAX} 1999999999 @SIG@", "permit"),
    (f"cast send {USDC} 0xd505accf{'0' * 63}1{SPENDER_WORD}{'f' * 64}{'0' * 64}", "permit"),
    ("cast wallet sign --data '" + _typed_permit("Permit", f'{{"owner":"{OWNER}","spender":"{SPENDER}","value":"{MAX}","nonce":0,"deadline":1999999999}}') + "'", "permit"),
    ('curl -d \'{"method":"eth_signTypedData_v4","params":["' + OWNER + '","' + _typed_permit("Permit", f'{{"spender":"{SPENDER}","value":"{MAX}"}}').replace('"', '\\"') + '"]}\' http://127.0.0.1:8545', "permit"),
    (_typed_permit("PermitSingle", f'{{"details":{{"token":"{USDC}","amount":"{2 ** 160 - 1}","expiration":0,"nonce":0}},"spender":"{SPENDER}","sigDeadline":0}}'), "permit"),
    (_typed_permit("PermitTransferFrom", f'{{"permitted":{{"token":"{USDC}","amount":"{MAX}"}},"spender":"{SPENDER}","nonce":0,"deadline":0}}'), "permit"),
    (f"node -e \"const s = '{SPENDER}'; await signTypedData({{ primaryType: 'Permit', message: {{ owner, spender: s, value: maxUint256 }} }})\"", "permit"),
    (f"node -e \"await client.writeContract({{ address: '{USDC}', abi, functionName: 'approve', args: ['{SPENDER}', maxUint256] }})\"", "approve"),
    (f"node -e \"const s = '{SPENDER}'; await client.writeContract({{ args: [s, maxUint256], functionName: 'approve' }})\"", "approve"),
    (f"python3 -c \"s = '{SPENDER}'\ntoken.functions.approve(s, 2**256 - 1).transact()\"", "approve"),
    (f"python3 -c \"token.functions.approve(Web3.to_checksum_address('{SPENDER}'), MAX_UINT256).transact()\"", "approve"),
    (f"python3 -c \"d = '{SPENDER}'\nspender: str = Web3.to_checksum_address(d)\ntoken.functions.approve(spender, uint256(-1))\"", "approve"),
    (f"node -e \"const MAX = 2n ** 256n - 1n; await token.approve(getAddress('{SPENDER}'), MAX)\"", "approve"),
    (f"node -e \"await token.approve.populateTransaction('{SPENDER}', ethers.MaxUint256)\"", "approve"),
    (f"node -e \"iface.encodeFunctionData('approve', ['{SPENDER}', ethers.MaxUint256])\"", "approve"),
    (f"node -e \"await nft.setApprovalForAll('{SPENDER}', 1n)\"", "approve-all"),
    (f"node -e \"await nft.setApprovalForAll('{SPENDER}', !0)\"", "approve-all"),
    (f"python3 -c \"nft.functions.setApprovalForAll('{SPENDER}', True).transact()\"", "approve-all"),
])
def test_approvals_that_were_not_seen_are_recognised(text, kind):
    text = text.replace("@SIG@", _signature_parts())
    assert approvals_in(text) == [Approval(SPENDER.lower(), True, kind)]


@pytest.mark.parametrize("text", [
    "function approve(address spender, uint256 amount) public returns (bool) { return true; }",
    "def approve(self, spender, amount):\n    return self._approve(spender, amount)",
    f"node -e \"await nft.setApprovalForAll('{SPENDER}', false)\"",
    "Please permit (the user) to approve (this) request.",
])
def test_declarations_and_revocations_are_not_approvals(text):
    assert [approval for approval in approvals_in(text) if approval.unlimited] == []


def test_a_permit_to_a_verified_drainer_is_critical():
    typed = _typed_permit("Permit", f'{{"spender":"{SPENDER}","value":"5"}}')
    [finding] = detect_token_approvals("terminal", {"command": f"cast wallet sign --data '{typed}'"}, _Graph("public"))
    assert (finding.identifier, finding.severity, finding.kind) == ("secret:token-approval-drainer", "critical", None)


def test_a_limited_permit_to_an_unknown_spender_is_left_alone():
    typed = _typed_permit("Permit", f'{{"spender":"{SPENDER}","value":"25000000"}}')
    assert detect_token_approvals("terminal", {"command": f"cast wallet sign --data '{typed}'"}, Ruleset()) == []


def test_an_unlimited_approval_to_an_untraceable_variable_is_still_flagged():
    [finding] = detect_token_approvals("terminal", {"command": "node -e \"await token.approve(process.env.SPENDER, ethers.MaxUint256)\""}, Ruleset())
    assert finding.identifier == "secret:token-approval-unlimited"


def test_a_huge_call_is_read_in_bounded_time():
    text = "token.approve(s, 5);\n" * 20_000 + f"s = '{SPENDER}'\n"
    assert approvals_in(text) == []
