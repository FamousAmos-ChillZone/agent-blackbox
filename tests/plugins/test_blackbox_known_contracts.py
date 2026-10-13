"""Well-known exchange routers are never flagged as bad addresses (KI-370).

Umanitek's verified graph lists seven exchange routers among its "drainer wallets"
(checked on-chain 2026-10-13). Every swap command names a router, so each one raised a
"known-bad wallet" flag. The routers live in kernel/crypto_secrets/known_contracts.json.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.detection.ioc_detection import detect_ioc
from plugins.blackbox.kernel import threat_ids
from plugins.blackbox.kernel.crypto_secrets import known_contracts, protocol_contract

ROUTERS = sorted(known_contracts.known_protocol_contracts())
DRAINER = "0x30f895a2c66030795131fb66cbad6a1f91461731"


class _Graph:
    """The verified graph as it is today: the routers AND a real drainer listed as wallets."""

    def __init__(self):
        self.ioc = {threat_ids.ioc_identifier("wallet", address): {"source": "public", "severity": "high"}
                    for address in ROUTERS + [DRAINER]}


@pytest.mark.parametrize("router", ROUTERS)
def test_a_command_naming_a_router_is_not_flagged(router):
    command = f"cast send {router} 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)' 1 0 [] {DRAINER[:2]}00 9"
    assert [f.identifier for f in detect_ioc("terminal", {"command": command}, _Graph())] == []


def test_a_real_listed_address_is_still_flagged():
    findings = detect_ioc("terminal", {"command": f"cast send {DRAINER} --value 1ether"}, _Graph())
    assert threat_ids.ioc_identifier("wallet", DRAINER) in [f.identifier for f in findings]


def test_the_list_is_checked_lower_case_and_says_how_each_was_checked():
    data = json.loads(known_contracts.KNOWN_CONTRACTS_FILE.read_text(encoding="utf-8"))
    for address, entry in data["contracts"].items():
        assert address == address.lower() and len(address) == 42 and entry["name"] and entry["checked"]
    assert protocol_contract("0x7A250D5630B4CF539739DF2C5DACB4C659F2488D") == "Uniswap V2 Router 02"
    assert protocol_contract(DRAINER) is None
