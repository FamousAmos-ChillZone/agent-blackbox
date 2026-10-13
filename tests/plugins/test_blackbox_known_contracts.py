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
        assert entry["chains"] and entry["chains_source"] and isinstance(entry["any_chain"], bool)   # KI-388
    assert len(known_contracts.known_protocol_contracts()) == len(data["contracts"])                 # none skipped
    assert protocol_contract("0x7A250D5630B4CF539739DF2C5DACB4C659F2488D") == "Uniswap V2 Router 02"
    assert protocol_contract(DRAINER) is None


# KI-386: one bad entry once raised KeyError inside detect_all, and the hook's fail-open
# then switched EVERY detector off. The list is now checked entry by entry and cached.

from plugins.blackbox.detection import detect_all
from plugins.blackbox.ruleset import Ruleset

UNLIMITED = str(2 ** 256 - 1)


@pytest.fixture
def contracts_file(tmp_path, monkeypatch):
    """Point the loader at a file the test writes; the cache is cleared before and after."""
    path = tmp_path / "known_contracts.json"
    monkeypatch.setattr(known_contracts, "KNOWN_CONTRACTS_FILE", path)
    known_contracts.known_protocol_contracts.cache_clear()
    yield path
    known_contracts.known_protocol_contracts.cache_clear()


def _names() -> dict[str, str]:
    return {address: known.name for address, known in known_contracts.known_protocol_contracts().items()}


def _approve_everything(spender: str) -> list[str]:
    command = f"cast send 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 'approve(address,uint256)' {spender} {UNLIMITED}"
    return [f.identifier for f in detect_all("terminal", {"command": command}, Ruleset())]


def test_an_entry_without_a_name_is_skipped_and_detection_keeps_running(contracts_file, caplog):
    router, nameless = "0x" + "1" * 40, "0x" + "2" * 40
    contracts_file.write_text(json.dumps({"contracts": {router: {"name": "Router", "chains": [1], "any_chain": True},
                                                        nameless: {"checked": "x", "chains": [1]}}}), encoding="utf-8")
    assert _names() == {router: "Router"}
    assert "has no name" in caplog.text
    assert "secret:token-approval-unlimited" in _approve_everything(nameless)
    assert "secret:token-approval-unlimited" not in _approve_everything(router)


@pytest.mark.parametrize("address", ["", "0x1234", "0x" + "g" * 40, "1" * 42])
def test_an_address_that_is_not_0x_and_40_hex_is_skipped(contracts_file, address):
    contracts_file.write_text(json.dumps({"contracts": {address: {"name": "Bad", "chains": [1]}}}), encoding="utf-8")
    assert known_contracts.known_protocol_contracts() == {}


def test_a_mixed_case_address_is_kept_lower_case(contracts_file):
    contracts_file.write_text(json.dumps({"contracts": {"0x" + "AB" * 20: {"name": "Router", "chains": [1]}}}), encoding="utf-8")
    assert _names() == {"0x" + "ab" * 20: "Router"}


@pytest.mark.parametrize("text", ["{not json", "[]", '{"contracts": []}', '{"about": "no contracts"}'])
def test_an_unreadable_file_gives_an_empty_list_and_detection_keeps_running(contracts_file, text, caplog):
    contracts_file.write_text(text, encoding="utf-8")
    assert known_contracts.known_protocol_contracts() == {}
    assert "could not be read" in caplog.text
    assert "secret:token-approval-unlimited" in _approve_everything("0x" + "3" * 40)


def test_a_missing_file_gives_an_empty_list(contracts_file):
    assert known_contracts.known_protocol_contracts() == {}


def test_the_list_is_read_once(contracts_file, monkeypatch):
    contracts_file.write_text("{not json", encoding="utf-8")
    reads = []
    real = type(contracts_file).read_text
    monkeypatch.setattr(type(contracts_file), "read_text", lambda self, *a, **k: reads.append(self) or real(self, *a, **k))
    for _ in range(3):
        protocol_contract("0x" + "1" * 40)
    assert reads == [contracts_file]


@pytest.mark.parametrize("chains", [None, [], ["1"], [0], "1"])
def test_an_entry_without_valid_chain_ids_is_skipped(contracts_file, chains, caplog):
    entry = {"name": "Router"} if chains is None else {"name": "Router", "chains": chains}
    contracts_file.write_text(json.dumps({"contracts": {"0x" + "1" * 40: entry}}), encoding="utf-8")
    assert known_contracts.known_protocol_contracts() == {}
    assert "lists no chain ids" in caplog.text


# KI-388: a router is a router on its own chains. PancakeSwap's V2 router is BNB Chain only.

PANCAKE = "0x10ed43c718714eb63d5aa57b78b54704e256024e"
ONEINCH = "0x1111111254eeb25477b68fb85ed929f73a960582"


@pytest.mark.parametrize("address, chain, match", [
    (PANCAKE, 56, known_contracts.RouterMatch.ON_ITS_CHAIN),
    (PANCAKE, 1, known_contracts.RouterMatch.OTHER_CHAIN),
    (PANCAKE, None, known_contracts.RouterMatch.CHAIN_UNKNOWN),
    (ONEINCH, None, known_contracts.RouterMatch.ON_ITS_CHAIN),   # the same address on every major chain
    (ONEINCH, 324, known_contracts.RouterMatch.OTHER_CHAIN),     # zkSync Era has its own
    (DRAINER, 56, known_contracts.RouterMatch.NOT_A_ROUTER),
])
def test_a_router_is_exempt_only_on_its_chains(address, chain, match):
    assert known_contracts.router_match(address, chain) is match


def test_a_router_named_on_another_chain_is_looked_up_like_any_address():
    graph = _Graph()
    on_its_chain = detect_ioc("terminal", {"command": f"cast send {PANCAKE} --rpc-url https://bsc-dataseed.binance.org 'f()'"}, graph)
    elsewhere = detect_ioc("terminal", {"command": f"cast send {PANCAKE} --chain mainnet 'f()'"}, graph)
    assert on_its_chain == []
    assert [f.identifier for f in elsewhere] == [threat_ids.ioc_identifier("wallet", PANCAKE)]
