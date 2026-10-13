"""Well-known exchange contracts: never treated as a drainer, never flagged as a bad address.

An agent that trades approves and calls these routers all day. Threat feeds that
extract addresses from malicious code pick them up too — a fake trading bot
hard-codes the real Uniswap router — and Umanitek's verified graph lists seven of
them as drainer wallets (KI-370). The data lives in ``known_contracts.json`` (one
source for the plugin and ``scripts/blackbox-trader-graph-counts.py``), each entry
with how it was checked.

STOPGAP for the verified-graph entries (KI-370): the real fix is a curator
correction removing them from the graph; until then this list keeps the rules
from acting on them. As a list of routers an agent may approve, it stays.

Usage::

    protocol_contract("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")   # -> "Uniswap V2 Router 02"
    protocol_contract("0xdead…")                                         # -> None
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

KNOWN_CONTRACTS_FILE = Path(__file__).with_name("known_contracts.json")


@lru_cache(maxsize=1)
def known_protocol_contracts() -> Dict[str, str]:
    """``{lower-case address: name}`` from the shipped list."""
    data = json.loads(KNOWN_CONTRACTS_FILE.read_text(encoding="utf-8"))
    return {address.lower(): entry["name"] for address, entry in data["contracts"].items()}


def protocol_contract(address: str) -> Optional[str]:
    """The name of the well-known exchange contract at *address*, or None."""
    return known_protocol_contracts().get(str(address or "").strip().lower())
