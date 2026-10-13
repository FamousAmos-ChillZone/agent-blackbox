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

The file is read once and cached. It is checked entry by entry (KI-386): an
address that is not ``0x`` + 40 hex characters, or an entry without a name, is
skipped with a WARNING; a file that cannot be read or parsed gives an empty list.
Nothing here ever raises into detection — the detectors run on every tool call,
and one bad entry once switched every detector off through the hook's fail-open.

Usage::

    protocol_contract("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")   # -> "Uniswap V2 Router 02"
    protocol_contract("0xdead…")                                         # -> None
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

KNOWN_CONTRACTS_FILE = Path(__file__).with_name("known_contracts.json")
_ADDRESS = re.compile(r"0x[0-9a-f]{40}")


def _entry_name(address: Any, entry: Any) -> Optional[str]:
    """The entry's name when *address* and *entry* are well formed, else None (logged)."""
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address.strip().lower()):
        logger.warning("blackbox: known_contracts.json: skipped an entry whose address is not 0x + 40 hex: %r", address)
        return None
    name = entry.get("name") if isinstance(entry, dict) else None
    if not isinstance(name, str) or not name.strip():
        logger.warning("blackbox: known_contracts.json: skipped %s, which has no name", address)
        return None
    return name.strip()


@lru_cache(maxsize=1)
def known_protocol_contracts() -> dict[str, str]:
    """``{lower-case address: name}`` from the shipped list, every entry checked (see
    the module doc); empty when the file cannot be read. Cached for the process."""
    try:
        data = json.loads(KNOWN_CONTRACTS_FILE.read_text(encoding="utf-8-sig"))
        contracts = data["contracts"]
        if not isinstance(contracts, dict):
            raise TypeError("contracts is not an object")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logger.warning("blackbox: known_contracts.json could not be read (%s); no exchange router is exempt", exc)
        return {}
    out: dict[str, str] = {}
    for address, entry in contracts.items():
        name = _entry_name(address, entry)
        if name is not None:
            out[address.strip().lower()] = name
    return out


def protocol_contract(address: str) -> Optional[str]:
    """The name of the well-known exchange contract at *address*, or None."""
    return known_protocol_contracts().get(str(address or "").strip().lower())
