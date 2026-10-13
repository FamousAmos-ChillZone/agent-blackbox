"""Secrets an agent handles or sends: API keys, wallet secrets, exchange keys.

* :func:`detect_secret_exposure` — a recognisable secret VALUE in a tool call's
  arguments; sending it (a command that sends, or — for wallet secrets — a web
  address or network-calling script code) raises it to critical.
* :func:`detect_exchange_key_misdirection` — an exchange's API key header sent to a
  site that is not that exchange.
* :func:`detect_own_wallet_keys` — a raw 64-hex private key that opens one of the
  operator's own listed addresses (Trader Shield settings).

Findings are ``source="secret"``: local-only (only the TYPE is recorded, never the
value) and blockable.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, List

from .. import content_scanners
from ..finding import Finding
from ..injection_detection import injection_scan_text
from ...kernel import crypto_secrets


#: Wallet secrets (``secret:<type>``): no destination is ever right for these, so ANY way of
#: sending them counts — a web address, or script code that makes a network call.
_WALLET_SECRET_TYPES = frozenset({"seed-phrase", "wallet-private-key", "solana-private-key"})


def _wallet_secrets_sent(text: str) -> set:
    """Wallet secret types this call sends: those inside a web address it names, and every
    one present when it runs network-calling script code. (API keys are left to the
    command-shaped egress check — an agent legitimately sends an API key to its API.)"""
    in_urls = {hit["type"] for hit in content_scanners.scan_secret_values(content_scanners.url_payloads(text))}
    if content_scanners.looks_like_script_send(text):
        in_urls |= {hit["type"] for hit in content_scanners.scan_secret_values(text)}
    return in_urls & _WALLET_SECRET_TYPES


def detect_secret_exposure(tool_name: str, args: Any) -> List[Finding]:
    """Flag a real secret VALUE (API key, token, private key) in the tool args.

    Complements the sensitive-FILE detection: this fires when the agent is
    actually *handling* a recognizable secret — e.g. passing an ``sk-…`` key in a
    command, or a private-key block. If the same call also sends data off-box
    (``curl --data``, ``nc``, …), it is treated as exfiltration and escalated to
    critical (blockable). Findings are ``source="secret"``: local-only (the
    value never leaves the machine — only the TYPE is recorded) and blockable.
    """
    text = injection_scan_text(args)
    if not text:
        return []
    hits = content_scanners.scan_secret_values(text)
    if not hits:
        return []
    egress = content_scanners.looks_like_egress(text)
    wallet_sent = _wallet_secrets_sent(text)
    out: List[Finding] = []
    for hit in hits:
        sent = egress or hit["type"] in wallet_sent
        severity = "critical" if (sent and hit["severity"] != "critical") else hit["severity"]
        prefix = "Secret exfiltration" if sent else "Secret exposed"
        out.append(
            Finding(
                identifier=f"secret:{hit['type']}",
                category="secret",
                severity=severity,
                title=f"{prefix}: {hit['type']}",
                tool_name=tool_name or "",
                matched=hit["type"],   # TYPE only — never the secret value
                evidence=hit["type"],
                confirmed=False,
                source="secret",
            )
        )
    return out


def detect_exchange_key_misdirection(tool_name: str, args: Any) -> List[Finding]:
    """An exchange's API key header sent to a site that is not that exchange
    (:mod:`kernel.crypto_secrets.exchange_keys`). Critical, local-only, under Trader Shield."""
    exchanges = crypto_secrets.misdirected_exchange_keys(injection_scan_text(args))
    return [
        Finding(
            identifier="secret:exchange-api-key",
            category="secret",
            severity="critical",
            title=f"Exchange API key sent to another site ({', '.join(exchanges)})",
            tool_name=tool_name or "",
            matched="exchange-api-key",   # the TYPE only — never the key
            evidence=f"exchange-api-key ({', '.join(exchanges)})",
            confirmed=False,
            source="secret",
        )
    ] if exchanges else []


#: A 64-hex value: the only shape a raw Ethereum private key can take.
_HEX64 = re.compile(r"(?<![0-9A-Za-z])(?:0x)?[0-9a-fA-F]{64}(?![0-9A-Za-z])")


def detect_own_wallet_keys(tool_name: str, args: Any, own_addresses: Callable[[], Iterable[str]]) -> List[Finding]:
    """A raw 64-hex private key that opens one of the operator's OWN listed addresses
    (``own_addresses`` is called only when a 64-hex value is present — no config read for
    ordinary calls). Handling it flags; sending it (command, web address, script) is critical."""
    text = injection_scan_text(args)
    if not text or not _HEX64.search(text):
        return []
    addresses = frozenset(own_addresses())
    if not crypto_secrets.own_keys_in(text, addresses):
        return []
    sent = (content_scanners.looks_like_egress(text) or content_scanners.looks_like_script_send(text)
            or bool(crypto_secrets.own_keys_in(content_scanners.url_payloads(text), addresses)))
    return [Finding(
        identifier="secret:wallet-private-key",
        category="secret",
        severity="critical" if sent else "high",
        title=("Secret exfiltration" if sent else "Secret exposed") + ": wallet-private-key",
        tool_name=tool_name or "",
        matched="wallet-private-key",   # the TYPE only — never the key or the address
        evidence="wallet-private-key (a raw key that opens one of your listed addresses)",
        confirmed=False,
        source="secret",
    )]
