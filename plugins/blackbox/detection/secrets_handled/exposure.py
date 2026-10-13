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
from . import sending
from ..finding import Finding
from ..injection_detection import injection_scan_text
from ...kernel import crypto_secrets


#: Wallet secrets (``secret:<type>``): no destination is ever right for these, so ANY way of
#: sending them counts — a web address, a network program, script code that makes a
#: network call, a tool whose arguments leave the machine (``sending.reaches_network``).
_WALLET_SECRET_TYPES = frozenset({"seed-phrase", "wallet-private-key", "solana-private-key", "bitcoin-private-key"})


def _wallet_secrets_sent(tool_name: str, text: str, hits: list[dict[str, str]]) -> set:
    """Wallet secret types this call sends: every one present when the call has any route
    off the machine, else those inside a web address it names. (API keys are left to the
    command-shaped egress check — an agent legitimately sends an API key to its API.)"""
    if sending.reaches_network(tool_name, text):
        return {hit["type"] for hit in hits} & _WALLET_SECRET_TYPES
    in_urls = {hit["type"] for hit in content_scanners.scan_secret_values(sending.url_payloads(text))}
    return in_urls & _WALLET_SECRET_TYPES


def _secret_finding(tool_name: str, secret_type: str, severity: str, sent: bool, evidence: str = "") -> Finding:
    """One local-only ``secret:<type>`` finding: the TYPE only, never the value."""
    return Finding(
        identifier=f"secret:{secret_type}",
        category="secret",
        severity=severity,
        title=f"{'Secret exfiltration' if sent else 'Secret exposed'}: {secret_type}",
        tool_name=tool_name or "",
        matched=secret_type,
        evidence=evidence or secret_type,
        confirmed=False,
        source="secret",
    )


def _unchecked_solana_keys_sent(tool_name: str, text: str) -> list[Finding]:
    """A call that SENDS more Solana-key-shaped values than the check's budget, none of
    which proved to be a key: flagged high — "could not tell" is never "no key" (KI-380,
    LES-011). Kept on the machine, a list of signatures raises nothing."""
    if not sending.reaches_network(tool_name, text) or not crypto_secrets.scan_solana_keys(text).unchecked:
        return []
    return [_secret_finding(tool_name, "solana-private-key", "high", True,
                            "solana-private-key (more key-shaped values sent than Blackbox checks in one call)")]


def detect_secret_exposure(tool_name: str, args: Any) -> list[Finding]:
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
    egress = sending.looks_like_egress(text)
    wallet_sent = _wallet_secrets_sent(tool_name, text, hits) if hits else set()
    out: list[Finding] = []
    for hit in hits:
        sent = egress or hit["type"] in wallet_sent
        severity = "critical" if (sent and hit["severity"] != "critical") else hit["severity"]
        out.append(_secret_finding(tool_name, hit["type"], severity, sent))
    if not any(hit["type"] == "solana-private-key" for hit in hits):
        out += _unchecked_solana_keys_sent(tool_name, text)
    return out


def detect_exchange_key_misdirection(tool_name: str, args: Any) -> list[Finding]:
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
_HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


def detect_own_wallet_keys(tool_name: str, args: Any, own_addresses: Callable[[], Iterable[str]]) -> list[Finding]:
    """A raw 64-hex private key that opens one of the operator's OWN listed addresses
    (``own_addresses`` is called only when a 64-hex value is present — no config read for
    ordinary calls). Handling it flags; sending it (command, web address, script) is critical.

    Only :data:`~kernel.crypto_secrets.evm_key.MAX_CANDIDATES` values are derived per call
    (KI-382). A call that SENDS more key-shaped values than that, none of which proved to
    be a key, is flagged high — "could not tell" is never read as "no key" (LES-011)."""
    text = injection_scan_text(args)
    if not text or not _HEX64.search(text):
        return []
    addresses = frozenset(own_addresses())
    scan = crypto_secrets.scan_own_keys(text, addresses)
    if not scan.spans and not scan.unchecked:
        return []
    sent = (sending.reaches_network(tool_name, text)
            or bool(crypto_secrets.own_keys_in(sending.url_payloads(text), addresses)))
    if not scan.spans and not sent:
        return []
    evidence = ("wallet-private-key (a raw key that opens one of your listed addresses)" if scan.spans else
                "wallet-private-key (more key-shaped values sent than Blackbox checks in one call)")
    return [Finding(
        identifier="secret:wallet-private-key",
        category="secret",
        severity="critical" if (sent and scan.spans) else "high",
        title=("Secret exfiltration" if sent else "Secret exposed") + ": wallet-private-key",
        tool_name=tool_name or "",
        matched="wallet-private-key",   # the TYPE only — never the key or the address
        evidence=evidence,
        confirmed=False,
        source="secret",
    )]
