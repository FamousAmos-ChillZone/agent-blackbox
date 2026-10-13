"""Bitcoin private keys — WIF keys and BIP-32 extended private keys — proven by their checksum.

Two shapes carry a Bitcoin-family private key as text, both Base58Check (a version
prefix, the payload, then the first 4 bytes of SHA-256(SHA-256(prefix + payload))):

* **WIF** ("wallet import format", Electrum's and Bitcoin Core's key export): version
  0x80 (mainnet) or 0xEF (testnet), the 32-byte key, an optional 0x01 "compressed" flag
  — 51 characters starting ``5``/``9`` or 52 starting ``K``/``L``/``c``.
* **Extended private keys** (BIP-32 ``xprv``; BIP-49/84 ``yprv``/``zprv``; testnet
  ``tprv``/``uprv``/``vprv``; multisig ``Yprv``/``Zprv``): 78 bytes — 4 version bytes, depth,
  parent fingerprint, child number, chain code, then 0x00 + the 32-byte key — 111
  characters. One xprv opens every account the wallet will ever derive.

The 4-byte checksum makes a random look-alike pass about 1 time in 4 billion, so a
verified candidate IS a key (the version bytes and key range are checked too).
Used by redaction (never logged) and detection (flagged when handled, critical when sent).

Usage::

    find_bitcoin_private_keys(text)   # -> [BitcoinKey(start, end, kind="wif" | "extended"), ...]
    redact_bitcoin_keys(text)         # -> text with each key (and one cut off at the end) replaced
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from . import base58

WIF_MARKER = "[REDACTED_BITCOIN_PRIVATE_KEY]"
EXTENDED_MARKER = "[REDACTED_EXTENDED_PRIVATE_KEY]"
_B58 = "1-9A-HJ-NP-Za-km-z"
_WIF = re.compile(rf"(?<![{_B58}])[59KLc][{_B58}]{{50,51}}(?![{_B58}])")
_EXTENDED = re.compile(rf"(?<![{_B58}])[xyztuvYZ]prv[{_B58}]{{107}}(?![{_B58}])")
#: A key CUT OFF at the end of a text (a truncated log line) cannot pass the checksum,
#: but most of it is still the key: redaction (never detection) removes it too (LES-021).
#: (A cut run must start a token and hold a non-hex letter — a hash is not a key.)
_CUT_WIF = re.compile(rf"(?<![0-9A-Za-z])(?=[0-9A-Za-z]{{0,107}}[g-km-zG-HJ-NP-Z])[59KLc][{_B58}]{{29,51}}\Z")
_CUT_EXTENDED = re.compile(rf"(?<![0-9A-Za-z])[xyztuvYZ]prv[{_B58}]{{0,107}}\Z")
_WIF_VERSIONS = frozenset({0x80, 0xEF})
_EXTENDED_VERSIONS = frozenset(bytes.fromhex(version) for version in (
    "0488ade4", "049d7878", "04b2430c",          # xprv, yprv, zprv
    "04358394", "044a4e28", "045f18bc",          # tprv, uprv, vprv
    "0295b005", "02aa7a99",                      # Yprv, Zprv (multisig)
))
#: secp256k1's group order: a private key is 1 <= k < N.
_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass(frozen=True)
class BitcoinKey:
    """A verified key in a text: ``start``/``end`` offsets; ``kind`` — ``"wif"`` or ``"extended"``."""

    start: int
    end: int
    kind: str


def check_decode(text: str) -> Optional[bytes]:
    """The payload of Base58Check *text* (version included, checksum removed), or None
    when the checksum does not hold."""
    raw = base58.decode(text)
    if len(raw) < 5:
        return None
    body, checksum = raw[:-4], raw[-4:]
    return body if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == checksum else None


def _in_range(key: bytes) -> bool:
    return 0 < int.from_bytes(key, "big") < _CURVE_ORDER


def _is_wif(text: str) -> bool:
    body = check_decode(text)
    if body is None or body[0] not in _WIF_VERSIONS:
        return False
    compressed = len(body) == 34 and body[33] == 0x01
    return (len(body) == 33 or compressed) and _in_range(body[1:33])


def _is_extended(text: str) -> bool:
    body = check_decode(text)
    return (body is not None and len(body) == 78 and body[:4] in _EXTENDED_VERSIONS
            and body[45] == 0x00 and _in_range(body[46:78]))


def find_bitcoin_private_keys(text: str) -> list[BitcoinKey]:
    """Every verified WIF or extended private key in *text*, in order."""
    if not text:
        return []
    found = [BitcoinKey(*match.span(), "wif") for match in _WIF.finditer(text) if _is_wif(match.group(0))]
    found += [BitcoinKey(*match.span(), "extended") for match in _EXTENDED.finditer(text) if _is_extended(match.group(0))]
    return sorted(found, key=lambda key: key.start)


def redact_bitcoin_keys(text: str) -> str:
    """*text* with every verified key — and a key-shaped run cut off at the end of the
    text — replaced by :data:`WIF_MARKER` / :data:`EXTENDED_MARKER`."""
    for key in reversed(find_bitcoin_private_keys(text)):
        text = text[:key.start] + (WIF_MARKER if key.kind == "wif" else EXTENDED_MARKER) + text[key.end:]
    return _CUT_WIF.sub(WIF_MARKER, _CUT_EXTENDED.sub(EXTENDED_MARKER, text))
