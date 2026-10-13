"""Solana secret keys — recognised by their own proof, not by their shape.

A Solana secret key is 64 bytes: a 32-byte Ed25519 seed followed by the public
key derived from it. Phantom's "Export private key" shows it as one base58
string (87–88 characters); the Solana CLI writes it to ``id.json`` as a JSON
array of 64 numbers. A transaction signature looks the same (88 base58
characters), but its second half is not the public key of its first half —
it passes the check below with probability about 2^-256. So every candidate is
verified, and an unverifiable one is never called a key
(``@solana/web3.js`` ``Keypair.fromSecretKey`` enforces the same rule).

Used by redaction (a key is never written to Blackbox's logs) and by detection
(an agent handling one is flagged, sending one off the machine is blocked).

Usage::

    find_solana_secret_keys(text)   # -> [(start, end), ...] spans of verified keys
    redact_solana_keys(text)        # -> text with each key replaced by MARKER
"""

from __future__ import annotations

import logging
import re
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)

MARKER = "[REDACTED_SOLANA_KEY]"
_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: value for value, char in enumerate(_ALPHABET)}
#: 64 bytes in base58 are 86–88 characters (87–88 in practice); 89 allows one slack.
_BASE58_KEY = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{86,89}(?![1-9A-HJ-NP-Za-km-z])")
#: The Solana CLI's keypair file: a JSON array of exactly 64 byte values.
_JSON_KEY = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")
#: A key CUT OFF at the end of a text (a truncated log line or argument) cannot pass
#: the self-check, yet its first half is the seed. Redaction (never detection) also
#: removes a key-shaped run that ends the text — as the PEM rule does (LES-021).
_CUT_BASE58 = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{45,89}\Z")
_CUT_JSON = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){31,63}\d{0,3}\s*\Z")
#: A text with more candidates than this is not a place keys hide; stop verifying.
_MAX_CANDIDATES = 64
_SEED_BYTES = 32


def _base58_decode(text: str) -> bytes:
    """Bitcoin-alphabet base58 to bytes (leading '1's are zero bytes)."""
    number = 0
    for char in text:
        number = number * 58 + _INDEX[char]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def _json_bytes(text: str) -> Optional[bytes]:
    values = [int(part) for part in re.findall(r"\d+", text)]
    return bytes(values) if all(value < 256 for value in values) else None


def _public_key(seed: bytes) -> Optional[bytes]:
    """The Ed25519 public key of *seed*, or None when it cannot be computed here."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:   # pragma: no cover - cryptography is a core dependency
        logger.warning("blackbox: cryptography unavailable; Solana keys cannot be verified")
        return None
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def is_solana_secret_key(material: Optional[bytes]) -> bool:
    """True when *material* is 64 bytes whose second half is the public key of its first."""
    if material is None or len(material) != 2 * _SEED_BYTES:
        return False
    return _public_key(material[:_SEED_BYTES]) == material[_SEED_BYTES:]


def find_solana_secret_keys(text: str) -> List[Tuple[int, int]]:
    """Spans of every VERIFIED Solana secret key in *text* (base58 or JSON array), in order."""
    if not text:
        return []
    spans: List[Tuple[int, int]] = []
    candidates: List[Tuple["re.Match[str]", Callable[[str], Optional[bytes]]]] = []
    candidates += [(m, _base58_decode) for m in _BASE58_KEY.finditer(text)]
    candidates += [(m, _json_bytes) for m in _JSON_KEY.finditer(text)]
    for match, decode in candidates[:_MAX_CANDIDATES]:
        if is_solana_secret_key(decode(match.group(0))):
            spans.append(match.span())
    return sorted(spans)


def redact_solana_keys(text: str) -> str:
    """*text* with every verified Solana secret key — and a key-shaped run cut off at
    the end of the text — replaced by :data:`MARKER`."""
    spans = find_solana_secret_keys(text)
    for start, end in reversed(spans):
        text = text[:start] + MARKER + text[end:]
    return _CUT_JSON.sub(MARKER, _CUT_BASE58.sub(MARKER, text))
