"""Solana secret keys — recognised by their own proof, not by their shape.

A Solana secret key is 64 bytes: a 32-byte Ed25519 seed followed by the public
key derived from it. Phantom's "Export private key" shows it as one base58
string (87–88 characters); the Solana CLI writes it to ``id.json`` as a JSON
array of 64 numbers; scripts also pass it as 128 hex characters or as base64.
A transaction signature looks the same (88 base58 characters), but its second
half is not the public key of its first half — it passes the check below with
probability about 2^-256. So every candidate is verified, and an unverifiable
one is never called a key (``@solana/web3.js`` ``Keypair.fromSecretKey``
enforces the same rule).

Cost: a check is ~0.1 ms, so at most :data:`MAX_CANDIDATES` distinct candidates are
verified per text, later ones first. The rest are returned as UNCHECKED: redaction
removes them anyway (a log may lose a few signatures, never a key) and a detector
treats them as "could not tell" (KI-380: 64 decoys used to hide a key from the check).
The 32-byte seed half alone has no self-check (it reads like an address); only a
labelled one is caught, by the labelled-key rule in ``kernel/redaction.py``.

Used by redaction (a key is never written to Blackbox's logs) and by detection
(an agent handling one is flagged, sending one off the machine is blocked).

Usage::

    find_solana_secret_keys(text)   # -> [(start, end), ...] spans of verified keys
    scan_solana_keys(text)          # -> SolanaKeyScan(keys=[...], unchecked=[...])
    redact_solana_keys(text)        # -> text with each key replaced by MARKER
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass
from typing import Callable, Optional

from . import base58

logger = logging.getLogger(__name__)

MARKER = "[REDACTED_SOLANA_KEY]"
#: 64 bytes in base58 are 86–88 characters (87–88 in practice); 89 allows one slack.
_BASE58_KEY = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{86,89}(?![1-9A-HJ-NP-Za-km-z])")
#: The Solana CLI's keypair file: a JSON array of exactly 64 byte values.
_JSON_KEY = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")
#: A key CUT OFF at the end of a text (a truncated log line or argument) cannot pass
#: the self-check, yet its first half is the seed. Redaction (never detection) also
#: removes a key-shaped run that ends the text — as the PEM rule does (LES-021).
#: A cut run must start a token (no letter or digit before it) and hold a non-hex letter:
#: a hash, or the tail of one, at the end of a line is not a key.
_CUT_BASE58 = re.compile(r"(?<![0-9A-Za-z])(?=[0-9A-Za-z]{0,107}[g-km-zG-HJ-NP-Z])[1-9A-HJ-NP-Za-km-z]{45,89}\Z")
_CUT_JSON = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){31,63}\d{0,3}\s*\Z")
#: …and the hex form cut off (65+ hex: a lone 64-hex value is a hash, left alone). A cut
#: base64 key is NOT removed: its alphabet is a URL path's, so the rule would eat the end
#: of ordinary log lines (a known gap; whole base64 keys are verified and removed).
_CUT_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?[0-9A-Fa-f]{65,127}\Z")
#: Scripts write the key as 128 hex characters or as base64 (88 characters with padding).
_HEX_KEY = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{128}(?![0-9A-Fa-f])")
_BASE64_KEY = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{86}(?:==)?(?![A-Za-z0-9+/_=-])")
#: Most distinct candidates verified per text (~0.1 ms each); the rest are UNCHECKED.
MAX_CANDIDATES = 256
_SEED_BYTES = 32


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


def _base64_bytes(text: str) -> Optional[bytes]:
    try:
        return base64.b64decode(text.replace("-", "+").replace("_", "/") + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex_bytes(text: str) -> Optional[bytes]:
    return bytes.fromhex(text)


_DECODERS: tuple[tuple[re.Pattern[str], Callable[[str], Optional[bytes]]], ...] = (
    (_BASE58_KEY, base58.decode), (_JSON_KEY, _json_bytes), (_HEX_KEY, _hex_bytes), (_BASE64_KEY, _base64_bytes))


@dataclass(frozen=True)
class SolanaKeyScan:
    """``keys`` — spans of verified secret keys; ``unchecked`` — spans of key-shaped
    candidates left unverified because the text held more than :data:`MAX_CANDIDATES`.
    Both sorted by start."""

    keys: list[tuple[int, int]]
    unchecked: list[tuple[int, int]]


def scan_solana_keys(text: str) -> SolanaKeyScan:
    """Verify the key-shaped candidates in *text*, later ones first, up to the budget."""
    if not text:
        return SolanaKeyScan([], [])
    candidates = [(match.span(), match.group(0), decode) for pattern, decode in _DECODERS
                  for match in pattern.finditer(text)]
    candidates.sort(key=lambda candidate: candidate[0][0], reverse=True)   # later first: front padding cannot hide a key
    verdicts: dict[tuple[str, Callable[[str], Optional[bytes]]], bool] = {}
    keys: list[tuple[int, int]] = []
    unchecked: list[tuple[int, int]] = []
    for span, value, decode in candidates:
        if (value, decode) not in verdicts:
            if len(verdicts) >= MAX_CANDIDATES:
                unchecked.append(span)
                continue
            verdicts[(value, decode)] = is_solana_secret_key(decode(value))
        if verdicts[(value, decode)]:
            keys.append(span)
    return SolanaKeyScan(sorted(set(keys)), sorted(set(unchecked) - set(keys)))


def find_solana_secret_keys(text: str) -> list[tuple[int, int]]:
    """Spans of every VERIFIED Solana secret key in *text* (base58, JSON array, hex or
    base64), in order — within the verification budget (see :func:`scan_solana_keys`)."""
    return scan_solana_keys(text).keys


def redact_solana_keys(text: str) -> str:
    """*text* with every verified Solana secret key, every candidate left unchecked
    (over the budget — fail closed), and a key-shaped run cut off at the end of the
    text replaced by :data:`MARKER`."""
    scan = scan_solana_keys(text)
    for start, end in reversed(_merged(scan.keys + scan.unchecked)):
        text = text[:start] + MARKER + text[end:]
    for cut in (_CUT_BASE58, _CUT_JSON, _CUT_HEX):
        text = cut.sub(MARKER, text)
    return text


def _merged(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """*spans* sorted, overlapping ones joined (a base58 and a base64 reading of one run)."""
    out: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if out and start < out[-1][1]:
            out[-1] = (out[-1][0], max(end, out[-1][1]))
        else:
            out.append((start, end))
    return out
