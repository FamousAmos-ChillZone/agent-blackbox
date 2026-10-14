"""Base58 — the Bitcoin alphabet many wallets write keys in (Solana keys, Bitcoin WIF, xprv).

Usage::

    decode("2NEpo7TZRRrLZSi2U")   # -> bytes (leading '1's become zero bytes)
"""

from __future__ import annotations

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: value for value, char in enumerate(ALPHABET)}


def decode(text: str) -> bytes:
    """Bitcoin-alphabet base58 to bytes (leading '1's are zero bytes)."""
    number = 0
    for char in text:
        number = number * 58 + _INDEX[char]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body
