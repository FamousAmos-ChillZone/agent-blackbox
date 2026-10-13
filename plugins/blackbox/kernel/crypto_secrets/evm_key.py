"""Raw Ethereum private keys, recognised by the address they open.

A raw key is 64 hex characters — exactly what a transaction hash, a block hash
or a file digest looks like, so its shape proves nothing. What proves it is
the address: a private key derives one address (secp256k1 public key →
Keccak-256 → last 20 bytes). When the operator has listed their own wallet
addresses (Trader Shield settings), a 64-hex value whose address is on that
list IS one of their keys; any other 64-hex value is left alone.

Keccak-256 is Ethereum's hash (the original Keccak padding, not NIST SHA3-256),
which Python's hashlib does not offer; it is implemented here from the Keccak
reference (keccak.team, Keccak-f[1600], rate 1088) and checked against
published vectors and Foundry's ``cast wallet address`` in the tests.

Usage::

    address_of(bytes.fromhex("00" * 31 + "01"))   # -> "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    own_keys_in("curl -d k=<64 hex> …", {"0x7e5f…"})   # -> 1 when the key opens a listed address
"""

from __future__ import annotations

import re
from typing import AbstractSet, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#: secp256k1's group order: a private key is 1 ≤ k < N.
_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#: A 64-hex value standing alone (with or without 0x) — a candidate raw key.
_CANDIDATE = re.compile(r"(?<![0-9A-Za-z])(?:0x)?([0-9a-fA-F]{64})(?![0-9A-Za-z])")
#: Ethereum address as the operator lists it.
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROTATIONS = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
_MASK = (1 << 64) - 1
_RATE = 136   # bytes: 1600-bit state minus 2 × 256-bit capacity


def _rotate(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(state: list) -> None:
    """Keccak-f[1600] on a 5×5 state of 64-bit lanes (``state[x][y]``), in place."""
    for constant in _ROUND_CONSTANTS:
        columns = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        for x in range(5):
            mix = columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x][y] ^= mix
        moved = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                moved[y][(2 * x + 3 * y) % 5] = _rotate(state[x][y], _ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = moved[x][y] ^ ((~moved[(x + 1) % 5][y]) & moved[(x + 2) % 5][y])
        state[0][0] ^= constant


def keccak256(data: bytes) -> bytes:
    """Ethereum's Keccak-256 of *data* (original Keccak padding 0x01…0x80)."""
    room = _RATE - len(data) % _RATE   # bytes left in the last block (1…136)
    # One byte left: the opening 0x01 and the closing 0x80 share it (0x81).
    padded = bytearray(data) + (b"\x81" if room == 1 else b"\x01" + b"\x00" * (room - 2) + b"\x80")
    state = [[0] * 5 for _ in range(5)]
    for block in range(0, len(padded), _RATE):
        for lane in range(_RATE // 8):
            word = int.from_bytes(padded[block + 8 * lane:block + 8 * lane + 8], "little")
            state[lane % 5][lane // 5] ^= word
        _permute(state)
    return b"".join(state[lane % 5][lane // 5].to_bytes(8, "little") for lane in range(4))


def address_of(private_key: bytes) -> Optional[str]:
    """The Ethereum address (lower-case ``0x…``) a 32-byte *private_key* opens, or
    None when it is not a valid secp256k1 key."""
    number = int.from_bytes(private_key, "big")
    if len(private_key) != 32 or not 0 < number < _CURVE_ORDER:
        return None
    public = ec.derive_private_key(number, ec.SECP256K1()).public_key()
    point = public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]   # drop the 0x04 prefix
    return "0x" + keccak256(point)[-20:].hex()


def own_keys_in(text: str, addresses: AbstractSet[str]) -> int:
    """How many 64-hex values in *text* are private keys of the listed *addresses*
    (lower-case ``0x…``). Zero when no address is listed — nothing is derived."""
    if not text or not addresses:
        return 0
    count = 0
    for candidate in {match.group(1).lower() for match in _CANDIDATE.finditer(text)}:
        if address_of(bytes.fromhex(candidate)) in addresses:
            count += 1
    return count
