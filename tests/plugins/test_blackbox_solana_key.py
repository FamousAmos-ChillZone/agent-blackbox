"""Solana secret keys (Phantom's exported key, the Solana CLI id.json) — kernel/crypto_secrets/solana_key.py.

Keys are made AT RUNTIME from fresh Ed25519 keypairs and encoded by a base58
encoder written here, independent of the code under test (LES-022: no
key-shaped literal in the repo). The negative cases are the look-alikes an
agent handles all day: transaction signatures (same length and alphabet) and
public addresses.
"""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from plugins.blackbox.kernel import crypto_secrets, redaction

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, digit = divmod(number, 58)
        out = ALPHABET[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def keypair_bytes() -> bytes:
    """A real Solana secret key: 32-byte seed + its Ed25519 public key."""
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes_raw()
    return seed + private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def phantom_export() -> str:
    return base58(keypair_bytes())


def cli_keyfile() -> str:
    return "[" + ",".join(str(b) for b in keypair_bytes()) + "]"


def signature() -> str:
    """A transaction-signature look-alike: 64 bytes that are NOT seed + public key."""
    return base58(os.urandom(64))


# ------------------------------------------------------------------ recognition


def test_a_phantom_exported_key_is_found():
    key = phantom_export()
    text = f"my phantom key is {key} ok"
    assert crypto_secrets.find_solana_secret_keys(text) == [(text.index(key), text.index(key) + len(key))]


def test_a_solana_cli_keyfile_is_found_in_json_with_any_spacing():
    compact = cli_keyfile()
    spaced = compact.replace(",", ", ").replace("[", "[\n  ")
    assert crypto_secrets.find_solana_secret_keys(compact) and crypto_secrets.find_solana_secret_keys(spaced)


@pytest.mark.parametrize("make", [signature, lambda: base58(os.urandom(32)), lambda: "[" + ",".join(str(b) for b in os.urandom(64)) + "]"],
                         ids=["transaction-signature", "public-address", "random-64-byte-array"])
def test_look_alikes_are_never_keys(make):
    assert crypto_secrets.find_solana_secret_keys(f"seen {make()} here") == []


def test_a_key_with_one_character_changed_is_not_a_key():
    key = phantom_export()
    swapped = key[:40] + ("2" if key[40] != "2" else "3") + key[41:]
    assert crypto_secrets.find_solana_secret_keys(swapped) == []


# -------------------------------------------------------------------- redaction


def test_redaction_removes_every_byte_of_the_key():
    key, keyfile = phantom_export(), cli_keyfile()
    out = redaction.redact_secret_values(f"export {key} and file {keyfile} done")
    assert key not in out and keyfile not in out and out.count(crypto_secrets.SOLANA_KEY_MARKER) == 2
    assert out.startswith("export ") and out.endswith(" done")


def test_a_key_cut_off_at_the_end_of_the_text_is_still_removed():
    """LES-021: a truncated key cannot pass the self-check, but its first half is the seed."""
    key = phantom_export()
    out = redaction.redact_secret_values("leaked " + key[:60])
    assert key[:60] not in out and out == "leaked " + crypto_secrets.SOLANA_KEY_MARKER
    numbers = cli_keyfile()[:-1].split(",")
    out = redaction.redact_secret_values("file " + ",".join(numbers[:40]))
    assert out == "file " + crypto_secrets.SOLANA_KEY_MARKER


def test_signatures_and_addresses_survive_redaction():
    sig, address = signature(), base58(os.urandom(32))
    text = f"tx {sig} from {address} confirmed"
    assert redaction.redact_secret_values(text) == text
