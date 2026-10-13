"""Trader Shield's attack table (dashboard/static/trader-shield-attacks.json) stays true.

The Trader Shield page shows people which Web3 attacks are blocked, flagged or not covered.
That table is the single source: every ``proof: "test"`` scenario is driven here through the
REAL pre-execution hook (Trader Shield on for MetaMask, block mode, block at critical, the
local rules only) and must give exactly the outcome the page claims. ``proof: "bench"``
scenarios need the verified threat graph or live OSV and are proven on a bench node (the
run is stamped in ``bench_run``). Placeholders are filled with values made at test time —
no secret-shaped literal lives in the repo (LES-022).
"""

from __future__ import annotations

import hashlib
import json
import random
import os
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.dashboard import protection
from plugins.blackbox.detection import wallet_files
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import crypto_secrets
from plugins.blackbox.kernel.crypto_secrets import seed_phrase, wallet_mode
from plugins.blackbox.ruleset import Ruleset

TABLE = json.loads((protection.TRADER_SHIELD_PAGE.parent / "trader-shield-attacks.json").read_text(encoding="utf-8"))
METAMASK = "nkbihfbeogaeaoehlefnkodbefgpgknn"
PHANTOM = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
#: blocked / flagged / missed (a gap); allowed = a harmless look-alike that must raise nothing.
OUTCOMES = {"blocked", "flagged", "missed", "allowed"}
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WORDS = seed_phrase.WORDLIST_FILE.read_text(encoding="ascii").split()


def _phrase(entropy: bytes) -> str:
    """A checksum-valid BIP-39 phrase, encoded here independently of the code under test."""
    bits = len(entropy) * 8
    checksum_bits = bits // 32
    value = int.from_bytes(entropy, "big") << checksum_bits | hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    count = (bits + checksum_bits) // 11
    return " ".join(WORDS[(value >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count))


def _base58(data: bytes) -> str:
    number, out = int.from_bytes(data, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        out = BASE58[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _solana_key() -> bytes:
    """A real Solana secret key, made here: Ed25519 seed + its public key."""
    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw() + private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture
def shield(tmp_path, monkeypatch):
    """MetaMask and Phantom installed in Chrome, Trader Shield on for both, block mode; returns a
    placeholder filler and the list the hook's findings land in."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    vault = tmp_path / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / METAMASK
    phantom = vault.parent / PHANTOM
    backup = tmp_path / ".config" / "google-chrome" / "Default" / "IndexedDB" / f"chrome-extension_{PHANTOM}_0.indexeddb.leveldb"
    for folder in (vault, phantom, backup):
        folder.mkdir(parents=True)
        (folder / "000003.log").write_text("vault", encoding="utf-8")
    wallet_files.EXISTING_STORES.reset()
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    findings: list = []
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda cfg, event, found, detail: findings.extend(found))
    seed12, seed24, key = _phrase(os.urandom(16)), _phrase(os.urandom(32)), "0x" + secrets.token_hex(32)
    # Every supported wallet chosen, and @KEY@'s address listed as the trader's own (settings).
    own = wallet_mode.WalletProtection(enabled=True, addresses=(crypto_secrets.address_of(bytes.fromhex(key[2:])),))
    monkeypatch.setattr(wallet_mode, "current", lambda: own)
    solana = _solana_key()
    values = {"@SEED12PLUS@": seed12.replace(" ", "+"), "@SEED12@": seed12, "@SEED24@": seed24, "@KEY@": key,
              "@HEX@": key[2:], "@TXHASH@": secrets.token_hex(32), "@APIKEY@": secrets.token_hex(32), "@VAULTFILE@": str(vault / "000003.log"),
              "@VAULT@": "~/.config/google-chrome/Default/Local\\ Extension\\ Settings/" + METAMASK,
              "@PHANTOMFILE@": str(phantom / "000003.log"),
              "@PHANTOM@": "~/.config/google-chrome/Default/Local\\ Extension\\ Settings/" + PHANTOM,
              "@SOLKEY@": _base58(solana), "@SOLFILE@": "[" + ",".join(str(b) for b in solana) + "]",
              "@SOLSIG@": _base58(random.randbytes(64))}

    def fill(value):
        if isinstance(value, str):
            for marker, real in values.items():
                value = value.replace(marker, real)
            return value
        if isinstance(value, list):
            return [fill(item) for item in value]
        return {k: fill(v) for k, v in value.items()} if isinstance(value, dict) else value

    yield fill, findings
    wallet_files.EXISTING_STORES.reset()


LOCAL = [attack for attack in TABLE["attacks"] if attack["proof"] == "test"]


@pytest.mark.parametrize("attack", LOCAL, ids=[attack["id"] for attack in LOCAL])
def test_each_attack_has_the_outcome_the_page_claims(shield, attack):
    fill, findings = shield
    result = hooks.on_pre_tool_call(tool_name=attack["tool"], args=fill(attack["args"]), session_id="matrix")
    outcome = "blocked" if result and result.get("action") == "block" else ("flagged" if findings else "missed")
    expected = "missed" if attack["outcome"] == "allowed" else attack["outcome"]   # allowed: nothing raised, by design
    assert outcome == expected, [f.identifier for f in findings]


def test_the_table_is_well_formed():
    groups = {group["id"] for group in TABLE["groups"]}
    ids = [attack["id"] for attack in TABLE["attacks"]]
    assert len(ids) == len(set(ids))
    for attack in TABLE["attacks"]:
        assert attack["group"] in groups and attack["outcome"] in OUTCOMES and attack["proof"] in ("test", "bench")
        assert attack["title"] and attack["how"] and attack["args"]
    assert TABLE.get("bench_run")


def test_every_gap_says_what_would_close_it():
    for attack in TABLE["attacks"]:
        if attack["outcome"] == "missed":
            assert attack["group"] == "gap" and attack.get("next"), attack["id"]


def test_the_page_reads_the_table_it_is_tested_against():
    page = protection.TRADER_SHIELD_PAGE.read_text(encoding="utf-8")
    assert 'fetch("/trader-shield/attacks.json"' in page
