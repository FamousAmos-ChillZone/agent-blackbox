"""The dashboard's wallet-protection panel (trader rules): what was found, how it is protected, what happened.

The panel must show the wallets that really exist on this machine (by folder name only),
say plainly whether Blackbox blocks or only watches, and list only wallet events.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.dashboard import protection
from plugins.blackbox.detection import wallet_files
from plugins.blackbox.kernel.config import BlackboxConfig

METAMASK_CHROME = wallet_files.WALLETS[0].chromium_ids[0]


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    wallet_files.EXISTING_STORES.reset()
    yield tmp_path
    wallet_files.EXISTING_STORES.reset()


def _vault(home, *parts):
    folder = home.joinpath(".config", "google-chrome", "Default", *parts)
    folder.mkdir(parents=True)
    (folder / "000003.log").write_text("placeholder", encoding="utf-8")


def test_a_metamask_vault_on_this_machine_is_listed_by_browser_profile_and_area(home):
    _vault(home, "Local Extension Settings", METAMASK_CHROME)
    _vault(home, "IndexedDB", f"chrome-extension_{METAMASK_CHROME}_0.indexeddb.leveldb")
    [found] = wallet_files.found_wallets()
    assert (found["wallet"], found["browser"], found["profile"]) == ("MetaMask", "Chrome", "default")   # paths are lower-cased
    assert sorted(found["areas"]) == ["backup copy", "vault"]


def test_a_machine_without_a_wallet_lists_none(home):
    assert wallet_files.found_wallets() == []


@pytest.mark.parametrize("mode, shown", [("block", "block"), ("audit", "audit")])
def test_the_panel_says_whether_it_blocks_or_only_watches(home, monkeypatch, mode, shown):
    monkeypatch.setattr(protection, "load_blackbox_config", lambda: BlackboxConfig(mode=mode))
    payload = protection.wallet_protection_payload()
    assert payload["mode"] == shown and payload["seed_checker"] is True and payload["terminal_reads"] == "logged"


def test_only_wallet_events_are_listed_with_blocked_or_flagged(home, monkeypatch):
    monkeypatch.setattr(protection, "load_blackbox_config", lambda: BlackboxConfig(mode="block"))
    findings = home / "bb" / "findings.jsonl"
    findings.parent.mkdir(parents=True)
    rows = [
        {"ts": 1, "detail": {"decision": "block"},
         "finding": {"identifier": "fileaccess:terminal:crypto-wallet", "title": "MetaMask key store", "tool_name": "terminal"}},
        {"ts": 2, "detail": {}, "finding": {"identifier": "secret:wallet-private-key", "title": "Wallet private key"}},
        {"ts": 3, "detail": {}, "finding": {"identifier": "ioc:domain:evil.example", "title": "not a wallet event"}},
    ]
    findings.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    events = protection.wallet_protection_payload()["events"]
    assert sorted((e["identifier"], e["outcome"]) for e in events) == [
        ("fileaccess:terminal:crypto-wallet", "blocked"), ("secret:wallet-private-key", "flagged")]
