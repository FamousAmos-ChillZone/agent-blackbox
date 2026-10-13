"""Wallet key stores an agent must never read (detection/wallet_files.py) — MetaMask first.

Each test drives one way an agent reaches MetaMask's vault (or a way that must
NOT count) through the real detector, and the guard's block decision.
"""

from __future__ import annotations

import os

import pytest

from plugins.blackbox.detection import detect_all, wallet_files
from plugins.blackbox.detection.wallet_files import detect_wallet_files

CHROME_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
EDGE_ID = "ejbalbakoplchlghecdalmeeeajnimhm"
MAC_CHROME = "~/Library/Application Support/Google/Chrome"


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A home folder holding MetaMask in Chrome's Default profile on macOS layout."""
    monkeypatch.setenv("HOME", str(tmp_path))
    store = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Local Extension Settings" / CHROME_ID
    store.mkdir(parents=True)
    (store / "000003.log").write_text("vault", encoding="utf-8")
    wallet_files.EXISTING_STORES.reset()
    yield tmp_path
    wallet_files.EXISTING_STORES.reset()


def _shell(command):
    return detect_wallet_files("terminal", {"command": command})


@pytest.mark.parametrize("path", [
    f"{MAC_CHROME}/Default/Local Extension Settings/{CHROME_ID}/000003.log",
    f"{MAC_CHROME}/Profile 2/Sync Extension Settings/{CHROME_ID}/LOG",
    f"{MAC_CHROME}/Default/IndexedDB/chrome-extension_{CHROME_ID}_0.indexeddb.leveldb/000005.ldb",
    f"~/.config/microsoft-edge/Default/Local Extension Settings/{EDGE_ID}/CURRENT",
    f"/custom/user-data-dir/Default/Local Extension Settings/{CHROME_ID}",          # root-agnostic
    f"C:\\Users\\a\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Extension Settings\\{CHROME_ID}\\x.ldb",
    "~/.mozilla/firefox/ab12.default/storage/default/moz-extension+++0b6f-uuid^userContextId=4294967295/idb/x.sqlite",
])
def test_file_tool_read_of_any_metamask_store_is_found(path):
    findings = detect_wallet_files("read_file", {"path": path})
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.category, finding.severity, finding.source) == ("fileaccess", "critical", "secret")
    assert finding.fields["file_category"] == "crypto-wallet"


def test_finding_never_carries_the_path():
    finding = detect_wallet_files("read_file", {"path": f"/x/Default/Local Extension Settings/{CHROME_ID}/a.log"})[0]
    assert "Local Extension Settings" not in finding.evidence and CHROME_ID not in str(finding.to_dict())


def test_shell_read_with_escaped_spaces_is_found():
    command = f"cat ~/Library/Application\\ Support/Google/Chrome/Default/Local\\ Extension\\ Settings/{CHROME_ID}/000003.log"
    assert _shell(command)[0].evidence == "read crypto-wallet (MetaMask)"


def test_archiving_a_browser_folder_that_holds_metamask_is_found(fake_home):
    assert _shell("tar czf out.tgz ~/Library/Application\\ Support/Google/Chrome")[0].evidence == "copy crypto-wallet (MetaMask)"
    assert _shell('zip -r out.zip "$HOME/Library/Application Support/Google"')
    assert _shell("cp -r ~/Library /tmp/stash")
    assert _shell("tar czf home.tgz ~")


def test_archiving_a_browser_folder_without_metamask_is_not_found(fake_home):
    other = fake_home / "Library" / "Application Support" / "Vivaldi" / "Default"
    other.mkdir(parents=True)
    assert _shell("tar czf out.tgz ~/Library/Application\\ Support/Vivaldi") == []


def test_non_recursive_read_of_a_parent_folder_is_not_found(fake_home):
    assert _shell("cat ~/Library/Application\\ Support/Google/Chrome/Local\\ State") == []
    assert _shell("ls -la ~/Library/Application\\ Support/Google/Chrome/Default") == []


def test_other_extensions_in_chromium_are_not_found():
    other = "aaaabbbbccccddddeeeeffffgggghhhh"
    assert detect_wallet_files("read_file", {"path": f"/x/Default/Local Extension Settings/{other}/a.log"}) == []


def test_ordinary_project_files_are_not_found(fake_home):
    assert _shell("cat package.json && tar czf build.tgz ./dist") == []
    assert detect_wallet_files("read_file", {"path": "src/wallet/metamask.ts"}) == []


def test_detect_all_includes_the_wallet_rule_even_with_discovery_off():
    findings = detect_all("read_file", {"path": f"/x/Default/Local Extension Settings/{CHROME_ID}/a.log"}, None, discover=False)
    assert any(f.fields.get("file_category") == "crypto-wallet" for f in findings)


def test_wallet_finding_blocks_in_block_mode():
    from plugins.blackbox.guard import hooks
    from plugins.blackbox.kernel.config import BlackboxConfig
    finding = detect_wallet_files("read_file", {"path": f"/x/Default/Local Extension Settings/{CHROME_ID}/a.log"})
    assert hooks._blocking(BlackboxConfig(mode="block"), finding) == finding
    assert hooks._blocking(BlackboxConfig(mode="audit"), finding) == []


def test_existing_store_scan_finds_the_fake_install(fake_home):
    found = wallet_files.EXISTING_STORES.get()
    assert [wallet for _path, wallet in found] == ["MetaMask"]
    assert all(os.sep not in path or path == path.lower() for path, _wallet in found)


def test_hook_blocks_a_terminal_read_of_metamask_in_block_mode(monkeypatch):
    from plugins.blackbox import ruleset as ruleset_mod
    from plugins.blackbox.guard import background as guard_background
    from plugins.blackbox.guard import hooks
    from plugins.blackbox.guard import reporting as guard_reporting
    from plugins.blackbox.kernel import config as config_mod
    from plugins.blackbox.ruleset import Ruleset
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block"))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    command = f"base64 ~/.config/google-chrome/Default/Local\\ Extension\\ Settings/{CHROME_ID}/000003.log"
    from plugins.blackbox.kernel.crypto_secrets import wallet_mode
    monkeypatch.setattr(wallet_mode, "current", lambda: wallet_mode.WalletProtection(enabled=True))   # Web3 wallet protection on

    result = hooks.on_pre_tool_call(tool_name="terminal", args={"command": command})

    assert result and result["action"] == "block"
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": "cat README.md"}) is None
    # Mode off (the default), or MetaMask not chosen: the same read is not blocked.
    monkeypatch.setattr(wallet_mode, "current", lambda: wallet_mode.WalletProtection(enabled=False))
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": command}) is None
    monkeypatch.setattr(wallet_mode, "current", lambda: wallet_mode.WalletProtection(enabled=True, wallets=()))
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": command}) is None


def test_a_firefox_vault_read_counts_while_trader_shield_is_on():
    """KI-366: Firefox storage cannot be tied to one wallet, so it was named "a Firefox
    extension" — which no chosen wallet matched, and the gate dropped every Firefox read."""
    from plugins.blackbox.kernel.crypto_secrets import wallet_mode

    path = "~/.mozilla/firefox/ab12.default/storage/default/moz-extension+++0b6f^userContextId=4294967295/idb/x.sqlite"
    [finding] = detect_wallet_files("read_file", {"path": path})
    as_dict = {"identifier": finding.identifier, "fields": finding.fields}
    assert wallet_mode.WalletProtection(enabled=True).allows_finding(as_dict)
    assert not wallet_mode.WalletProtection(enabled=False).allows_finding(as_dict)
    assert not wallet_mode.WalletProtection(enabled=True, wallets=()).allows_finding(as_dict)
