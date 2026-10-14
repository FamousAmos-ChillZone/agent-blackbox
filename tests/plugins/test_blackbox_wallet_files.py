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
    from plugins.blackbox.shields.trader import mode as trader_mode
    monkeypatch.setattr(trader_mode, "current", lambda: trader_mode.build(enabled=True))   # Web3 wallet protection on

    result = hooks.on_pre_tool_call(tool_name="terminal", args={"command": command})

    assert result and result["action"] == "block"
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": "cat README.md"}) is None
    # Mode off (the default), or MetaMask not chosen: the same read is not blocked.
    monkeypatch.setattr(trader_mode, "current", lambda: trader_mode.build(enabled=False))
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": command}) is None
    monkeypatch.setattr(trader_mode, "current", lambda: trader_mode.build(enabled=True, wallets=()))
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": command}) is None


def test_a_firefox_vault_read_counts_while_trader_shield_is_on():
    """KI-366: Firefox storage cannot be tied to one wallet, so it was named "a Firefox
    extension" — which no chosen wallet matched, and the gate dropped every Firefox read."""
    from plugins.blackbox.shields.trader import mode as trader_mode

    path = "~/.mozilla/firefox/ab12.default/storage/default/moz-extension+++0b6f^userContextId=4294967295/idb/x.sqlite"
    [finding] = detect_wallet_files("read_file", {"path": path})
    as_dict = {"identifier": finding.identifier, "fields": finding.fields}
    assert trader_mode.allows_finding(as_dict, trader_mode.build(enabled=True))
    assert not trader_mode.allows_finding(as_dict, trader_mode.build(enabled=False))
    assert not trader_mode.allows_finding(as_dict, trader_mode.build(enabled=True, wallets=()))


def test_archiving_a_folder_with_several_wallets_names_every_one(monkeypatch):
    """KI-367: the archive check named only the FIRST wallet inside, so with that
    wallet unticked the gate dropped the finding and a ticked wallet's vault left."""
    from plugins.blackbox.shields.trader import mode as trader_mode

    profile = wallet_files.normalize_path("~/.config/google-chrome/Default")
    stores = [(profile + "/local extension settings/" + CHROME_ID, "MetaMask"),
              (profile + "/local extension settings/" + "b" * 32, "SecondWallet")]
    monkeypatch.setattr(wallet_files.EXISTING_STORES, "get", lambda: stores)

    findings = detect_wallet_files("terminal", {"command": "tar czf /tmp/x.tgz ~/.config/google-chrome"})

    assert sorted(f.fields["wallet"] for f in findings) == ["metamask", "secondwallet"]
    only_second = trader_mode.build(enabled=True, wallets=("secondwallet",))
    kept = [f for f in findings if trader_mode.allows_finding({"identifier": f.identifier, "fields": f.fields}, only_second)]
    assert [f.fields["wallet"] for f in kept] == ["secondwallet"]


PHANTOM_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa"


@pytest.mark.parametrize("path", [
    f"{MAC_CHROME}/Default/Local Extension Settings/{PHANTOM_ID}/000003.log",
    f"{MAC_CHROME}/Profile 1/Sync Extension Settings/{PHANTOM_ID}/LOG",
    f"{MAC_CHROME}/Default/IndexedDB/chrome-extension_{PHANTOM_ID}_0.indexeddb.leveldb/000005.ldb",
    f"~/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/{PHANTOM_ID}",
])
def test_any_read_of_phantoms_store_is_found_and_named(path):
    [finding] = detect_wallet_files("read_file", {"path": path})
    assert finding.fields["wallet"] == "phantom" and "Phantom" in finding.title and finding.severity == "critical"


@pytest.mark.parametrize("profile_root", [
    ".config/mozilla/firefox/ab12.default-release",              # Firefox 147+ on Linux (XDG)
    "snap/firefox/common/.mozilla/firefox/ab12.default",          # Ubuntu's default snap Firefox
    ".var/app/org.mozilla.firefox/.mozilla/firefox/ab12.default", # Flatpak Firefox
])
def test_archiving_a_firefox_profile_in_every_linux_layout_is_found(tmp_path, monkeypatch, profile_root):
    """KI-368: a real Firefox on a bench keeps its profile in ~/.config/mozilla (Firefox 147+) or
    ~/snap/firefox/... — the folder check only knew ~/.mozilla, so tar of the profile was missed."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    store = tmp_path / profile_root / "storage" / "default" / "moz-extension+++4b8e0c78^userContextId=4294967295"
    store.mkdir(parents=True)
    (store / "data.sqlite").write_text("x", encoding="utf-8")
    wallet_files.EXISTING_STORES.reset()
    try:
        archive_root = str(tmp_path / profile_root).rsplit("/", 1)[0]   # the folder holding the profiles
        [finding] = detect_wallet_files("terminal", {"command": f"tar czf /tmp/p.tgz {archive_root}"})
        assert finding.fields["wallet"] == "any-extension"
    finally:
        wallet_files.EXISTING_STORES.reset()


@pytest.mark.parametrize("store_parent", [
    "snap/chromium/common/chromium/Default/Local Extension Settings",
    ".var/app/com.google.Chrome/config/google-chrome/Default/Local Extension Settings",
    ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default/Local Extension Settings",
])
def test_archiving_a_snap_or_flatpak_chromium_profile_is_found(tmp_path, monkeypatch, store_parent):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    store = tmp_path / store_parent / CHROME_ID
    store.mkdir(parents=True)
    (store / "000003.log").write_text("vault", encoding="utf-8")
    wallet_files.EXISTING_STORES.reset()
    try:
        profile = str(tmp_path / store_parent).rsplit("/Default/", 1)[0]
        [finding] = detect_wallet_files("terminal", {"command": f"tar czf /tmp/p.tgz {profile}"})
        assert finding.fields["wallet"] == "metamask"
    finally:
        wallet_files.EXISTING_STORES.reset()
