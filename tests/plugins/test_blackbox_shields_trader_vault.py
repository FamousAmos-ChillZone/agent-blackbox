"""Trader Shield's browser-extension kind (shields/trader/detectors) — moved from
test_blackbox_wallet_files.py in shields S4a.

Each test drives one way an agent reaches a browser wallet's vault (or a way that must
NOT count) through the NEW detector, ``detectors.detect``. Until S5b deletes the old
module, every input also goes through ``detection.detect_wallet_files`` and the two
must give identical findings apart from the added ``pack`` field (:func:`_detect`);
the attack table's vault and Firefox rows are run through both the same way.
"""

from __future__ import annotations

import dataclasses
import json
import os

import pytest

from plugins.blackbox.dashboard import protection
from plugins.blackbox.detection import wallet_files
from plugins.blackbox.detection.wallet_files import detect_wallet_files
from plugins.blackbox.shields.contract import Pack
from plugins.blackbox.shields.trader import detectors
from plugins.blackbox.shields.trader import mode as trader_mode
from plugins.blackbox.shields.trader.detectors import browser_extension
from plugins.blackbox.shields.trader.detectors.browser_extension import BrowserExtensionMatcher, Owner

CHROME_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
EDGE_ID = "ejbalbakoplchlghecdalmeeeajnimhm"
PHANTOM_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
MAC_CHROME = "~/Library/Application Support/Google/Chrome"
EVERY_PACK = trader_mode.build(enabled=True)


def _same_apart_from_pack(new, old):
    """The new findings equal the old ones once ``pack`` is taken out (every kind, since the
    app-folder kinds joined in S4b), and ``pack``, when present, is the wallet's id."""
    for finding in new:
        assert finding.fields.get("pack", finding.fields["wallet"]) == finding.fields["wallet"]
    stripped = [dataclasses.replace(f, fields={k: v for k, v in f.fields.items() if k != "pack"}) for f in new]
    assert stripped == old


def _detect(tool, args, active=EVERY_PACK):
    """The new detector's findings, after checking the old one agrees (equivalence)."""
    new = detectors.detect(tool, args, active)
    _same_apart_from_pack(new, detect_wallet_files(tool, args))
    return new


def _reset_stores():
    wallet_files.EXISTING_STORES.reset()
    detectors.EXISTING_STORES.reset()


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A home folder holding MetaMask in Chrome's Default profile on macOS layout."""
    monkeypatch.setenv("HOME", str(tmp_path))
    store = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Local Extension Settings" / CHROME_ID
    store.mkdir(parents=True)
    (store / "000003.log").write_text("vault", encoding="utf-8")
    _reset_stores()
    yield tmp_path
    _reset_stores()


def _shell(command):
    return _detect("terminal", {"command": command})


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
    findings = _detect("read_file", {"path": path})
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.category, finding.severity, finding.source) == ("fileaccess", "critical", "secret")
    assert finding.fields["file_category"] == "crypto-wallet"


def test_finding_never_carries_the_path():
    finding = _detect("read_file", {"path": f"/x/Default/Local Extension Settings/{CHROME_ID}/a.log"})[0]
    assert "Local Extension Settings" not in finding.evidence and CHROME_ID not in str(finding.to_dict())


def test_a_finding_names_its_pack_by_id():
    """F-004: the pack is named by id in ``fields["pack"]``, the person-facing name stays in the text."""
    [finding] = _detect("read_file", {"path": f"/x/Default/Local Extension Settings/{CHROME_ID}/a.log"})
    assert finding.fields["pack"] == "metamask" and "MetaMask" in finding.title


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
    assert _detect("read_file", {"path": f"/x/Default/Local Extension Settings/{other}/a.log"}) == []


def test_ordinary_project_files_are_not_found(fake_home):
    assert _shell("cat package.json && tar czf build.tgz ./dist") == []
    assert _detect("read_file", {"path": "src/wallet/metamask.ts"}) == []


def test_wallet_finding_blocks_in_block_mode():
    from plugins.blackbox.guard import hooks
    from plugins.blackbox.kernel.config import BlackboxConfig
    finding = _detect("read_file", {"path": f"/x/Default/Local Extension Settings/{CHROME_ID}/a.log"})
    assert hooks._blocking(BlackboxConfig(mode="block"), finding) == finding
    assert hooks._blocking(BlackboxConfig(mode="audit"), finding) == []


def test_existing_store_scan_finds_the_fake_install(fake_home):
    found = detectors.EXISTING_STORES.get()
    assert [wallet for _path, wallet in found] == [Owner("metamask", "MetaMask")]
    assert all(os.sep not in path or path == path.lower() for path, _wallet in found)


def test_a_firefox_vault_read_is_pack_less_and_counts_while_trader_shield_is_on():
    """KI-366 / F-004: Firefox storage the map cannot place names no pack; it is the shield's
    as a whole, so it is returned whatever is chosen and today's gate still counts it."""
    path = "~/.mozilla/firefox/ab12.default/storage/default/moz-extension+++0b6f^userContextId=4294967295/idb/x.sqlite"
    [finding] = _detect("read_file", {"path": path})
    assert "pack" not in finding.fields and finding.fields["wallet"] == trader_mode.ANY_EXTENSION_WALLET
    assert detectors.detect("read_file", {"path": path}, trader_mode.build(enabled=True, wallets=())) == [finding]
    as_dict = {"identifier": finding.identifier, "fields": finding.fields}
    assert trader_mode.allows_finding(as_dict, trader_mode.build(enabled=True))
    assert not trader_mode.allows_finding(as_dict, trader_mode.build(enabled=False))


def test_only_chosen_packs_are_returned():
    path = f"/x/Default/Local Extension Settings/{PHANTOM_ID}/a.log"
    assert detectors.detect("read_file", {"path": path}, trader_mode.build(enabled=True, wallets=("metamask",))) == []
    assert [f.fields["pack"] for f in _detect("read_file", {"path": path})] == ["phantom"]


def test_archiving_a_folder_with_several_wallets_names_every_one(monkeypatch):
    """KI-367: the archive check named only the FIRST wallet inside, so with that
    wallet unticked a ticked wallet's vault left inside the archive."""
    profile = browser_extension.normalize_path("~/.config/google-chrome/Default")
    stores = [(profile + "/local extension settings/" + CHROME_ID, "MetaMask"),
              (profile + "/local extension settings/" + "b" * 32, "SecondWallet")]
    monkeypatch.setattr(wallet_files.EXISTING_STORES, "get", lambda: stores)
    monkeypatch.setattr(detectors.EXISTING_STORES, "get",
                        lambda: [(path, Owner(name.lower(), name)) for path, name in stores])
    command = {"command": "tar czf /tmp/x.tgz ~/.config/google-chrome"}

    both = _detect("terminal", command, trader_mode.build(enabled=True, wallets=("metamask", "secondwallet")))
    only_second = detectors.detect("terminal", command, trader_mode.build(enabled=True, wallets=("secondwallet",)))

    assert sorted(f.fields["pack"] for f in both) == ["metamask", "secondwallet"]
    assert [f.fields["pack"] for f in only_second] == ["secondwallet"]


@pytest.mark.parametrize("path", [
    f"{MAC_CHROME}/Default/Local Extension Settings/{PHANTOM_ID}/000003.log",
    f"{MAC_CHROME}/Profile 1/Sync Extension Settings/{PHANTOM_ID}/LOG",
    f"{MAC_CHROME}/Default/IndexedDB/chrome-extension_{PHANTOM_ID}_0.indexeddb.leveldb/000005.ldb",
    f"~/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/{PHANTOM_ID}",
])
def test_any_read_of_phantoms_store_is_found_and_named(path):
    [finding] = _detect("read_file", {"path": path})
    assert finding.fields["pack"] == "phantom" and "Phantom" in finding.title and finding.severity == "critical"


@pytest.mark.parametrize("profile_root", [
    ".config/mozilla/firefox/ab12.default-release",              # Firefox 147+ on Linux (XDG)
    "snap/firefox/common/.mozilla/firefox/ab12.default",          # Ubuntu's default snap Firefox
    ".var/app/org.mozilla.firefox/.mozilla/firefox/ab12.default", # Flatpak Firefox
])
def test_archiving_a_firefox_profile_in_every_linux_layout_is_found(tmp_path, monkeypatch, profile_root):
    """KI-368: Firefox keeps its profile in ~/.config/mozilla (Firefox 147+) or ~/snap/firefox/...
    — every root in browsers.json is scanned."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    store = tmp_path / profile_root / "storage" / "default" / "moz-extension+++4b8e0c78^userContextId=4294967295"
    store.mkdir(parents=True)
    (store / "data.sqlite").write_text("x", encoding="utf-8")
    _reset_stores()
    try:
        archive_root = str(tmp_path / profile_root).rsplit("/", 1)[0]   # the folder holding the profiles
        [finding] = _shell(f"tar czf /tmp/p.tgz {archive_root}")
        assert finding.fields["wallet"] == "any-extension" and "pack" not in finding.fields
    finally:
        _reset_stores()


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
    _reset_stores()
    try:
        profile = str(tmp_path / store_parent).rsplit("/Default/", 1)[0]
        [finding] = _shell(f"tar czf /tmp/p.tgz {profile}")
        assert finding.fields["pack"] == "metamask"
    finally:
        _reset_stores()


# -- built from data: the packs and browsers.json, not WALLETS / _browser_roots (S4a) ------------

def test_a_pack_with_no_chromium_id_matches_no_chromium_path(tmp_path):
    """An empty id alternation would match every extension folder; such a pack gets no pattern."""
    firefox_only = Pack(id="fox-only", name="Fox Only", kind="browser-extension", status="supported", order=1,
                        folder=tmp_path, data={"stores": {"firefox": ["wallet@fox.example"]}})
    matcher = BrowserExtensionMatcher([firefox_only])
    assert matcher.owner(f"/x/Default/Local Extension Settings/{'a' * 32}/a.log") is None
    assert matcher.store_globs("/x", "chromium") == []


def test_planned_and_other_kind_packs_build_no_matcher():
    built = {pack.id for pack in detectors.matcher().packs}
    assert built == {pack.id for pack in trader_mode.wallet_packs()
                     if pack.status == "supported" and pack.kind == browser_extension.KIND} == {"metamask", "phantom"}


@pytest.mark.parametrize("env", [
    {"XDG_CONFIG_HOME": None, "APPDATA": None, "LOCALAPPDATA": None},
    {"XDG_CONFIG_HOME": "/elsewhere/.Config", "APPDATA": "C:/Users/T/AppData/Roaming", "LOCALAPPDATA": "C:/Users/T/AppData/Local"},
])
def test_roots_and_store_globs_equal_todays(monkeypatch, tmp_path, env):
    """Proof step 3a: the 31 roots expand to today's ``_browser_roots()``, and each root's store
    globs are today's ``_store_globs`` for that root's engine (Firefox storage under Firefox
    roots, the Chromium stores under Chromium roots)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for name, value in env.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    roots = detectors.browser_roots()
    expanded = [detectors.expand_template(root.path) for root in roots]
    assert len(roots) == 31 and sorted(expanded) == sorted(wallet_files._browser_roots())
    firefox_glob = "moz-extension+++*"
    for root, folder in zip(roots, expanded):
        today = wallet_files._store_globs(folder)
        engine_part = [g for g in today if g.endswith(firefox_glob) == (root.engine == "firefox")]
        assert detectors.matcher().store_globs(folder, root.engine) == engine_part, root.path


# -- the attack table's vault and Firefox rows, through both detectors ----------------------------

TABLE = json.loads((protection.TRADER_SHIELD_PAGE.parent / "trader-shield-attacks.json").read_text(encoding="utf-8"))
VAULT_ROWS = [row for row in TABLE["attacks"]
              if row["proof"] == "test" and (row["group"] == "vault" or "firefox" in row["id"])]


@pytest.fixture
def attack_home(tmp_path, monkeypatch):
    """The attack table's layout: MetaMask and Phantom (and Phantom's backup copy) in Chrome."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    vault = tmp_path / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / CHROME_ID
    phantom = vault.parent / PHANTOM_ID
    backup = tmp_path / ".config" / "google-chrome" / "Default" / "IndexedDB" / f"chrome-extension_{PHANTOM_ID}_0.indexeddb.leveldb"
    for folder in (vault, phantom, backup):
        folder.mkdir(parents=True)
        (folder / "000003.log").write_text("vault", encoding="utf-8")
    _reset_stores()
    values = {"@VAULTFILE@": str(vault / "000003.log"), "@PHANTOMFILE@": str(phantom / "000003.log"),
              "@VAULT@": "~/.config/google-chrome/Default/Local\\ Extension\\ Settings/" + CHROME_ID,
              "@PHANTOM@": "~/.config/google-chrome/Default/Local\\ Extension\\ Settings/" + PHANTOM_ID}

    def fill(text):
        for marker, real in values.items():
            text = text.replace(marker, real)
        assert "@" not in text.replace("user@", ""), f"unfilled placeholder in {text!r}"
        return text

    yield fill
    _reset_stores()


def test_the_attack_table_has_vault_and_firefox_rows():
    ids = {row["id"] for row in VAULT_ROWS}
    assert {"vault-file-tool", "vault-archive-profile", "vault-firefox", "phantom-backup-copy"} <= ids


@pytest.mark.parametrize("row", VAULT_ROWS, ids=[row["id"] for row in VAULT_ROWS])
def test_every_vault_and_firefox_row_gives_the_same_findings(attack_home, row):
    args = {key: attack_home(value) if isinstance(value, str) else value for key, value in row["args"].items()}
    new = _detect(row["tool"], args)
    if row["outcome"] == "blocked":
        assert new, row["id"]
