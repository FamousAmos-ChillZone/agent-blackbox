"""Firefox wallets follow the wallet ticks like every other browser (detection/firefox_extensions.py).

Firefox names an add-on's storage folder by a random UUID; its prefs.js maps add-on id →
UUID (the format below was copied from real Firefox 157 installs on a bench, 2026-10-13).
Before this, every Firefox extension's storage was one blanket "Firefox wallets" entry that
no wallet tick could turn off. Now MetaMask-in-Firefox is MetaMask, Phantom-in-Firefox is
Phantom, other add-ons are not wallets, and a folder the map cannot place stays protected.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from plugins.blackbox.detection import firefox_extensions, wallet_files
from plugins.blackbox.detection.wallet_files import detect_wallet_files
from plugins.blackbox.kernel.crypto_secrets import wallet_mode

METAMASK_UUID = "ef23dd6a-2006-436e-a3a0-6a52d309351c"
PHANTOM_UUID = "343768ad-2ba9-4e3f-b661-cabb0410a556"
OTHER_UUID = "7f1e3b94-1fd0-45b5-ae6b-655d40f368c4"      # formautofill@mozilla.org, not a wallet
UNMAPPED_UUID = "0b6f2c1e-0000-4000-8000-000000000000"


def _write_prefs(profile, mapping):
    """prefs.js as Firefox writes it: the map is a JSON object stored as a JS string."""
    value = json.dumps(json.dumps(mapping, separators=(",", ":")))
    (profile / "prefs.js").write_text(
        '// Mozilla User Preferences\nuser_pref("browser.startup.homepage_override.mstone", "157.0.1");\n'
        f'user_pref("extensions.webextensions.uuids", {value});\n', encoding="utf-8")


@pytest.fixture
def firefox(tmp_path, monkeypatch):
    """A Firefox 147+ profile (~/.config/mozilla) with MetaMask, Phantom and one other add-on."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    profile = tmp_path / ".config" / "mozilla" / "firefox" / "f14sa4r4.default-release"
    for uuid in (METAMASK_UUID, PHANTOM_UUID, OTHER_UUID, UNMAPPED_UUID):
        store = profile / "storage" / "default" / f"moz-extension+++{uuid}^userContextId=4294967295" / "idb"
        store.mkdir(parents=True)
        (store / "data.sqlite").write_text("x", encoding="utf-8")
    _write_prefs(profile, {"formautofill@mozilla.org": OTHER_UUID, "webextension@metamask.io": METAMASK_UUID,
                           "{7c42eea1-b3e4-4be4-a56f-82a5852b12dc}": PHANTOM_UUID})
    firefox_extensions.PREFS_MAPS.reset()
    wallet_files.EXISTING_STORES.reset()
    yield profile
    firefox_extensions.PREFS_MAPS.reset()
    wallet_files.EXISTING_STORES.reset()


def _store(profile, uuid):
    return str(profile / "storage" / "default" / f"moz-extension+++{uuid}^userContextId=4294967295" / "idb" / "data.sqlite")


@pytest.mark.parametrize("uuid, wallet", [(METAMASK_UUID, "metamask"), (PHANTOM_UUID, "phantom")])
def test_a_firefox_wallet_folder_is_named_by_firefox_own_map(firefox, uuid, wallet):
    [finding] = detect_wallet_files("read_file", {"path": _store(firefox, uuid)})
    assert finding.fields["wallet"] == wallet


def test_another_firefox_extension_is_not_a_wallet(firefox):
    assert detect_wallet_files("read_file", {"path": _store(firefox, OTHER_UUID)}) == []


@pytest.mark.parametrize("break_it", ["missing", "garbled", "not-in-map"])
def test_a_folder_the_map_cannot_place_stays_protected(firefox, break_it):
    """Could not tell is never read as "not a wallet" (LES-011): protect for every chosen wallet."""
    uuid = UNMAPPED_UUID
    if break_it == "missing":
        os.remove(firefox / "prefs.js")
        uuid = METAMASK_UUID
    elif break_it == "garbled":
        (firefox / "prefs.js").write_text('user_pref("extensions.webextensions.uuids", "{not json");\n', encoding="utf-8")
        uuid = METAMASK_UUID
    [finding] = detect_wallet_files("read_file", {"path": _store(firefox, uuid)})
    assert finding.fields["wallet"] == wallet_mode.ANY_EXTENSION_WALLET


def test_unticking_a_wallet_turns_off_its_firefox_protection_too(firefox):
    only_phantom = wallet_mode.WalletProtection(enabled=True, wallets=("phantom",))
    findings = detect_wallet_files("terminal", {"command": f"tar czf backup.tgz {firefox}"})
    kept = sorted(f.fields["wallet"] for f in findings
                  if only_phantom.allows_finding({"identifier": f.identifier, "fields": f.fields}))
    assert kept == ["any-extension", "phantom"]   # MetaMask unticked: its Firefox folder is no longer guarded


def test_found_wallets_lists_firefox_under_each_wallet(firefox):
    found = {(w["wallet"], w["browser"]) for w in wallet_files.found_wallets()}
    assert {("MetaMask", "Firefox"), ("Phantom", "Firefox")} <= found
    assert all(w["id"] != "formautofill" for w in wallet_files.found_wallets())


def test_the_map_is_read_again_when_firefox_changes_it(firefox):
    _write_prefs(firefox, {"webextension@metamask.io": OTHER_UUID})   # a reinstall moved MetaMask
    future = time.time() + 5
    os.utime(firefox / "prefs.js", (future, future))
    [finding] = detect_wallet_files("read_file", {"path": _store(firefox, OTHER_UUID)})
    assert finding.fields["wallet"] == "metamask"
