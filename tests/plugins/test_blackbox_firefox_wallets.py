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
import sys
import threading
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


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need extra rights on Windows")
def test_a_symlinked_prefs_js_in_a_folder_the_call_names_is_not_followed(tmp_path, firefox):
    """A folder named by the call cannot lend itself another file's map: a symlinked prefs.js is
    not read, so its folder is "could not tell" and stays protected, even though the map behind
    the link would call this add-on not a wallet."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _write_prefs(elsewhere, {"formautofill@mozilla.org": METAMASK_UUID})
    profile = tmp_path / "anywhere" / "x.profile"
    profile.mkdir(parents=True)
    os.symlink(elsewhere / "prefs.js", profile / "prefs.js")
    [finding] = detect_wallet_files("read_file", {"path": _store(profile, METAMASK_UUID)})
    assert finding.fields["wallet"] == wallet_mode.ANY_EXTENSION_WALLET


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no named pipes in the file system")
def test_a_named_pipe_as_prefs_js_in_a_folder_the_call_names_never_stalls_the_check(tmp_path, firefox):
    """The check runs in a thread with a join timeout so a regression fails instead of hanging the suite.
    A map that cannot be read is "could not tell", so the folder stays protected."""
    profile = tmp_path / "anywhere" / "x.profile"
    profile.mkdir(parents=True)
    os.mkfifo(profile / "prefs.js")
    outcome = []
    worker = threading.Thread(
        target=lambda: outcome.append(detect_wallet_files("read_file", {"path": _store(profile, METAMASK_UUID)})),
        daemon=True)
    worker.start()
    worker.join(1.0)
    assert not worker.is_alive(), "detect_wallet_files blocked on a prefs.js named by the call"
    [[finding]] = outcome
    assert finding.fields["wallet"] == wallet_mode.ANY_EXTENSION_WALLET


def test_the_map_cache_keeps_at_most_64_profiles(tmp_path, firefox, monkeypatch):
    """Profile folders come from the agent's calls, so the cache is least-recently-used and bounded."""
    profiles = []
    for number in range(firefox_extensions._MAX_PROFILES + 6):
        profile = tmp_path / "profiles" / f"p{number}"
        profile.mkdir(parents=True)
        _write_prefs(profile, {"webextension@metamask.io": METAMASK_UUID})
        profiles.append(profile)
    reads = []
    real_read_map = firefox_extensions._read_map
    monkeypatch.setattr(firefox_extensions, "_read_map", lambda path: reads.append(path) or real_read_map(path))
    maps = firefox_extensions.PREFS_MAPS
    maps.get(str(profiles[0]))
    for profile in profiles[1:]:
        maps.get(str(profile))
        maps.get(str(profiles[0]))      # kept in use, so never the one evicted
    cached = set(maps._cache)
    assert len(cached) == firefox_extensions._MAX_PROFILES == 64
    assert reads.count(str(profiles[0] / "prefs.js")) == 1   # every later get was a cache hit
    assert str(profiles[0] / "prefs.js") in cached
    assert str(profiles[1] / "prefs.js") not in cached
    assert str(profiles[-1] / "prefs.js") in cached
