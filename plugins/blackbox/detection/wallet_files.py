"""Crypto wallet key stores an agent must never read — starting with MetaMask.

A browser wallet keeps its encrypted vault (the seed and keys, locked by the
user's password) in the browser profile. Copied off the machine, the vault can
be attacked offline with password crackers, so reading it is the first step of
every wallet stealer reviewed on 2026-10-12 (research report "Local crypto
protection rules", misc/research). No agent task needs those files.

What is matched (facts re-checked against the sources named beside them):

* The extension IDs — MetaMask on the Chrome Web Store (also what Brave, Opera,
  Vivaldi and Arc install) and on Edge Add-ons, which issues its own ID.
* All three places a Chromium browser keeps an extension's data, in any
  profile under any browser folder (Chromium ``extensions/common/constants.h``):
  ``Local Extension Settings/<id>``, ``Sync Extension Settings/<id>`` and
  ``IndexedDB/chrome-extension_<id>_0.indexeddb.leveldb|blob`` — MetaMask
  writes a backup copy of its vault there (``metamask-backup``, see
  metamask-extension ``shared/lib/stores/persistence-manager.ts``).
* Firefox extension storage: ``storage/default/moz-extension+++<uuid>^userContextId=4294967295``
  (``ExtensionStorageIDB.sys.mjs``). The UUID is random per install, so every
  extension's storage folder is covered; no agent task reads one.

Two ways in, both covered:

* a path that lies inside a key store (any read, file tool or shell);
* a folder that CONTAINS a key store, handed whole to a copy or archive command
  (``tar czf x.tgz ~/Library/Application\\ Support/Google/Chrome``). This needs
  to know where key stores exist on this machine, so it looks once under the
  usual browser folders (cached for :data:`_EXISTING_TTL_SECONDS`); a machine
  without MetaMask never trips it.

Pattern: Specification — :class:`WalletStore` is data (name + IDs); one matcher
serves every wallet added later.

Usage::

    detect_wallet_files("terminal", {"command": "cat .../Local Extension Settings/<id>/000003.log"})
    # -> [Finding(category="fileaccess", source="secret", severity="critical", ...)]
"""

from __future__ import annotations

import glob
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..kernel import threat_ids
from ..kernel.crypto_secrets import wallet_mode
from . import action_parsing, shell_files, shell_shapes
from .finding import Finding


@dataclass(frozen=True)
class WalletStore:
    """A wallet whose key store lives in browser extension storage.

    ``chromium_ids`` — every store ID it is published under (verified against
    the store listing on the date in the module doc). Add a wallet by adding a
    row to :data:`WALLETS`; nothing else changes.
    """

    name: str
    chromium_ids: Tuple[str, ...]


WALLETS: Tuple[WalletStore, ...] = (
    WalletStore("MetaMask", (
        "nkbihfbeogaeaoehlefnkodbefgpgknn",   # Chrome Web Store (verified 2026-10-12)
        "ejbalbakoplchlghecdalmeeeajnimhm",   # Edge Add-ons (verified 2026-10-12)
    )),
)

#: The file category these findings carry (a closed name, never a path).
WALLET_CATEGORY = "crypto-wallet"
#: Shown for Firefox extension storage, which no folder name ties to one wallet.
FIREFOX_EXTENSION = "a Firefox extension"
#: How long the list of key stores found on this machine is reused.
_EXISTING_TTL_SECONDS = 300.0
_FIREFOX_STORAGE = r"storage/default/moz-extension\+\+\+[^/]*\^usercontextid=4294967295"


def _store_pattern(store: WalletStore) -> "re.Pattern[str]":
    ids = "|".join(re.escape(store_id) for store_id in store.chromium_ids)
    return re.compile(
        rf"(?:^|/)(?:(?:local|sync) extension settings/(?:{ids})"
        rf"|indexeddb/chrome-extension_(?:{ids})_0\.indexeddb\.(?:leveldb|blob))(?:/|$)"
    )


_PATTERNS = tuple((store.name, _store_pattern(store)) for store in WALLETS)
_FIREFOX_PATTERN = re.compile(rf"(?:^|/){_FIREFOX_STORAGE}(?:/|$)")


def normalize_path(path: str) -> str:
    """*path* with ``~``, ``$HOME`` and Windows ``%VARS%`` expanded, ``\\`` made
    ``/``, ``.``/``..`` resolved and lower-cased (macOS and Windows file names
    ignore case), so one pattern serves every OS."""
    text = str(path or "").strip()
    text = re.sub(r"%([A-Za-z_]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), text)
    text = os.path.expanduser(os.path.expandvars(text)).replace("\\", "/")
    return os.path.normpath(text).replace("\\", "/").lower() if text else ""


def wallet_in_path(path: str) -> Optional[str]:
    """The wallet whose key store *path* lies inside, or ``None``."""
    normalized = normalize_path(path)
    if not normalized:
        return None
    for name, pattern in _PATTERNS:
        if pattern.search(normalized):
            return name
    if _FIREFOX_PATTERN.search(normalized):
        return FIREFOX_EXTENSION
    return None


# -- key stores that exist on this machine (for whole-folder copies) ---------

def _browser_roots() -> List[str]:
    """Where browsers keep their data on this OS (Chromium ``user_data_dir.md``,
    Mozilla's profile docs). Globs; missing folders simply match nothing."""
    home = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    support = os.path.join(home, "Library", "Application Support")
    config = os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config"))
    return [
        os.path.join(support, "Google", "Chrome*"), os.path.join(support, "Chromium"),
        os.path.join(support, "BraveSoftware", "Brave-Browser*"), os.path.join(support, "Microsoft Edge*"),
        os.path.join(support, "Vivaldi"), os.path.join(support, "Arc", "User Data"),
        os.path.join(support, "com.operasoftware.Opera*"), os.path.join(support, "Firefox", "Profiles", "*"),
        os.path.join(config, "google-chrome*"), os.path.join(config, "chromium"),
        os.path.join(config, "BraveSoftware", "Brave-Browser*"), os.path.join(config, "microsoft-edge*"),
        os.path.join(config, "vivaldi"), os.path.join(config, "opera"),
        os.path.join(home, ".mozilla", "firefox", "*"),
        os.path.join(local, "Google", "Chrome*", "User Data"), os.path.join(local, "Chromium", "User Data"),
        os.path.join(local, "BraveSoftware", "Brave-Browser*", "User Data"),
        os.path.join(local, "Microsoft", "Edge*", "User Data"), os.path.join(local, "Vivaldi", "User Data"),
        os.path.join(roaming, "Opera Software", "Opera*"), os.path.join(roaming, "Mozilla", "Firefox", "Profiles", "*"),
    ]


class _ExistingStores:
    """The key-store folders present on this machine, found by a bounded glob
    (browser folder → profile → store) and reused for a few minutes. One lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._found: List[Tuple[str, str]] = []
        self._at = float("-inf")

    def get(self) -> List[Tuple[str, str]]:
        with self._lock:
            if time.monotonic() - self._at > _EXISTING_TTL_SECONDS:
                self._found = self._scan()
                self._at = time.monotonic()
            return list(self._found)

    def reset(self) -> None:
        with self._lock:
            self._at = float("-inf")

    @staticmethod
    def _scan() -> List[Tuple[str, str]]:
        found: List[Tuple[str, str]] = []
        for root in _browser_roots():
            for candidate in _store_globs(root):
                for match in glob.glob(candidate):
                    wallet = wallet_in_path(match)
                    if wallet:
                        found.append((normalize_path(match), wallet))
        return found


def _store_globs(root: str) -> List[str]:
    """The exact key-store folder globs under one browser folder — never a deep
    walk (a profile holds thousands of cache files)."""
    out = [os.path.join(root, "storage", "default", "moz-extension+++*")]   # a Firefox profile
    for store in WALLETS:
        for store_id in store.chromium_ids:
            for profile in (os.path.join(root, "*"), root):              # Opera keeps no profile folder
                out.append(os.path.join(profile, "Local Extension Settings", store_id))
                out.append(os.path.join(profile, "Sync Extension Settings", store_id))
                out.append(os.path.join(profile, "IndexedDB", f"chrome-extension_{store_id}_0.indexeddb.*"))
    return out


EXISTING_STORES = _ExistingStores()


#: Browser names recognised in a key-store path (first match wins), for the dashboard.
_BROWSERS = (("brave", "Brave"), ("edge", "Edge"), ("vivaldi", "Vivaldi"), ("opera", "Opera"), ("arc", "Arc"),
             ("chromium", "Chromium"), ("chrome", "Chrome"), ("firefox", "Firefox"), ("mozilla", "Firefox"))
#: Which storage area a key-store folder is (Chromium constants / Firefox storage), in plain words.
_AREAS = (("Local Extension Settings", "vault"), ("Sync Extension Settings", "synced copy"),
          ("IndexedDB", "backup copy"), ("moz-extension", "extension storage"))


def found_wallets() -> List[dict]:
    """The wallets whose key stores exist on this machine, for the dashboard:
    ``[{wallet, browser, profile, areas: [...]}]``. Built from the folder NAMES
    the archive check already found (:data:`EXISTING_STORES`) — no file is opened,
    nothing is read inside a store."""
    grouped: dict = {}
    for path, wallet in EXISTING_STORES.get():
        low = path.lower()
        browser = next((label for key, label in _BROWSERS if key in low), "Browser")
        area = next((label for key, label in _AREAS if key.lower() in low), "storage")
        parts = path.split("/")
        anchor = next((i for i, part in enumerate(parts) if part in ("local extension settings", "sync extension settings",
                                                                    "indexeddb", "storage")), len(parts))   # paths are lower-cased
        profile = parts[anchor - 1] if anchor > 0 else ""
        entry = grouped.setdefault((wallet, browser, profile), {"wallet": wallet, "browser": browser,
                                                                 "profile": profile, "areas": []})
        if area not in entry["areas"]:
            entry["areas"].append(area)
    return list(grouped.values())


def wallets_inside_folder(path: str) -> List[str]:
    """Every wallet whose key store sits somewhere inside folder *path* on this
    machine, in the order found, each once (empty when none exists here).

    ALL of them, not the first: the Trader Shield gate keeps only findings for
    the wallets the operator chose, so naming one wallet would let a chosen
    wallet's vault leave inside an archive named after an unchosen one (KI-367)."""
    folder = normalize_path(path)
    if not folder:
        return []
    prefix = folder.rstrip("/") + "/"
    wallets: List[str] = []
    for store, wallet in EXISTING_STORES.get():
        if (store == folder or store.startswith(prefix) or folder == "/") and wallet not in wallets:
            wallets.append(wallet)
    return wallets


# -- the detector -------------------------------------------------------------

def _finding(tool: str, mode: str, wallet: str) -> Finding:
    return Finding(
        identifier=threat_ids.fileaccess_identifier(tool, WALLET_CATEGORY),
        category="fileaccess",
        severity="critical",
        title=f"Read of a crypto wallet's key store ({wallet})",
        tool_name=tool,
        matched=WALLET_CATEGORY,
        evidence=f"{mode} {WALLET_CATEGORY} ({wallet})",
        confirmed=False,
        source="secret",   # built-in, local-only, blockable — never shared (it names this machine's wallet)
        fields={"tool_name": tool, "file_category": WALLET_CATEGORY,
                "wallet": wallet_mode.ANY_EXTENSION_WALLET if wallet == FIREFOX_EXTENSION else wallet.lower()},
    )


def detect_wallet_files(tool_name: str, args: Any) -> List[Finding]:
    """A finding when this call reads a wallet key store, or copies/archives a
    folder that holds one — one finding per wallet involved, so the mode gate can
    keep the chosen ones. Fail-open (an error returns ``[]`` so a Blackbox fault
    never breaks the agent)."""
    try:
        access = action_parsing.file_access_arg(tool_name, args)
        if access:
            wallet = wallet_in_path(access["path"])
            return [_finding(access["tool"], access["mode"], wallet)] if wallet else []
        tool = (tool_name or "").strip().lower()
        if tool not in shell_shapes.SHELL_TOOLS:
            return []
        mode_by_wallet: Dict[str, str] = {}   # each wallet once, with how it was first reached
        for arg in shell_files.shell_file_args(shell_shapes.command_from_args(tool_name, args)):
            direct = wallet_in_path(arg.path)
            found = [direct] if direct else (wallets_inside_folder(arg.path) if arg.recursive else [])
            for wallet in found:
                mode_by_wallet.setdefault(wallet, "copy" if arg.recursive else "read")
        return [_finding(tool, mode, wallet) for wallet, mode in mode_by_wallet.items()]
    except Exception:  # pragma: no cover - fail open
        return []
