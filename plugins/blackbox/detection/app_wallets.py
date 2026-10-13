"""Wallets that live in an app's own folder — desktop wallets and the Solana command line.

A browser wallet hides in extension storage (:mod:`.wallet_files`); these keep
their keys in a fixed folder or file of their own. Each location below was found
by installing the real software the normal way and looking (bench bb-trader-1,
Ubuntu 24.04, 2026-10-13), or read from the app's own source where a platform
could not be installed:

* **Exodus 26.10.7** (official .deb, hash checked against Exodus's signed list):
  ``~/.config/Exodus/exodus.wallet/`` holds ``seed.seco`` beside
  ``passphrase.json`` — with no password set, that folder alone IS the wallet.
  macOS and Windows use the same Electron app folder under
  ``~/Library/Application Support/Exodus`` and ``%APPDATA%\\Exodus``.
* **Electrum 4.8.2** (official AppImage): wallet files in ``~/.electrum/wallets/``,
  and ``~/.electrum/<network>/wallets/`` for testnet, signet and regtest;
  ``%APPDATA%\\Electrum`` on Windows (``electrum/util.py`` ``user_dir``).
* **Solana CLI 4.3.0** (Anza installer): ``solana-keygen new`` writes
  ``~/.config/solana/id.json``; ``~/.config/solana/cli/config.yml`` names the
  key file in use (``keypair_path``), which may be anywhere — it is read like
  Firefox's extension map (:mod:`.firefox_extensions`): the settings file only,
  never the key.

Pattern: Specification — :class:`AppWallet` rows are data; one matcher serves all.

Usage::

    app_wallet_at(normalize_path("~/.electrum/wallets/default_wallet"))   # -> "Electrum"
    existing_app_wallets()   # -> [("/home/u/.config/exodus/exodus.wallet", "Exodus"), ...]
"""

from __future__ import annotations

import glob
import os
import re
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

@dataclass(frozen=True)
class AppWallet:
    """A wallet kept in an app's own folder.

    ``name`` — the display name (its settings id is in ``wallet_mode.SUPPORTED_WALLETS``);
    ``places`` — where its keys live, as paths starting with ``~``, ``$XDG_CONFIG_HOME``
    or a Windows ``%VAR%``, where ``*`` stands for one folder or file name; everything
    inside a place is protected; ``kind`` — what the dashboard calls it."""

    name: str
    places: tuple[str, ...]
    kind: str


APP_WALLETS: tuple[AppWallet, ...] = (
    AppWallet("Exodus", (
        "$XDG_CONFIG_HOME/Exodus/exodus.wallet",
        "~/Library/Application Support/Exodus/exodus.wallet",
        "%APPDATA%/Exodus/exodus.wallet",
    ), kind="Desktop app"),
    AppWallet("Electrum", (
        "~/.electrum/wallets", "~/.electrum/*/wallets",
        "%APPDATA%/Electrum/wallets", "%APPDATA%/Electrum/*/wallets",
        "%LOCALAPPDATA%/Electrum/wallets", "%LOCALAPPDATA%/Electrum/*/wallets",
    ), kind="Desktop app"),
    AppWallet("Solana CLI", (
        "$XDG_CONFIG_HOME/solana/*.json",
        "~/.config/solana/*.json",
    ), kind="Command line"),
)
#: Display name -> kind, for the dashboard.
KINDS: dict[str, str] = {wallet.name: wallet.kind for wallet in APP_WALLETS}
#: The Solana CLI's own settings file, which names the key file in use.
SOLANA_CONFIG = "$XDG_CONFIG_HOME/solana/cli/config.yml"
_KEYPAIR_PATH = re.compile(r"^keypair_path:\s*['\"]?(?P<path>[^'\"\n]+?)['\"]?\s*$", re.MULTILINE)
_MAX_CONFIG_BYTES = 64 * 1024


def _real(place: str) -> str:
    """*place* with ``~``, ``$XDG_CONFIG_HOME`` (default ``~/.config``) and ``%VARS%``
    expanded and ``/`` separators, case kept (for looking on disk). An unset ``%VAR%``
    stays literal — it still matches a command that names it the same way, and is
    never looked for on disk."""
    config = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    text = place.replace("$XDG_CONFIG_HOME", config)
    text = re.sub(r"%([A-Za-z_]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), text)
    return os.path.normpath(os.path.expanduser(text)).replace("\\", "/")


def _absolute(place: str) -> str:
    """:func:`_real`, lower-cased — how wallet paths are compared (macOS and Windows
    file names ignore case)."""
    return _real(place).lower()


def _place_pattern(place: str) -> re.Pattern[str]:
    parts = [re.escape(part) for part in _absolute(place).split("*")]
    return re.compile("^" + "[^/]+".join(parts) + "(?:/|$)")


class _SolanaKeyFile:
    """The key file the Solana CLI's config names (``keypair_path``), re-read only when
    the config changes. One lock. None when there is no config or it names none."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: tuple[Optional[float], Optional[str]] = (None, None)

    def get(self) -> Optional[str]:
        config_path = _real(SOLANA_CONFIG)
        try:
            mtime = os.path.getmtime(config_path)
        except OSError:
            return None
        with self._lock:
            if self._cache[0] == mtime:
                return self._cache[1]
        path = self._read(config_path)
        with self._lock:
            self._cache = (mtime, path)
        return path

    @staticmethod
    def _read(config_path: str) -> Optional[str]:
        try:
            if os.path.getsize(config_path) > _MAX_CONFIG_BYTES:
                return None
            with open(config_path, encoding="utf-8-sig", errors="replace") as handle:
                match = _KEYPAIR_PATH.search(handle.read())
        except OSError:
            return None
        return _absolute(match.group("path").strip()) if match else None

    def reset(self) -> None:
        with self._lock:
            self._cache = (None, None)


SOLANA_KEY_FILE = _SolanaKeyFile()


def app_wallet_at(normalized: str) -> Optional[str]:
    """The app wallet whose keys the *normalized* path (``wallet_files.normalize_path``)
    lies inside, or None."""
    if not normalized:
        return None
    for wallet in APP_WALLETS:
        if any(_place_pattern(place).search(normalized) for place in wallet.places):
            return wallet.name
    configured = SOLANA_KEY_FILE.get()
    return "Solana CLI" if configured and normalized == configured else None


def existing_app_wallets() -> list[tuple[str, str]]:
    """``[(normalized place, wallet name)]`` for every app-wallet place present on this
    machine (a bounded glob over the fixed places; nothing inside is opened)."""
    found: list[tuple[str, str]] = []
    for wallet in APP_WALLETS:
        for place in wallet.places:
            pattern = _real(place)
            if "%" in pattern:
                continue
            for match in glob.glob(pattern):
                found.append((match.replace("\\", "/").lower(), wallet.name))
    configured = SOLANA_KEY_FILE.get()
    if configured and os.path.exists(configured) and all(configured != place for place, _ in found):
        found.append((configured, "Solana CLI"))
    return found
