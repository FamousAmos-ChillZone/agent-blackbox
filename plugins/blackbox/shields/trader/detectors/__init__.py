"""Trader Shield's detector table: which pack kinds it serves and how each kind's block is checked.

The pack loader (:mod:`...packs`) hands every ``supported`` manifest to the detector whose
``KINDS`` names its kind; that detector answers the first problem with its kind block as
one sentence, or None. The loader has already checked ``places`` templates, ``pointer``
and ``verified`` itself, so the validators here check only what is theirs:

* ``browser-extension`` (MetaMask, Phantom): ``stores.chromium`` — Chromium extension
  ids, each ``^[a-p]{32}$``; ``stores.firefox`` — addons.mozilla.org add-on ids, each a
  ``{uuid}`` or an ``name@domain`` id; at least one id in total.
* ``desktop-app`` (Exodus, Electrum) and ``cli-key-file`` (the Solana CLI): ``places`` —
  at least one path template where the keys live; ``label`` — what the dashboard calls
  it; an optional ``pointer`` to a settings file naming the key file in use.

Detection (shields S4a): :func:`detect` answers, for one tool call, a finding per
chosen pack whose key store the call reads — or copies or archives inside a folder
handed whole to ``tar``/``zip``/``cp``/``rsync`` (:func:`wallets_inside_folder`, which
needs to know where key stores exist on this machine: :data:`EXISTING_STORES`, a
bounded glob under every ``browsers.json`` root, reused for five minutes). The
browser-extension matcher lives in :mod:`.browser_extension`; the app-folder kinds
join in S4b. Every finding carries ``fields["pack"]`` (the pack id); a Firefox folder
no pack can be tied to carries none and belongs to the shield as a whole.

Usage::

    from plugins.blackbox.shields.trader import detectors
    Shield(..., detectors=detectors.DETECTORS, detect=detectors.detect)
    detectors.detect("terminal", {"command": "tar czf x.tgz ~/.config/google-chrome"}, mode.current())
    # -> [Finding(category="fileaccess", source="secret", fields={"pack": "metamask", ...}), ...]
"""

from __future__ import annotations

import functools
import glob
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from ....detection import SHELL_TOOLS, Finding, command_from_args, file_access_arg, shell_file_args
from ....kernel import threat_ids
from ...contract import BrowserRoot, Pack, PackDetector, ShieldMode
from ...packs import load_browser_roots
from .. import mode as trader_mode
from .browser_extension import BrowserExtensionMatcher, Owner, normalize_path

CHROMIUM_ID = re.compile(r"[a-p]{32}")
FIREFOX_ID = re.compile(r"\{[0-9a-f-]{36}\}|[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{1,64}")
#: The manifest's common fields (the loader's), which no kind block repeats.
_COMMON = frozenset({"id", "name", "kind", "status", "order", "verified", "source", "logo"})


@dataclass(frozen=True)
class KindTable:
    """One row of the detector table: the kinds it serves and its kind-block validator
    (satisfies :class:`~...contract.PackDetector`)."""

    KINDS: tuple[str, ...]
    check: Callable[[Mapping[str, Any]], Optional[str]]

    def validate_pack(self, manifest: Mapping[str, Any]) -> Optional[str]:
        """The first problem with *manifest*'s kind block, or None when it is valid."""
        return self.check(manifest)


def _unknown_fields(manifest: Mapping[str, Any], allowed: frozenset[str]) -> Optional[str]:
    unknown = sorted(set(manifest) - _COMMON - allowed)
    return f"a {manifest.get('kind')} pack has no field {unknown[0]!r}" if unknown else None


def _ids(value: Any, pattern: re.Pattern[str], what: str) -> Optional[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and pattern.fullmatch(item) for item in value):
        return f"stores.{what} must be a list of {what} extension ids"
    return None


def _check_browser_extension(manifest: Mapping[str, Any]) -> Optional[str]:
    stores = manifest.get("stores")
    if not isinstance(stores, dict) or set(stores) - {"chromium", "firefox"}:
        return "stores must be an object with chromium and/or firefox id lists"
    problem = (_unknown_fields(manifest, frozenset({"stores"}))
               or _ids(stores.get("chromium", []), CHROMIUM_ID, "chromium")
               or _ids(stores.get("firefox", []), FIREFOX_ID, "firefox"))
    if problem:
        return problem
    if not stores.get("chromium") and not stores.get("firefox"):
        return "a browser-extension pack names at least one extension id"
    return None


def _check_app_folder(manifest: Mapping[str, Any]) -> Optional[str]:
    problem = _unknown_fields(manifest, frozenset({"places", "pointer", "label"}))
    if problem:
        return problem
    if not manifest.get("places"):
        return "places must name at least one path template"
    if not isinstance(manifest.get("label"), str) or not manifest["label"].strip():
        return "label must say what the dashboard calls this wallet"
    return None


#: Every detector Trader Shield has, as the loader sees it.
DETECTORS: tuple[PackDetector, ...] = (
    KindTable(KINDS=("browser-extension",), check=_check_browser_extension),
    KindTable(KINDS=("desktop-app", "cli-key-file"), check=_check_app_folder),
)


# -- detection ----------------------------------------------------------------

#: The file category these findings carry (a closed name, never a path).
WALLET_CATEGORY = "crypto-wallet"
#: How long the list of key stores found on this machine is reused.
_EXISTING_TTL_SECONDS = 300.0

_matcher_for: tuple[tuple[Pack, ...], BrowserExtensionMatcher] = ((), BrowserExtensionMatcher(()))


def matcher() -> BrowserExtensionMatcher:
    """The browser-extension matcher for the packs the mode holds now (built once, rebuilt
    only when the shield hands the mode its packs again)."""
    global _matcher_for
    packs = trader_mode.wallet_packs()
    if _matcher_for[0] is not packs:
        _matcher_for = (packs, BrowserExtensionMatcher(packs))
    return _matcher_for[1]


@functools.cache
def browser_roots() -> tuple[BrowserRoot, ...]:
    """Every root in Trader's ``browsers.json``, loaded and validated once."""
    from ...trader import TRADER   # here, not at the top: the shield record imports this module before it exists
    return load_browser_roots(TRADER)[0]


def expand_template(template: str) -> str:
    """A path template (``$XDG_CONFIG_HOME/google-chrome*``) as a glob on this machine: its
    root from the environment now (``$XDG_CONFIG_HOME`` → ``~/.config``, ``%APPDATA%`` →
    ``~/AppData/Roaming``, ``%LOCALAPPDATA%`` → ``~/AppData/Local`` when unset)."""
    home = os.path.expanduser("~")
    roots = {"~": home, "$XDG_CONFIG_HOME": os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config")),
             "%APPDATA%": os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming")),
             "%LOCALAPPDATA%": os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))}
    root, *below = template.split("/")
    return os.path.join(roots[root], *below)


class _ExistingStores:
    """The key-store folders present on this machine, found by a bounded glob
    (browser folder → profile → store) and reused for a few minutes. One lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._found: list[tuple[str, Owner]] = []
        self._at = float("-inf")

    def get(self) -> list[tuple[str, Owner]]:
        with self._lock:
            if time.monotonic() - self._at > _EXISTING_TTL_SECONDS:
                self._found = self._scan()
                self._at = time.monotonic()
            return list(self._found)

    def reset(self) -> None:
        with self._lock:
            self._at = float("-inf")

    @staticmethod
    def _scan() -> list[tuple[str, Owner]]:
        stores = matcher()
        found: list[tuple[str, Owner]] = []
        for root in browser_roots():
            for candidate in stores.store_globs(expand_template(root.path), root.engine):
                for match in glob.glob(candidate):
                    owner = stores.owner(match)
                    if owner:
                        found.append((normalize_path(match), owner))
        return found


EXISTING_STORES = _ExistingStores()


def wallets_inside_folder(path: str) -> list[Owner]:
    """Every wallet whose key store sits somewhere inside folder *path* on this machine,
    in the order found, each once (empty when none exists here).

    ALL of them, not the first: the gate keeps only findings for the packs the operator
    chose, so naming one wallet would let a chosen wallet's vault leave inside an
    archive named after an unchosen one (KI-367)."""
    folder = normalize_path(path)
    if not folder:
        return []
    prefix = folder.rstrip("/") + "/"
    wallets: list[Owner] = []
    for store, wallet in EXISTING_STORES.get():
        if (store == folder or store.startswith(prefix) or folder == "/") and wallet not in wallets:
            wallets.append(wallet)
    return wallets


def _finding(tool: str, mode: str, wallet: Owner) -> Finding:
    fields = {"tool_name": tool, "file_category": WALLET_CATEGORY,
              "wallet": wallet.pack or trader_mode.ANY_EXTENSION_WALLET}
    if wallet.pack:
        fields["pack"] = wallet.pack   # absent: a store no pack can be named for, the shield's as a whole
    return Finding(
        identifier=threat_ids.fileaccess_identifier(tool, WALLET_CATEGORY),
        category="fileaccess",
        severity="critical",
        title=f"Read of a crypto wallet's key store ({wallet.wallet})",
        tool_name=tool,
        matched=WALLET_CATEGORY,
        evidence=f"{mode} {WALLET_CATEGORY} ({wallet.wallet})",
        confirmed=False,
        source="secret",   # built-in, local-only, blockable — never shared (it names this machine's wallet)
        fields=fields,
    )


def _all_packs_findings(tool_name: str, args: Any) -> list[Finding]:
    """A finding when this call reads a key store of ANY supported pack, or copies/archives
    a folder that holds some — one per wallet involved. Fail-open (an error returns ``[]``
    so a Blackbox fault never breaks the agent)."""
    try:
        access = file_access_arg(tool_name, args)
        if access:
            wallet = matcher().owner(access["path"])
            return [_finding(access["tool"], access["mode"], wallet)] if wallet else []
        tool = (tool_name or "").strip().lower()
        if tool not in SHELL_TOOLS:
            return []
        mode_by_wallet: dict[Owner, str] = {}   # each wallet once, with how it was first reached
        for arg in shell_file_args(command_from_args(tool_name, args)):
            direct = matcher().owner(arg.path)
            found = [direct] if direct else (wallets_inside_folder(arg.path) if arg.recursive else [])
            for wallet in found:
                mode_by_wallet.setdefault(wallet, "copy" if arg.recursive else "read")
        return [_finding(tool, mode, wallet) for wallet, mode in mode_by_wallet.items()]
    except Exception:  # pragma: no cover - fail open
        return []


def detect(tool_name: str, args: Any, active: ShieldMode) -> list[Finding]:
    """Trader's own findings for this call under *active*: one per CHOSEN pack whose key
    store the call reaches, plus every pack-less one (the gate decides those for the
    shield as a whole)."""
    chosen = set(trader_mode.wallets(active))
    return [finding for finding in _all_packs_findings(tool_name, args)
            if "pack" not in finding.fields or finding.fields["pack"] in chosen]
