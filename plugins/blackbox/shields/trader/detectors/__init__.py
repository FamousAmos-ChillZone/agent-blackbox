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

Only the table lives here today; the matchers arrive beside their validators in S4a
(browser-extension) and S4b (the app-folder kinds).

Usage::

    from plugins.blackbox.shields.trader import detectors
    Shield(..., detectors=detectors.DETECTORS)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from ...contract import PackDetector

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
