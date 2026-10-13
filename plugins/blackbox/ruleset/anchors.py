"""Legacy anchors — what the verified graph held before curator envelopes.

* Proof-era anchors: order-independent per-threat anchor hashes and a combined
  root, used only by :func:`.compiler.verified_identifiers` to accept threats
  published under the earlier proof scheme.
* The legacy asset list (trust-and-threat-lab §03.4, D24): the release file
  ``legacy_assets.txt`` beside this module names the assets confirmed before
  curator manifest v1; :func:`verified_legacy_assets` hands it out only when its
  hash equals the trusted manifest's ``legacy_assets_hash`` pin.

Usage::

    legacy = verified_legacy_assets(manifest.legacy_assets_hash)
    if legacy.uals is not None: ...   # the list may be trusted this refresh
    elif legacy.refused: ...          # SECURITY alarm: keep the last-good tiers
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, Optional

from ..kernel.signing import key_manifest

logger = logging.getLogger(__name__)

#: The shipped legacy asset list: one UAL per line, ``#`` comments and blank lines ignored.
LEGACY_ASSETS_FILE = Path(__file__).with_name("legacy_assets.txt")

# ---------------------------------------------------------------------------
# Legacy proof anchors (read compatibility only)
# ---------------------------------------------------------------------------

#: Detection-relevant fields covered by a threat's anchor hash, in canonical
#: order. Producers and consumers hash the same SPARQL binding values, so
#: tampering with any field the detector consumes breaks the batch root.
ANCHOR_FIELDS = ("identifier", "kind", "severity", "name", "pattern", "toolName", "argShape")


def threat_anchor_hash(fields: dict[str, Any]) -> str:
    """Canonical sha256 over a threat row's detection-relevant fields."""
    lines = [f"{k}={fields.get(k) or ''}" for k in ANCHOR_FIELDS]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def anchor_hashes_from_rows(rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    """Map identifier -> anchor hash from plain-string binding rows.

    A re-published threat can yield several rows per identifier; keeping the
    lexicographically greatest hash makes independent clients converge on
    the same value without coordinating row order.
    """
    out: dict[str, str] = {}
    for row in rows:
        ident = str(row.get("identifier") or "").strip()
        if not ident:
            continue
        h = threat_anchor_hash(row)
        if ident not in out or h > out[ident]:
            out[ident] = h
    return out


def anchor_root(pairs: Iterable[tuple]) -> str:
    """Batch root: sha256 over the sorted ``identifier\\x00hash`` lines."""
    lines = sorted(f"{ident}\x00{h}" for ident, h in pairs)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The legacy asset list (D24)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LegacyAssets:
    """The legacy list as one refresh may use it. ``uals`` — the verified list
    (None: not usable this refresh); ``refused`` — why a pinned list was refused
    ("" when it matched, or when no trusted manifest pins one)."""

    uals: Optional[frozenset[str]] = None
    refused: str = ""


def load_legacy_assets(path: Optional[Path] = None) -> Optional[frozenset[str]]:
    """The UALs in the list file (default :data:`LEGACY_ASSETS_FILE`); None when it cannot be read."""
    try:
        text = (path or LEGACY_ASSETS_FILE).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("blackbox: legacy asset list not readable: %s", exc)
        return None
    return frozenset(line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))


def legacy_list_hash(uals: Iterable[str]) -> str:
    """The list's pin — the same sha256 the manifest signs (:func:`key_manifest.legacy_assets_hash`)."""
    return key_manifest.legacy_assets_hash(uals)


def verified_legacy_assets(pinned_hash: str, path: Optional[Path] = None) -> LegacyAssets:
    """The list file, read now, checked against *pinned_hash* (the trusted
    manifest's ``legacy_assets_hash``; "" = no trusted manifest, nothing to check
    against, so the list is not used and nothing is wrong). A list that is
    missing or whose hash differs is REFUSED — the caller keeps the last-good
    tiers and raises the alarm; it never treats the corpus as unlisted."""
    if not pinned_hash:
        return LegacyAssets()
    uals = load_legacy_assets(path)
    if uals is None:
        return LegacyAssets(refused="the shipped legacy asset list could not be read")
    if legacy_list_hash(uals) != pinned_hash:
        logger.warning("blackbox: SECURITY — the shipped legacy asset list does not match the curator "
                       "manifest's pin; the last-good asset tiers stay in force")
        return LegacyAssets(refused="the shipped legacy asset list does not match the curator manifest's pin")
    return LegacyAssets(uals=uals)
