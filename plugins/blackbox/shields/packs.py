"""One loader for any shield's pack folders and its ``browsers.json`` (validate, then use).

A pack is a folder holding one ``*.json`` manifest (``wallets/metamask/wallet.json``):
common fields (``id``, ``name``, ``kind``, ``status``, ``order``, ``verified``,
``source``, ``logo``) plus the kind's own block, which the detector serving that kind
validates (each detector declares ``KINDS`` and ``validate_pack``). A pack that fails
any rule loads as ``unavailable`` with its reason, logged at WARNING, and is never
used to build a matcher — so a typo can never silently protect nothing. Loading
never raises: every pack and every browser root is checked on its own.

Pack data has the trust of plugin code, yet the loader still refuses what no honest
pack contains, so a stray edit or a bad copy is never half-used:

* every file is read through :func:`kernel.bounded_files.read_small_text` with a cap
  (manifest 64 KB, ``browsers.json`` 256 KB, ``attacks.json`` / ``page/content.json``
  512 KB, logo 128 KB) and without following a symlink;
* every folder and file is checked with ``lstat`` (a regular file or folder, never a
  symlink — ``copytree`` would copy a symlink's TARGET into every install) and must
  lie inside the shield's own folder;
* a pack id equals its folder name exactly; two folders differing only in case are
  both refused;
* JSON nests at most 8 deep and a duplicate key is refused (the field a human reads
  is the one the code uses).

A **path template** starts at ``~``, ``$XDG_CONFIG_HOME``, ``%APPDATA%`` or
``%LOCALAPPDATA%`` (a closed list), uses ``/``, lets ``*`` match within one segment,
refuses ``**``, ``..``, ``.``, empty segments and absolute paths, and names at least
two segments below its root, the first of them literal — a typo must never protect
the whole home folder.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from ..kernel.bounded_files import read_small_text
from .contract import BrowserRoot, Pack, PackDetector, PackLogo, Shield

logger = logging.getLogger(__name__)

MANIFEST_MAX_BYTES = 64 * 1024
BROWSERS_MAX_BYTES = 256 * 1024
TABLE_MAX_BYTES = 512 * 1024        # attacks.json and page/content.json
LOGO_MAX_BYTES = 128 * 1024
MAX_JSON_DEPTH = 8

PACK_ID = re.compile(r"[a-z0-9-]{2,32}")
POINTER_KEY = re.compile(r"[a-z_]{1,32}")    # matched later as a literal line prefix, never compiled
BROWSER_ID = re.compile(r"[a-z0-9-]{2,32}")
TEMPLATE_ROOTS = ("~", "$XDG_CONFIG_HOME", "%APPDATA%", "%LOCALAPPDATA%")
SENTINEL_IDS = frozenset({"any-extension", "all", "none"})
PACK_STATUSES = ("supported", "planned")
COMMON_FIELDS = frozenset({"id", "name", "kind", "status", "order", "verified", "source", "logo"})
ENGINES = ("chromium", "firefox")
OPERATING_SYSTEMS = ("linux", "macos", "windows")
INSTALLS = ("native", "snap", "flatpak")
PROFILE_LAYOUTS = ("children", "self")
_LOGO_LINT = (re.compile(r"<script", re.IGNORECASE), re.compile(r"<foreignObject", re.IGNORECASE),
              re.compile(r"\son[a-z]+\s*=", re.IGNORECASE), re.compile(r"href\s*=\s*[\"'](?!#)", re.IGNORECASE))


class PackError(ValueError):
    """A pack, root or shield file broke a rule; the message is the reason shown to the operator."""


@dataclass(frozen=True)
class ShieldData:
    """What the loader found for one shield: its packs, its browser roots, and health reasons."""

    packs: tuple[Pack, ...] = ()
    roots: tuple[BrowserRoot, ...] = ()
    health: tuple[str, ...] = ()


# ------------------------------------------------------------------ files


def safe_file(path: Path, inside: Path) -> Path:
    """*path* when it lies inside *inside* and nothing on the way is a symlink; else PackError."""
    try:
        relative = Path(os.path.normpath(path)).relative_to(os.path.normpath(inside))
    except ValueError:
        raise PackError(f"{path.name} is outside the shield's folder") from None
    if ".." in relative.parts:
        raise PackError(f"{path.name} is outside the shield's folder")
    current = Path(os.path.normpath(inside))
    for part in relative.parts:
        current = current / part
        try:
            mode = os.lstat(current).st_mode
        except OSError:
            raise PackError(f"{current.name} is missing") from None
        if stat.S_ISLNK(mode):
            raise PackError(f"{current.name} is a symlink")
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise PackError(f"{current.name} is not a regular file or folder")
    if not path.resolve().is_relative_to(inside.resolve()):
        raise PackError(f"{path.name} is outside the shield's folder")
    return path


def read_text_file(path: Path, *, inside: Path, max_bytes: int) -> str:
    """The text of a shield file, after :func:`safe_file`, read with the size cap *max_bytes*."""
    safe_file(path, inside)
    status = os.lstat(path)
    if not stat.S_ISREG(status.st_mode):
        raise PackError(f"{path.name} is not a regular file")
    if status.st_size > max_bytes:
        raise PackError(f"{path.name} too large (over {max_bytes} bytes)")
    text = read_small_text(str(path), max_bytes, nofollow=True)
    if text is None:
        raise PackError(f"{path.name} could not be read")
    return text


def read_json_file(path: Path, *, inside: Path, max_bytes: int) -> Any:
    """A shield JSON file: the file rules above, at most 8 deep, no duplicate key."""
    text = read_text_file(path, inside=inside, max_bytes=max_bytes)
    try:
        value = json.loads(text, object_pairs_hook=_refuse_duplicate_keys)
    except RecursionError:
        raise PackError(f"{path.name} nests deeper than {MAX_JSON_DEPTH}") from None
    except ValueError as exc:
        raise PackError(f"{path.name} is not valid JSON: {exc}") from None
    if _depth(value) > MAX_JSON_DEPTH:
        raise PackError(f"{path.name} nests deeper than {MAX_JSON_DEPTH}")
    return value


def _refuse_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _depth(value: Any) -> int:
    """How many objects and lists deep *value* nests (a scalar is 0), without recursion."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, level = stack.pop()
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else None
        if children is not None:
            deepest = max(deepest, level)
            stack.extend((child, level + 1) for child in children)
    return deepest


# -------------------------------------------------------------- templates


def check_template(template: Any) -> str:
    """*template* when it is a valid path template (see the module doc); else PackError."""
    if not isinstance(template, str) or not template:
        raise PackError("a path template must be non-empty text")
    if "\\" in template:
        raise PackError(f"path template {template!r} must use / separators")
    root, *below = template.split("/")
    if root not in TEMPLATE_ROOTS:
        raise PackError(f"path template {template!r} must start with one of {', '.join(TEMPLATE_ROOTS)}")
    for segment in below:
        if segment in ("", ".", "..") or "**" in segment:
            raise PackError(f"path template {template!r} has a refused segment {segment!r}")
    if len(below) < 2:
        raise PackError(f"path template {template!r} must name at least two folders below {root}")
    if "*" in below[0]:
        raise PackError(f"path template {template!r} must name its first folder below {root} literally")
    return template


def _check_date(value: Any, what: str) -> str:
    try:
        date.fromisoformat(value)
    except (TypeError, ValueError):
        raise PackError(f"{what} must be a date (YYYY-MM-DD)") from None
    return value


# ------------------------------------------------------------------ packs


def load_packs(shield: Shield) -> tuple[Pack, ...]:
    """Every pack under ``shield.packs``, in display order; failures are ``unavailable``."""
    names = _folder_names(shield.packs)
    reserved = SENTINEL_IDS | {capability.id for capability in shield.capabilities}
    packs = [_load_one(shield, name, reserved) for name in names]
    packs = _refuse_shared(packs, lambda pack: pack.id.lower(), "duplicate id ignoring case", among_all=True)
    packs = _refuse_shared(packs, lambda pack: pack.order, "order is used by another pack", among_all=False)
    return tuple(sorted(packs, key=lambda pack: (pack.status == "unavailable", pack.order, pack.id)))


def _folder_names(packs_folder: Path) -> list[str]:
    """The entries of the packs folder that are folders or symlinks (regular files are ignored)."""
    if not packs_folder.is_dir():
        return []
    return sorted(entry.name for entry in os.scandir(packs_folder)
                  if entry.is_symlink() or entry.is_dir(follow_symlinks=False))


def _load_one(shield: Shield, name: str, reserved: frozenset[str]) -> Pack:
    """The pack in folder *name*, or that folder as an ``unavailable`` pack with the reason."""
    folder = shield.packs / name
    try:
        return _validated_pack(shield, folder, reserved)
    except Exception as exc:   # one bad pack never stops the others (PackError or anything else)
        reason = str(exc) if isinstance(exc, PackError) else f"could not be loaded ({type(exc).__name__})"
        logger.warning("blackbox: %s pack %r unavailable: %s", shield.id, name, reason)
        return Pack(id=name, name=name, kind="", status="unavailable", order=0, folder=folder, reason=reason)


def _validated_pack(shield: Shield, folder: Path, reserved: frozenset[str]) -> Pack:
    safe_file(folder, shield.folder)
    manifests = sorted(path for path in folder.iterdir() if path.suffix == ".json")
    if len(manifests) != 1:
        raise PackError("a pack folder holds exactly one .json manifest")
    manifest = read_json_file(manifests[0], inside=shield.folder, max_bytes=MANIFEST_MAX_BYTES)
    if not isinstance(manifest, dict):
        raise PackError("the manifest must be a JSON object")
    pack_id = _check_id(manifest.get("id"), folder.name, reserved)
    status, kind = manifest.get("status"), manifest.get("kind", "")
    if status not in PACK_STATUSES:
        raise PackError(f"status must be one of {', '.join(PACK_STATUSES)}")
    if type(manifest.get("order")) is not int:
        raise PackError("order must be an integer")
    if not isinstance(manifest.get("name"), str) or not manifest["name"].strip():
        raise PackError("name must be non-empty text")
    if status == "supported":
        _check_supported(manifest, kind, shield.detectors)
    elif set(manifest) - COMMON_FIELDS:
        raise PackError("a planned pack carries the common fields only")
    if "verified" in manifest:
        _check_date(manifest["verified"], "verified")
    logo = _check_logo(manifest.get("logo"), folder)
    return Pack(id=pack_id, name=manifest["name"], kind=str(kind), status=status, order=manifest["order"],
                folder=folder, data={key: value for key, value in manifest.items() if key not in COMMON_FIELDS},
                logo=logo, verified=manifest.get("verified", ""), source=str(manifest.get("source", "")))


def _check_id(pack_id: Any, folder_name: str, reserved: frozenset[str]) -> str:
    if not isinstance(pack_id, str) or not PACK_ID.fullmatch(pack_id):
        raise PackError("id must be 2-32 lower-case letters, digits or hyphens")
    if pack_id != folder_name:
        raise PackError("folder name must be the id")
    if pack_id in reserved:
        raise PackError(f"id {pack_id!r} is reserved")
    return pack_id


def _check_supported(manifest: Mapping[str, Any], kind: Any, detectors: Iterable[PackDetector]) -> None:
    """A supported pack names a served kind, its templates are valid, and its detector accepts it."""
    detector = next((item for item in detectors if kind in item.KINDS), None)
    if detector is None:
        raise PackError(f"no detector serves kind {kind!r}")
    if "verified" not in manifest:
        raise PackError("a supported pack says when it was verified")
    places = manifest.get("places", [])
    if not isinstance(places, list):
        raise PackError("places must be a list of path templates")
    for template in places:
        check_template(template)
    if "pointer" in manifest:
        _check_pointer(manifest["pointer"])
    problem = detector.validate_pack(manifest)
    if problem:
        raise PackError(problem)


def _check_pointer(pointer: Any) -> None:
    if not isinstance(pointer, dict):
        raise PackError("pointer must be an object")
    check_template(pointer.get("config"))
    if not isinstance(pointer.get("key"), str) or not POINTER_KEY.fullmatch(pointer["key"]):
        raise PackError("pointer.key must be 1-32 lower-case letters or underscores")
    max_bytes = pointer.get("max_bytes", MANIFEST_MAX_BYTES)
    if type(max_bytes) is not int or not 0 < max_bytes <= MANIFEST_MAX_BYTES:
        raise PackError(f"pointer.max_bytes must be an integer from 1 to {MANIFEST_MAX_BYTES}")


def _check_logo(logo: Any, folder: Path) -> Optional[PackLogo]:
    """The pack's logo once its file and terms are present, safe and clean; None when it has none."""
    if logo is None:
        return None
    if not isinstance(logo, dict) or not isinstance(logo.get("file"), str) or not isinstance(logo.get("terms"), str):
        raise PackError("a logo names both its file and its terms")
    svg = read_text_file(folder / logo["file"], inside=folder, max_bytes=LOGO_MAX_BYTES)
    read_text_file(folder / logo["terms"], inside=folder, max_bytes=MANIFEST_MAX_BYTES)
    for pattern in _LOGO_LINT:
        if pattern.search(svg):
            raise PackError(f"the logo carries refused markup ({pattern.pattern})")
    return PackLogo(file=logo["file"], terms=logo["terms"], source=str(logo.get("source", "")))


def _refuse_shared(packs: list[Pack], key: Callable[[Pack], object], reason: str, *, among_all: bool) -> list[Pack]:
    """*packs* with every usable pack that shares *key* with another made ``unavailable``.

    *among_all* counts unavailable packs too: ``MetaMask/`` (refused for its name) still
    makes ``metamask/`` a duplicate ignoring case; an order is shared only among usable packs.
    """
    counts: dict[object, int] = {}
    for pack in packs:
        if among_all or pack.status != "unavailable":
            counts[key(pack)] = counts.get(key(pack), 0) + 1
    result = []
    for pack in packs:
        if pack.status != "unavailable" and counts.get(key(pack), 0) > 1:
            logger.warning("blackbox: pack %r unavailable: %s", pack.id, reason)
            pack = Pack(id=pack.id, name=pack.name, kind=pack.kind, status="unavailable", order=pack.order,
                        folder=pack.folder, reason=reason)
        result.append(pack)
    return result


def chosen_but_unavailable(packs: Iterable[Pack], chosen: Iterable[str]) -> tuple[str, ...]:
    """A health line for every chosen pack id that is not supported right now (never dropped)."""
    by_id = {pack.id: pack for pack in packs}
    lines = []
    for pack_id in chosen:
        pack = by_id.get(pack_id)
        if pack is None:
            lines.append(f"{pack_id}: chosen but unavailable — no such pack")
        elif pack.status != "supported":
            lines.append(f"{pack_id}: chosen but unavailable — {pack.reason or pack.status}")
    return tuple(lines)


# ---------------------------------------------------------- browser roots


def load_browser_roots(shield: Shield) -> tuple[tuple[BrowserRoot, ...], tuple[str, ...]]:
    """``(roots, health reasons)`` from the shield's ``browsers.json``; a bad entry is dropped."""
    if shield.browser_roots is None:
        return (), ()
    try:
        entries = read_json_file(shield.browser_roots, inside=shield.folder, max_bytes=BROWSERS_MAX_BYTES)
        if not isinstance(entries, list):
            raise PackError("browsers.json must be a list")
    except PackError as exc:
        logger.warning("blackbox: %s browser roots unavailable: %s", shield.id, exc)
        return (), (f"browser folder rules unavailable — {exc}",)
    roots: list[BrowserRoot] = []
    health: list[str] = []
    for index, entry in enumerate(entries):
        try:
            root = _validated_root(entry)
            if any(seen.path == root.path for seen in roots):
                raise PackError(f"duplicate path {root.path!r}")
            roots.append(root)
        except Exception as exc:   # one bad root never stops the others
            reason = str(exc) if isinstance(exc, PackError) else f"could not be read ({type(exc).__name__})"
            logger.warning("blackbox: %s browser root %d dropped: %s", shield.id, index, reason)
            health.append(f"browser folder rule unavailable — {reason}")
    return tuple(roots), tuple(health)


def _validated_root(entry: Any) -> BrowserRoot:
    if not isinstance(entry, dict):
        raise PackError("a browser root must be an object")
    allowed = {"engine": ENGINES, "os": OPERATING_SYSTEMS, "install": INSTALLS, "profiles": PROFILE_LAYOUTS}
    for key, values in allowed.items():
        if entry.get(key) not in values:
            raise PackError(f"{key} must be one of {', '.join(values)}")
    if not isinstance(entry.get("browser"), str) or not BROWSER_ID.fullmatch(entry["browser"]):
        raise PackError("browser must be 2-32 lower-case letters, digits or hyphens")
    path = check_template(entry.get("path"))
    if entry["engine"] == "firefox" and path.rsplit("/", 1)[-1] != "*":
        raise PackError(f"a firefox root must end in a * profile folder: {path!r}")
    if not isinstance(entry.get("source"), str) or not entry["source"].strip():
        raise PackError("source must say how the root was checked")
    return BrowserRoot(browser=entry["browser"], engine=entry["engine"], os=entry["os"], path=path,
                       profiles=entry["profiles"], install=entry["install"],
                       verified=_check_date(entry.get("verified"), "verified"), source=entry["source"])


def load_shield_data(shield: Shield) -> ShieldData:
    """Everything the loader reads for *shield*, once, at registry import. Never raises."""
    try:
        packs, problems = load_packs(shield), ()
    except Exception as exc:   # the packs folder itself could not be listed
        logger.warning("blackbox: %s packs unavailable: %s", shield.id, exc)
        packs, problems = (), (f"packs unavailable — could not list the folder ({type(exc).__name__})",)
    roots, health = load_browser_roots(shield)
    return ShieldData(packs=packs, roots=roots, health=problems + health)
