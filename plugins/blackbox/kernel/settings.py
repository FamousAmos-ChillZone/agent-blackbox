"""Read/write the user-tunable Blackbox detection policy.

The dashboard settings page (gear icon) is the primary consumer. Settings live
under ``plugins.entries.blackbox.*`` in the hermes ``config.yaml`` — the same
place :mod:`config` reads from — so a change here is picked up by every hook on
the next :func:`config.load_blackbox_config`.

Everything is best-effort and validated: :func:`read_settings` always returns a
complete, defaulted view (even with no config file), and :func:`write_settings`
only ever persists known keys with validated values, preserving every unrelated
config key. A save is all-or-nothing (KI-389): one invalid value and NOTHING is
persisted — a half-applied save once turned wallet protection off while reporting
an error about an unrelated field. Writing prefers the hermes config writer (comment/format-preserving)
and falls back to a plain YAML read-modify-write for standalone installs.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Tuple

from . import constants, crypto_secrets
from . import yaml_files
from .config import DETECTION_CATEGORIES, load_blackbox_config

logger = logging.getLogger(__name__)

_GEAR_KEYS = ("plugins", "entries", "blackbox")
#: Most protected paths a save may list (each is matched on every file-access call).
MAX_PROTECTED_PATHS = 100


def read_settings() -> dict[str, Any]:
    """Return the current settings as a JSON-friendly, fully-defaulted dict."""
    cfg = load_blackbox_config()
    categories = {
        cat: cfg.category_setting(cat) for cat in DETECTION_CATEGORIES
    }
    return {
        "mode": cfg.mode,
        "block_severity": cfg.block_severity,
        "report": cfg.report,
        "report_min_severity": cfg.report_min_severity,
        "discover": cfg.discover,
        "osv_lookup": cfg.osv_lookup,
        "categories": categories,
        "protected_paths": list(cfg.protected_paths),
        "wallet_protection": crypto_secrets.wallet_mode.current().as_json(),   # Web3 wallet protection (trader rules)
        "llm": {
            "enabled": cfg.llm_enabled,
            "provider": cfg.llm_provider,
            "model": cfg.llm_model,
            # Never expose the raw key; report only whether one is set.
            "has_key": bool(cfg.llm_api_key),
        },
        "severity_order": list(constants.SEVERITY_ORDER),
        "category_labels": {
            "injection": "Prompt injection",
            "escalation": "Dangerous commands",
            "dependency": "Vulnerable dependencies",
            "fileaccess": "Sensitive file access",
            "skill": "Suspicious skills",
            "secret": "Secret exposure",
            "ioc": "Malicious indicators",
        },
    }


def _validate(payload: dict[str, Any], *, sharing_consent: bool = False) -> tuple[dict[str, Any], list[str]]:
    """Coerce a settings *payload* into a validated ``blackbox`` config subtree.

    Returns ``(entry_updates, errors)``. Unknown keys are ignored; an invalid value
    is an error (and :func:`write_settings` then persists nothing), so a malformed
    request can never corrupt the config. *sharing_consent* (R13, injected by the caller —
    the kernel never asks a feature): without it ``report: true`` is refused.
    """
    errors: list[str] = []
    updates: dict[str, Any] = {}
    if not isinstance(payload, dict):
        return {}, ["payload must be an object"]

    if "mode" in payload:
        mode = str(payload["mode"]).lower()
        (updates.__setitem__("mode", mode) if mode in ("audit", "block") else errors.append(f"invalid mode: {payload['mode']!r}"))

    for key in ("block_severity", "report_min_severity"):
        if key in payload:
            val = str(payload[key]).lower()
            if val in constants.SEVERITY_RANK:
                updates[key] = val
            else:
                errors.append(f"invalid {key}: {payload[key]!r}")

    for key in ("discover", "osv_lookup", "report"):
        # `report` (KI-005): the community-sharing switch is a real settings
        # key now — validate-then-persist like every other boolean.
        if key in payload:
            if not isinstance(payload[key], bool):
                errors.append(f"{key} must be a boolean")
            elif key == "report" and payload[key] and not sharing_consent:
                errors.append("report: could not record turning community sharing back on — check that the Blackbox home is writable")
            else:
                updates[key] = payload[key]

    if "categories" in payload:
        cats = payload["categories"]
        detection: dict[str, Any] = {}
        if isinstance(cats, dict):
            for cat in DETECTION_CATEGORIES:
                item = cats.get(cat)
                if not isinstance(item, dict):
                    continue
                setting: dict[str, Any] = {}
                if "enabled" in item:
                    if isinstance(item["enabled"], bool):
                        setting["enabled"] = item["enabled"]
                    else:
                        errors.append(f"{cat}.enabled must be a boolean")
                if "min_severity" in item:
                    ms = str(item["min_severity"]).lower()
                    if ms in constants.SEVERITY_RANK:
                        setting["min_severity"] = ms
                    else:
                        errors.append(f"invalid {cat}.min_severity: {item['min_severity']!r}")
                if setting:
                    detection[cat] = setting
        else:
            errors.append("categories must be an object")
        updates["detection"] = detection

    if "protected_paths" in payload:
        raw = payload["protected_paths"]
        if isinstance(raw, list) and len(raw) <= MAX_PROTECTED_PATHS:
            paths: list[str] = []
            for item in raw:
                text = str(item or "").strip()
                if text and text not in paths:
                    paths.append(text)
            updates["protected_paths"] = paths
        else:
            errors.append(f"protected_paths must be a list of up to {MAX_PROTECTED_PATHS} paths")

    if "llm" in payload:
        llm = _validate_llm(payload["llm"], errors)
        if llm:
            updates["llm"] = llm

    return updates, errors


def _validate_llm(raw: Any, errors: list[str]) -> dict[str, Any]:
    """The valid ``llm`` reviewer fields of *raw*; each problem is appended to *errors*.

    The key is stored ONE way (KI-371): ``api_key_env`` (the name of the variable that
    holds it, e.g. ``OPENAI_API_KEY`` from ~/.hermes/.env) or ``api_key`` (a key typed
    in). Saving one clears the other — ``None`` here means "remove it" (see :func:`_apply`).
    """
    llm: dict[str, Any] = {}
    if not isinstance(raw, dict):
        errors.append("llm must be an object")
        return llm
    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            llm["enabled"] = raw["enabled"]
        else:
            errors.append("llm.enabled must be a boolean")
    if "provider" in raw:
        prov = str(raw["provider"]).strip().lower()
        if prov in ("openai", "anthropic", ""):
            llm["provider"] = prov
        else:
            errors.append(f"invalid llm.provider: {raw['provider']!r}")
    if "model" in raw:
        llm["model"] = str(raw["model"]).strip()
    if "api_key" in raw:
        llm["api_key"] = str(raw["api_key"]).strip()
        llm["api_key_env"] = None
    if raw.get("api_key_env"):
        name = str(raw["api_key_env"]).strip()
        if name.isascii() and name.isidentifier():
            llm["api_key_env"] = name
            llm["api_key"] = None
        else:
            errors.append(f"invalid llm.api_key_env: {raw['api_key_env']!r}")
    return llm


def write_settings(payload: dict[str, Any], *, sharing_consent: bool = False) -> dict[str, Any]:
    """Validate *payload* and persist it under ``plugins.entries.blackbox``.

    Returns ``{"ok": bool, "errors": [...], "settings": <new read_settings>}``.
    All-or-nothing: with any error nothing is persisted and ``ok`` is False (the
    dashboard answers 400). Never raises — a write failure is reported in the result.
    """
    updates, errors = _validate(payload, sharing_consent=sharing_consent)
    wallet_updates, wallet_errors = crypto_secrets.wallet_mode.validate(payload)   # Web3 wallet protection
    updates.update(wallet_updates)
    errors.extend(wallet_errors)
    if errors:
        return {"ok": False, "errors": errors, "settings": read_settings()}
    if not updates:
        return {"ok": False, "errors": errors or ["nothing to update"], "settings": read_settings()}

    persisted = _persist(updates)
    if not persisted:
        errors.append("could not persist settings (config not writable)")
    return {"ok": persisted, "errors": errors, "settings": read_settings()}


#: KI-030: settings persistence is read-modify-write; concurrent dashboard
#: saves raced and could silently drop each other's changes. One process-wide
#: lock serializes writers (the dashboard is the only writer, single process).
_persist_lock = threading.Lock()


def _persist(updates: dict[str, Any]) -> bool:
    """Merge *updates* into the blackbox config entry. Prefer hermes' writer.

    Serialized under ``_persist_lock`` so concurrent saves can never lose
    updates (KI-030); both writers below end in atomic tmp+rename inside
    their respective helpers.
    """
    with _persist_lock:
        return _persist_locked(updates)


def _persist_locked(updates: dict[str, Any]) -> bool:
    try:
        from hermes_cli import config as hconfig

        raw = hconfig.read_raw_config()
        if not isinstance(raw, dict):
            raw = {}
        entry = _dig(raw, _GEAR_KEYS)
        _apply(entry, updates)
        hconfig.save_config(raw, strip_defaults=False, preserve_keys={_GEAR_KEYS})
        return True
    except Exception as exc:
        logger.debug("blackbox.settings: hermes config write failed (%s); trying YAML", exc)

    # Standalone fallback: plain YAML read-modify-write of the active home.
    try:
        path = constants.hermes_home() / "config.yaml"
        data = yaml_files.load_yaml(path)
        if not isinstance(data, dict):
            data = {}
        entry = _dig(data, _GEAR_KEYS)
        _apply(entry, updates)
        yaml_files.dump_yaml(path, data)
        return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox.settings: YAML config write failed: %s", exc)
        return False


def _dig(root: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Return the nested dict at *keys*, creating empty dicts along the way."""
    node = root
    for key in keys:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    return node


def _apply(entry: dict[str, Any], updates: dict[str, Any]) -> None:
    """Apply validated *updates* onto the blackbox config *entry* in place.

    ``detection`` and ``llm`` are deep-merged (so setting the model never drops
    the key, and tuning one category never drops another); every other key is a
    straight overwrite.
    """
    for key, value in updates.items():
        if key == "detection" and isinstance(value, dict):
            existing = entry.get("detection")
            if not isinstance(existing, dict):
                existing = {}
                entry["detection"] = existing
            for cat, setting in value.items():
                cur = existing.get(cat)
                if not isinstance(cur, dict):
                    cur = {}
                    existing[cat] = cur
                cur.update(setting)
        elif key == "llm" and isinstance(value, dict):
            existing = entry.get("llm")
            if not isinstance(existing, dict):
                existing = {}
                entry["llm"] = existing
            existing.update(value)
            for cleared in [name for name, setting in value.items() if setting is None]:
                existing.pop(cleared, None)   # KI-371: a replaced key copy is removed, not left behind
        else:
            entry[key] = value
