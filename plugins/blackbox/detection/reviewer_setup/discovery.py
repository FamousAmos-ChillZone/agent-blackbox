"""Find an LLM reviewer key the operator already has: Hermes config + .env, OpenClaw, the environment.

Each finder returns a candidate ``{"source", "provider", "model", "api_key", "api_key_env"}``
or None. ``api_key_env`` names the environment variable the key was read from ("" when the
key is written into a config file); :func:`reachable_key_env` says whether Blackbox can read
that variable itself at run time, so ``setup-llm`` saves the name instead of a copy (KI-371).
Used by :mod:`.` (``blackbox setup-llm``), which decides whether to use one.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Optional

from ... import attach
from ...kernel import constants, yaml_files
from .. import reviewer as llm

#: Standard env var names each provider's key lives in (mirrors hermes auth).
_LLM_KEY_ENV_VARS = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN"),
}

_PROVIDER_ALIASES = {
    "openai": "openai",
    "openai-api": "openai",
    "openai-responses": "openai",
    "openai-chat": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "anthropic-api": "anthropic",
}

_PROVIDER_KEYS = ("provider", "model_provider", "modelProvider", "llm_provider", "llmProvider")
_MODEL_KEYS = ("model", "default", "default_model", "defaultModel", "llm_model", "llmModel")
_API_KEY_KEYS = ("api_key", "apiKey", "key", "token")
_API_KEY_ENV_KEYS = ("key_env", "keyEnv", "api_key_env", "apiKeyEnv", "env", "env_var", "envVar")


def _env_key(provider: str) -> tuple[str, str]:
    """(key, variable name) from *provider*'s standard key variables in this process, or ("", "")."""
    return _env_key_from(provider)


def _runtime_env() -> dict[str, str]:
    """The variables a Hermes process has at run time: its environment plus ~/.hermes/.env."""
    try:
        from hermes_cli import config as hconfig

        return {**os.environ, **hconfig.load_env()}
    except Exception:   # Hermes not importable (standalone run): the process environment only
        return dict(os.environ)


def reachable_key_env(candidate: dict[str, str]) -> str:
    """*candidate*'s variable name when a Hermes process will find the same key under it, else "".

    A key read from another profile's .env, or written into a config file, is not reachable:
    saving only its name would leave the reviewer without a key.
    """
    name = candidate.get("api_key_env", "")
    return name if name and _runtime_env().get(name, "").strip() == candidate.get("api_key") else ""


def _provider_alias(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    return _PROVIDER_ALIASES.get(raw, "")


def _env_lookup(name: str, env: Optional[dict[str, str]] = None) -> str:
    if not name:
        return ""
    if env and env.get(name):
        return str(env[name]).strip()
    return str(os.environ.get(name, "") or "").strip()


def _env_key_from(provider: str, env: Optional[dict[str, str]] = None) -> tuple[str, str]:
    """(key, variable name): the first of *provider*'s standard key variables that is set."""
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):  # ordered, first wins
        val = _env_lookup(name, env)
        if val:
            return val, name
    return "", ""


def _value_from(mapping: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        val = mapping.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _key_from_mapping(mapping: dict[str, Any], provider: str, env: Optional[dict[str, str]] = None) -> tuple[str, str]:
    """(key, variable name it came from — "" when the key is written in *mapping* itself)."""
    direct = _value_from(mapping, _API_KEY_KEYS)
    if direct:
        return direct, ""
    for key in _API_KEY_ENV_KEYS:
        env_name = mapping.get(key)
        if env_name is not None:
            name = str(env_name).strip()
            found = _env_lookup(name, env)
            if found:
                return found, name
    return _env_key_from(provider, env)


def _iter_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dicts(child)


def _candidate_from_mapping(
    mapping: dict[str, Any],
    source: str,
    env: Optional[dict[str, str]] = None,
) -> Optional[dict[str, str]]:
    provider = _provider_alias(_value_from(mapping, _PROVIDER_KEYS))
    if not provider:
        return None
    api_key, api_key_env = _key_from_mapping(mapping, provider, env)
    if not api_key:
        return None
    model = _value_from(mapping, _MODEL_KEYS) or llm.default_model(provider)
    return {"source": source, "provider": provider, "model": model, "api_key": api_key, "api_key_env": api_key_env}


def _parse_env_value(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except Exception:
        return env
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        line = line.removeprefix("export ")
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            env[key] = _parse_env_value(value)
    return env


def _candidate_from_hermes_config(
    cfg: dict[str, Any],
    env: Optional[dict[str, str]],
    source: str,
) -> Optional[dict[str, str]]:
    if not isinstance(cfg, dict):
        return None
    model_cfg = cfg.get("model") if isinstance(cfg.get("model"), dict) else {}
    candidates = [model_cfg, cfg]
    custom = cfg.get("custom_providers") or cfg.get("providers")
    if isinstance(custom, dict):
        candidates.extend(v for v in custom.values() if isinstance(v, dict))
    for candidate in candidates:
        resolved = _candidate_from_mapping(candidate, source, env)
        if resolved:
            return resolved
    return None


def _hermes_llm_candidate() -> Optional[dict[str, str]]:
    try:
        from hermes_cli import config as hconfig

        cfg = hconfig.load_config()
        env = {**os.environ, **hconfig.load_env()}
    except Exception:
        cfg, env = {}, {}

    current = _candidate_from_hermes_config(cfg, env, "Hermes")
    if current:
        return current

    seen: set[Path] = set()
    for home in attach.discover_hermes_homes():
        try:
            resolved_home = home.expanduser().resolve()
        except Exception:
            continue
        if resolved_home in seen:
            continue
        seen.add(resolved_home)
        home_cfg = yaml_files.load_yaml(resolved_home / "config.yaml")
        home_env = {**os.environ, **_load_env_file(resolved_home / ".env")}
        source = f"Hermes ({resolved_home})"
        candidate = _candidate_from_hermes_config(home_cfg, home_env, source)
        if candidate:
            return candidate
    return None


def _openclaw_llm_candidate() -> Optional[dict[str, str]]:
    for workspace in attach.discover_openclaw_workspaces():
        path = workspace / "openclaw.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            continue
        for mapping in _iter_dicts(data):
            resolved = _candidate_from_mapping(mapping, f"OpenClaw ({workspace})")
            if resolved:
                return resolved
    return None


def stored_llm_entry() -> dict[str, Any]:
    """The ``plugins.entries.blackbox.llm`` mapping as saved in the active Hermes home's config.yaml."""
    data = yaml_files.load_yaml(constants.hermes_home() / "config.yaml")
    for key in ("plugins", "entries", "blackbox", "llm"):
        data = data.get(key) if isinstance(data, dict) else None
    return data if isinstance(data, dict) else {}


def copied_key_env(provider: str, api_key: str) -> str:
    """The standard variable a Hermes process holds *api_key* under, or "" (KI-371 clean-up)."""
    runtime = _runtime_env()
    names = _LLM_KEY_ENV_VARS.get(provider, ())
    return next((name for name in names if api_key and runtime.get(name, "").strip() == api_key), "")
