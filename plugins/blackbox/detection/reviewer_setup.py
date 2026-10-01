"""``blackbox setup-llm`` — configure the opt-in LLM second-opinion reviewer.

Finds an API key the operator already has (Hermes or OpenClaw config, env
files, environment) and asks before using it; keys are masked on screen.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from .. import attach
from ..kernel import settings
from ..kernel import yaml_files
from . import reviewer as llm
from ..kernel.config import load_blackbox_config

# ---------------------------------------------------------------------------
# setup-llm: interactive picker for the optional LLM reviewer
# ---------------------------------------------------------------------------

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


def _tty():
    """Return an interactive /dev/tty handle, or None (piped / no terminal)."""
    try:
        return open("/dev/tty", "r+", encoding="utf-8")
    except Exception:
        return None


def _ask(prompt: str, tty) -> str:
    """Print *prompt* and read one trimmed line from the tty (or stdin)."""
    if tty is not None:
        tty.write(prompt)
        tty.flush()
        line = tty.readline()
        return line.strip() if line else ""
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _mask_key(key: str) -> str:
    """Show a key as ``sk-a…wxyz`` — enough to recognize, not enough to leak."""
    key = key or ""
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}…{key[-4:]}"


def _env_key(provider: str) -> str:
    """First non-empty value among *provider*'s standard key env vars."""
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):  # ordered, first wins
        val = os.environ.get(name)
        if val and val.strip():
            return val.strip()
    return ""


def _provider_alias(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    return _PROVIDER_ALIASES.get(raw, "")


def _env_lookup(name: str, env: Optional[Dict[str, str]] = None) -> str:
    if not name:
        return ""
    if env and env.get(name):
        return str(env[name]).strip()
    return str(os.environ.get(name, "") or "").strip()


def _env_key_from(provider: str, env: Optional[Dict[str, str]] = None) -> str:
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):
        val = _env_lookup(name, env)
        if val:
            return val
    return ""


def _value_from(mapping: Dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        val = mapping.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _key_from_mapping(mapping: Dict[str, Any], provider: str, env: Optional[Dict[str, str]] = None) -> str:
    direct = _value_from(mapping, _API_KEY_KEYS)
    if direct:
        return direct
    for key in _API_KEY_ENV_KEYS:
        env_name = mapping.get(key)
        if env_name is not None:
            found = _env_lookup(str(env_name).strip(), env)
            if found:
                return found
    return _env_key_from(provider, env)


def _iter_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dicts(child)


def _candidate_from_mapping(
    mapping: Dict[str, Any],
    source: str,
    env: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, str]]:
    provider = _provider_alias(_value_from(mapping, _PROVIDER_KEYS))
    if not provider:
        return None
    api_key = _key_from_mapping(mapping, provider, env)
    if not api_key:
        return None
    model = _value_from(mapping, _MODEL_KEYS) or llm.default_model(provider)
    return {"source": source, "provider": provider, "model": model, "api_key": api_key}


def _parse_env_value(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _load_env_file(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except Exception:
        return env
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            env[key] = _parse_env_value(value)
    return env


def _candidate_from_hermes_config(
    cfg: Dict[str, Any],
    env: Optional[Dict[str, str]],
    source: str,
) -> Optional[Dict[str, str]]:
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


def _hermes_llm_candidate() -> Optional[Dict[str, str]]:
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


def _openclaw_llm_candidate() -> Optional[Dict[str, str]]:
    for workspace in attach.discover_openclaw_workspaces():
        path = workspace / "openclaw.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for mapping in _iter_dicts(data):
            resolved = _candidate_from_mapping(mapping, f"OpenClaw ({workspace})")
            if resolved:
                return resolved
    return None


def _auto_llm_candidate() -> tuple[str, Optional[Dict[str, str]]]:
    cfg = load_blackbox_config()
    if cfg.llm_ready:
        return "Blackbox", {
            "source": "Blackbox",
            "provider": cfg.llm_provider,
            "model": cfg.llm_model,
            "api_key": cfg.llm_api_key,
        }
    for resolver in (_hermes_llm_candidate, _openclaw_llm_candidate):
        candidate = resolver()
        if candidate:
            return candidate["source"], candidate
    return "", None


def _resolve_key(source: str, provider: str) -> str:
    """Resolve an API key for *provider* from the chosen *source*."""
    if source == "new":
        return ""
    if source == "openclaw":
        candidate = _openclaw_llm_candidate()
        if candidate and candidate["provider"] == provider:
            return candidate["api_key"]
    if source == "hermes":
        candidate = _hermes_llm_candidate()
        if candidate and candidate["provider"] == provider:
            return candidate["api_key"]
    return _env_key(provider)


def cmd_setup_llm(args: argparse.Namespace) -> int:
    """Configure the opt-in LLM prompt-injection reviewer.

    Interactive by default (reads /dev/tty); fully scriptable via flags. Writes
    ``plugins.entries.blackbox.llm.*`` through the shared settings writer.
    """
    if args.disable:
        result = settings.write_settings({"llm": {"enabled": False}})
        print("LLM reviewer disabled." if result.get("ok") else f"error: {result.get('errors')}")
        return 0 if result.get("ok") else 1

    explicit = any(
        getattr(args, name, None)
        for name in ("provider", "model", "key_source", "api_key")
    )
    if not explicit and not getattr(args, "configure", False):
        source, candidate = _auto_llm_candidate()
        if candidate:
            if source == "Blackbox":
                print(
                    f"LLM reviewer already configured: "
                    f"provider={candidate['provider']}  model={candidate['model']}"
                )
                return 0
            result = settings.write_settings({
                "llm": {
                    "enabled": True,
                    "provider": candidate["provider"],
                    "model": candidate["model"],
                    "api_key": candidate["api_key"],
                }
            })
            if not result.get("ok"):
                print(f"error: could not save settings: {result.get('errors')}")
                return 1
            print(
                f"LLM reviewer enabled from {source}: "
                f"provider={candidate['provider']}  model={candidate['model']}"
            )
            return 0
        if args.auto:
            print("No reusable Hermes/OpenClaw LLM config found.")
            return 2

    tty = _tty()
    try:
        # --- provider -------------------------------------------------------
        provider = args.provider
        if not provider:
            if tty is None and not args.api_key:
                print("error: setup-llm needs a terminal, or pass --provider/--model/--api-key.")
                return 2
            ans = _ask("AI provider for the reviewer — [1] OpenAI (default)  [2] Anthropic: ", tty)
            provider = "anthropic" if ans in ("2", "anthropic") else "openai"

        # --- key source + resolution ---------------------------------------
        source = args.key_source
        api_key = args.api_key or ""
        if not api_key:
            if not source:
                ans = _ask(
                    "API key — [1] from Hermes env (default)  [2] from OpenClaw  [3] paste a new key: ",
                    tty,
                )
                source = {"2": "openclaw", "3": "new"}.get(ans, "hermes")
            api_key = _resolve_key(source, provider)
            if not api_key:
                env_hint = " / ".join(_LLM_KEY_ENV_VARS.get(provider, ()))
                if source != "new":
                    print(f"  No {provider} key found in the environment ({env_hint}).")
                api_key = _ask_secret("  Paste the API key: ", tty)

        if not api_key:
            print("error: no API key provided — nothing saved.")
            return 2

        # --- model ----------------------------------------------------------
        model = (args.model or "").strip()
        if not model:
            default_model = llm.default_model(provider)
            ans = _ask(f"Model id [{default_model}]: ", tty) if tty is not None else ""
            model = ans or default_model

        # --- persist --------------------------------------------------------
        result = settings.write_settings({
            "llm": {"enabled": True, "provider": provider, "model": model, "api_key": api_key},
        })
        if not result.get("ok"):
            print(f"error: could not save settings: {result.get('errors')}")
            return 1
        print(
            f"\nLLM reviewer enabled: provider={provider}  model={model}  key={_mask_key(api_key)}\n"
            "It gives a second opinion on prompt injection over the observer path (never blocks).\n"
            "Disable anytime with:  hermes blackbox setup-llm --disable"
        )
        return 0
    finally:
        if tty is not None:
            try:
                tty.close()
            except Exception:
                pass


def _ask_secret(prompt: str, tty) -> str:
    """Read a secret without echoing when possible; fall back to a plain read."""
    try:
        import getpass

        return getpass.getpass(prompt).strip()
    except Exception:
        return _ask(prompt, tty)
