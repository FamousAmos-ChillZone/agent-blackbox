"""``blackbox setup-llm`` — configure the opt-in LLM second-opinion reviewer.

Finds an API key the operator already has (Hermes or OpenClaw config, env
files, environment) and asks before using it; keys are masked on screen.
"""

from __future__ import annotations

import argparse
from typing import Optional

from ...kernel import settings
from .. import reviewer as llm
from ...kernel.config import load_blackbox_config
from .discovery import _LLM_KEY_ENV_VARS, _env_key, _hermes_llm_candidate, _openclaw_llm_candidate

# ---------------------------------------------------------------------------
# setup-llm: interactive picker for the optional LLM reviewer
# ---------------------------------------------------------------------------

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


def _auto_llm_candidate() -> tuple[str, Optional[dict[str, str]]]:
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


def _reuse_found_config() -> Optional[int]:
    """Use a reviewer config found elsewhere (Blackbox, Hermes, OpenClaw).

    Returns the command's exit code when one was found, or None when there is none.
    """
    source, candidate = _auto_llm_candidate()
    if not candidate:
        return None
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
        reused = _reuse_found_config()
        if reused is not None:
            return reused
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
