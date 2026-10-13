"""``blackbox setup-llm`` — configure the opt-in LLM second-opinion reviewer.

Finds an API key the operator already has (Hermes or OpenClaw config, env
files, environment) and asks before using it; keys are masked on screen.

KI-371: a key that lives in an environment variable Hermes loads (``~/.hermes/.env``)
is saved as that variable's NAME (``llm.api_key_env``), never copied into config.yaml;
only a key typed or pasted here is stored as itself. Nothing is switched on without
the operator's yes: an unattended run (no terminal) only says how to turn it on.
"""

from __future__ import annotations

import argparse
import os
from typing import Any, Optional

from ...kernel import settings
from .. import reviewer as llm
from ...kernel.config import load_blackbox_config
from .discovery import (_LLM_KEY_ENV_VARS, _env_key, _hermes_llm_candidate, _openclaw_llm_candidate,
                        copied_key_env, reachable_key_env, stored_llm_entry)

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
            "api_key_env": "",
        }
    for resolver in (_hermes_llm_candidate, _openclaw_llm_candidate):
        candidate = resolver()
        if candidate:
            return candidate["source"], candidate
    return "", None


def _resolve_key(source: str, provider: str) -> tuple[str, str]:
    """(key, variable name to save instead of it — "" to save the key itself) from *source*.

    ``new`` reads ``BLACKBOX_LLM_API_KEY`` (how the installer hands over a key: an
    environment variable, never a command-line argument other programs can list).
    """
    if source == "new":
        return os.environ.get("BLACKBOX_LLM_API_KEY", "").strip(), ""
    resolver = {"openclaw": _openclaw_llm_candidate, "hermes": _hermes_llm_candidate}.get(source)
    candidate = resolver() if resolver else None
    if candidate and candidate["provider"] == provider:
        return candidate["api_key"], reachable_key_env(candidate)
    return _env_key(provider)


def _llm_payload(provider: str, model: str, api_key: str, api_key_env: str) -> dict[str, Any]:
    """The settings to save: the variable's name when there is one (no copy), else the key."""
    key = {"api_key_env": api_key_env} if api_key_env else {"api_key": api_key}
    return {"llm": {"enabled": True, "provider": provider, "model": model, **key}}


def _operator_agrees(candidate: dict[str, str]) -> bool:
    """Ask on the terminal before the reviewer starts sending text to the provider; no terminal = no."""
    where = f"{candidate['provider']} key from {candidate['source']} ({_mask_key(candidate['api_key'])})"
    tty = _tty()
    if tty is None:
        print(f"Found a {where}. The LLM reviewer would send the text your agent reads to "
              f"{candidate['provider']}; it stays off until you turn it on:  blackbox setup-llm")
        return False
    try:
        answer = _ask(f"Use the {where} for the LLM reviewer? It sends the text your agent reads "
                      f"to {candidate['provider']} for a second opinion. [y/N]: ", tty)
    finally:
        tty.close()
    return answer.strip().lower() in ("y", "yes")


def _replace_copied_key(candidate: dict[str, str]) -> None:
    """KI-371 clean-up: a key an earlier setup copied into config.yaml becomes its variable's name."""
    if os.environ.get("BLACKBOX_LLM_API_KEY") or not stored_llm_entry().get("api_key"):
        return
    name = copied_key_env(candidate["provider"], candidate["api_key"])
    if name and settings.write_settings({"llm": {"api_key_env": name}}).get("ok"):
        print(f"The reviewer's key is now read from {name}; the copy in config.yaml was removed.")


def _reuse_found_config() -> Optional[int]:
    """Use a reviewer config found elsewhere (Blackbox, Hermes, OpenClaw).

    Returns the command's exit code when one was found, or None when there is none.
    """
    source, candidate = _auto_llm_candidate()
    if not candidate:
        return None
    if source == "Blackbox":
        _replace_copied_key(candidate)
        print(
            f"LLM reviewer already configured: "
            f"provider={candidate['provider']}  model={candidate['model']}"
        )
        return 0
    if not _operator_agrees(candidate):
        return 2
    result = settings.write_settings(_llm_payload(
        candidate["provider"], candidate["model"], candidate["api_key"], reachable_key_env(candidate)))
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
        api_key, api_key_env = args.api_key or "", ""
        if not api_key:
            if not source:
                ans = _ask(
                    "API key — [1] from Hermes env (default)  [2] from OpenClaw  [3] paste a new key: ",
                    tty,
                )
                source = {"2": "openclaw", "3": "new"}.get(ans, "hermes")
            api_key, api_key_env = _resolve_key(source, provider)
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
        result = settings.write_settings(_llm_payload(provider, model, api_key, api_key_env))
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
