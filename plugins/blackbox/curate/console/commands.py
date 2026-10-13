"""``blackbox curate console`` — run the key console (trust-and-threat-lab C3, §03.2).

The verb registers here, never in ``curate/commands.py``: ``curate/parser.py``
calls :func:`add_console_parser`, and the sub-parser's own ``func`` default
dispatches straight to :func:`cmd_console`.

The console binds to 127.0.0.1 and is reached only through ``tailscale
serve``. Its gates read ``<curate home>/console_settings.json``::

    {"tailscaleLogin": "amos@example.com",
     "magicDnsHost": "curator-a.tail1234.ts.net",
     "loginPassphraseHash": "<from curate.console.session.hash_login_passphrase>"}

Usage::

    blackbox curate console --port 9710
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from .. import keys
from ..context import build_context
from .app import CONSOLE_BIND_HOST, DEFAULT_CONSOLE_PORT, ConsoleSettings, create_console_app
from .routes import ConsoleServices, add_console_routes

SETTINGS_FILE = "console_settings.json"
_PORT_RANGE = range(1024, 65536)


class ConsoleSetupError(RuntimeError):
    """The console cannot start; the message says what to fix."""


def add_console_parser(verbs_: Any) -> None:
    """Register ``console`` on the ``blackbox curate`` verbs."""
    c = verbs_.add_parser("console", help="The key console (root A): join requests, approve/decline, "
                                          "removal, renewal — on 127.0.0.1 behind `tailscale serve`")
    c.add_argument("--port", type=int, default=DEFAULT_CONSOLE_PORT,
                   help=f"the loopback port `tailscale serve` forwards to (default {DEFAULT_CONSOLE_PORT})")
    c.set_defaults(func=cmd_console)


def load_settings(port: int) -> ConsoleSettings:
    """The console's settings from ``<curate home>/console_settings.json`` and *port*."""
    if port not in _PORT_RANGE:
        raise ConsoleSetupError("--port must be between 1024 and 65535")
    path = keys.curate_home() / SETTINGS_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return ConsoleSettings(tailscale_login=str(data["tailscaleLogin"]), magic_dns_host=str(data["magicDnsHost"]),
                               login_passphrase_hash=str(data["loginPassphraseHash"]), port=port)
    except FileNotFoundError:
        raise ConsoleSetupError(f"no {path}: write tailscaleLogin, magicDnsHost and loginPassphraseHash "
                                "(see `curate/console/commands.py`)") from None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ConsoleSetupError(f"{path} is not usable: {exc}") from None


def cmd_console(args: argparse.Namespace) -> int:
    """Serve the console until stopped; 2 when it cannot start."""
    try:
        settings = load_settings(args.port)
    except ConsoleSetupError as exc:
        print(f"Refused: {exc}")
        return 2
    import uvicorn

    app = create_console_app(settings)
    compiled = getattr(args, "compiled_ruleset", None)
    add_console_routes(app, ConsoleServices(context=lambda: build_context(compiled, authority="verified")))
    print(f"key console on http://{CONSOLE_BIND_HOST}:{settings.port} — reach it through "
          f"`tailscale serve` as https://{settings.magic_dns_host}")
    uvicorn.run(app, host=CONSOLE_BIND_HOST, port=settings.port)
    return 0


__all__ = ["SETTINGS_FILE", "ConsoleSetupError", "add_console_parser", "cmd_console", "load_settings"]
