"""Dashboard — the local web UI (FastAPI, loopback-only, 127.0.0.1:9700).

* :func:`cmd_dashboard` — the ``blackbox dashboard`` command (starts the server).
* :mod:`.server` — the app and its API routes (FastAPI/uvicorn are the optional
  ``[web]`` extra, imported only when the server starts).
* :mod:`.settings` — validate-then-persist for settings edited in the UI.
"""

from __future__ import annotations

from .command import cmd_dashboard

__all__ = ["cmd_dashboard"]
