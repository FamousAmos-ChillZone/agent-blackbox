"""Dashboard — the local web UI (FastAPI, loopback-only, 127.0.0.1:9700).

* :func:`cmd_dashboard` — the ``blackbox dashboard`` command (starts the server).
* :mod:`.server` — the app and its API routes (FastAPI/uvicorn are the optional
  ``[web]`` extra, imported only when the server starts).
* :mod:`.community_agents` — the community-graph reporters query + grouping
  behind ``/api/agents``' ``community_agents`` list.
"""

from __future__ import annotations

from .command import cmd_dashboard

__all__ = ["cmd_dashboard"]
