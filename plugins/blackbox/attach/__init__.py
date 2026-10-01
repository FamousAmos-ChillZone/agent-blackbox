"""Attach — wire Blackbox protection into every agent on this machine.

Finds Hermes homes and OpenClaw workspaces, copies the plugin in (or points
OpenClaw at the bundled JS bridge), and enables it — idempotent, fail-open per
target. Callers use this surface:

* :func:`attach_all` / :func:`detach_all` — every target at once (CLI, dashboard,
  the periodic auto-attach sweep).
* :func:`attach_hermes` / :func:`detach_hermes`, :func:`attach_openclaw` /
  :func:`detach_openclaw` — one target.
* :func:`discover_hermes_homes`, :func:`discover_openclaw_workspaces`,
  :func:`is_managed_blackbox_chat_profile`, :func:`enabled_list_has`.
* :func:`copy_plugin_tree`, :func:`repo_root` — the copy step and the source
  checkout root (used by the dev sync script and the dashboard).

Internals: :mod:`.plugin_copy` · :mod:`.hermes_homes` · :mod:`.openclaw_discovery`
· :mod:`.openclaw_bridge` · :mod:`.openclaw_json5` · :mod:`.sweep`.

Usage::

    from .. import attach
    report = attach.attach_all(hermes=True, openclaw=True, dry_run=False)
"""

from __future__ import annotations

from .hermes_homes import (
    attach_hermes,
    detach_hermes,
    discover_hermes_homes,
    enabled_list_has,
    is_managed_blackbox_chat_profile,
)
from .openclaw_bridge import attach_openclaw, detach_openclaw
from .openclaw_discovery import discover_openclaw_workspaces
from .plugin_copy import copy_plugin_tree, repo_root
from .sweep import attach_all, detach_all

__all__ = [
    "attach_all",
    "attach_hermes",
    "attach_openclaw",
    "copy_plugin_tree",
    "detach_all",
    "detach_hermes",
    "detach_openclaw",
    "discover_hermes_homes",
    "discover_openclaw_workspaces",
    "enabled_list_has",
    "is_managed_blackbox_chat_profile",
    "repo_root",
]
