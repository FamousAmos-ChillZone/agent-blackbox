"""The managed DKG node's sync profile: which sync settings it should run with.

Holds the settings tables (environment-variable name → value, and → the
node's config.json key), reads what the node has persisted, writes the
profile into config.json, and checks whether a live node runs it. The
process side — starting, restarting, waiting — stays in :mod:`.managed_node`.
"""

from __future__ import annotations

import json
import os
import psutil
from pathlib import Path
from typing import Dict

from ..kernel.config import BlackboxConfig

_DKG_STEADY_SYNC_SETTINGS = {
    "DKG_SYNC_ON_CONNECT_ENABLED": "1",
    "DKG_SYNC_RECONCILER_ENABLED": "1",
    "DKG_DURABLE_SYNC_ENABLED": "1",
    "DKG_SYNC_GLOBAL_MAX_INFLIGHT": "1",
    "DKG_SYNC_GLOBAL_QUEUE_LIMIT": "0",
}

_DKG_CONFIG_SYNC_SETTINGS = {
    "DKG_SYNC_ON_CONNECT_ENABLED": "syncOnConnectEnabled",
    "DKG_SYNC_RECONCILER_ENABLED": "syncReconcilerEnabled",
    "DKG_DURABLE_SYNC_ENABLED": "durableSyncEnabled",
    "DKG_SYNC_GLOBAL_MAX_INFLIGHT": "syncGlobalMaxInflight",
    "DKG_SYNC_GLOBAL_QUEUE_LIMIT": "syncGlobalQueueLimit",
}


def _persisted_dkg_sync_settings(cfg: BlackboxConfig) -> Dict[str, str]:
    """Return the node's persisted sync settings, keyed by DKG env-var name.

    Values come from ``<dkg_home>/config.json`` (normalized to the env string
    form: booleans as ``"1"``/``"0"``, integers as decimal strings). A setting
    absent from the file is omitted, so callers can tell "not persisted" from
    "persisted as X".
    """
    try:
        persisted = json.loads(
            (Path(cfg.dkg_home) / "config.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, TypeError):
        return {}
    settings: Dict[str, str] = {}
    if isinstance(persisted, dict):
        for env_name, config_name in _DKG_CONFIG_SYNC_SETTINGS.items():
            value = persisted.get(config_name)
            if isinstance(value, bool):
                settings[env_name] = "1" if value else "0"
            elif isinstance(value, int):
                settings[env_name] = str(value)
    return settings


def _managed_dkg_sync_mode_matches(
    cfg: BlackboxConfig,
    expected: Dict[str, str],
) -> bool:
    """Return whether the live worker's EFFECTIVE sync settings equal *expected*.

    DKG resolves each sync setting as environment variable, else
    ``config.json``, else its built-in default (dkg-agent
    ``sync/backpressure.js`` ``resolveBooleanSwitch`` /
    ``resolveSyncGlobalBackpressure``). So a worker launched WITHOUT the
    variables — e.g. by a systemd unit running ``dkg start --foreground`` —
    still runs the persisted values. Comparing only the launch environment
    (the pre-2026-09-26 behavior) misread every service-managed node as stale
    and restarted it on every hourly sync (KI-059/KI-065): the source of the
    "hourly self-exit". A variable that IS set still overrides config, so a
    worker launched with a stale bootstrap override is still detected.
    """
    try:
        pid = int(
            (Path(cfg.dkg_home) / "daemon.pid")
            .read_text(encoding="utf-8")
            .strip()
        )
        process_env = psutil.Process(pid).environ()
    except (OSError, TypeError, ValueError, psutil.Error):
        return False
    persisted = _persisted_dkg_sync_settings(cfg)
    for name, value in expected.items():
        effective = process_env.get(name) or persisted.get(name)
        if effective != value:
            return False
    return True


def _set_persisted_dkg_steady_state(cfg: BlackboxConfig) -> bool:
    """Persist resumable native reconciliation and report whether it changed.

    Older Blackbox releases temporarily disabled native reconciliation around a
    foreground sync.  If that process was interrupted, an existing installation
    could remain in bootstrap mode forever.  Every new sync repairs that state
    before doing network work, without touching DKG's durable checkpoints.
    """
    path = Path(cfg.dkg_home) / "config.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    original = json.dumps(data, sort_keys=True)
    data.update(
        {
            "syncOnConnectEnabled": True,
            "syncReconcilerEnabled": True,
            "durableSyncEnabled": True,
            "syncGlobalMaxInflight": 1,
            "syncGlobalQueueLimit": 0,
            "syncSharedMemoryOnConnect": False,
        }
    )
    if original == json.dumps(data, sort_keys=True):
        return False
    tmp = path.with_suffix(f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return True
