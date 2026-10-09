"""YAML config files (Hermes ``config.yaml`` and friends), read and written safely.

:func:`load_yaml` never raises (unreadable -> ``{}``); :func:`dump_yaml` writes
through :func:`atomic_write` (temp file + rename) so a concurrent reader never
sees a torn file. ``yaml`` is None only if PyYAML is somehow absent.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

try:  # PyYAML ships with hermes; degrade gracefully if it is somehow absent.
    import yaml
except Exception:  # pragma: no cover - yaml is a hard dep in practice
    yaml = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# YAML helpers (idempotent, preserve unrelated keys)
# ---------------------------------------------------------------------------


def load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None or not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("blackbox.attach: could not parse %s (%s)", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def atomic_write(path: Path, text: str) -> None:
    """Write *text* via a temp file + rename so a reader never sees a torn file.

    A concurrent auto-attach sweep (or the dashboard reading a config) can race a
    write; ``os.replace`` is atomic on the same filesystem, so readers always see
    either the old or the new complete file, never a half-written one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def dump_yaml(path: Path, data: Dict[str, Any]) -> None:
    atomic_write(path, yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
