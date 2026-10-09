"""The DKG node's process limits: settings it can only get from its environment.

DKG reads the V8 heap cap (``NODE_OPTIONS``), the store queue limit
(``DKG_STORE_QUEUE_LIMIT``) and the graph-list projection switch
(``DKG_LIST_CONTEXT_GRAPHS_PROJECTION``) from its process environment only; no
config.json key exists for them (dkg-storage store-priority-scheduler.js,
dkg-agent cg-resolve.js, 10.0.22). So whoever launches the node must pass them,
or the node runs with Node's ~4 GB default heap and DKG's default queues.

The installer chooses them once and records them with :func:`write_process_limits`
(``blackbox-process-limits.json`` in the node's home); every node restart
Blackbox makes reads them back (:func:`read_process_limits`) and applies them
(:func:`apply_process_limits`), falling back to the installer's own defaults
(:func:`default_process_limits`). This closes the gap Umanitek's PR #21 closed
with live process capture: a restart by ``blackbox sync`` or the dashboard no
longer drops the limits.

Shared with the installer through ``scripts/blackbox-dkg-runtime-fingerprint.py``,
which loads this file by path, so it imports nothing from the plugin. Standard
library only.

Usage::

    limits = read_process_limits(dkg_home) or default_process_limits()
    apply_process_limits(env, limits)      # env: the launch environment, edited in place
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Optional


class ProcessLimitsError(RuntimeError):
    """Raised when a safe process limit cannot be chosen."""


_CGROUP_MEMORY_LIMIT_PATHS = (
    Path("/sys/fs/cgroup/memory.max"),
    Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
)
_UNLIMITED_MEMORY_THRESHOLD = 1 << 50
_V8_HEAP_OPTION_RE = re.compile(
    r"(?:^|\s)--max[-_]old[-_]space[-_]size(?:=|\s)",
    re.IGNORECASE,
)


def read_cgroup_memory_limit() -> int | None:
    """Return the active cgroup memory ceiling, if it is finite."""
    for path in _CGROUP_MEMORY_LIMIT_PATHS:
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            continue
        if raw == "max":
            return None
        if not raw:
            continue
        try:
            limit = int(raw)
        except ValueError:
            continue
        if limit >= _UNLIMITED_MEMORY_THRESHOLD:
            return None
        if limit > 0:
            return limit
    return None


def read_physical_memory() -> int | None:
    """Return physical RAM in bytes using only the standard library."""
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and page_size > 0:
            return pages * page_size
    except (AttributeError, OSError, TypeError, ValueError):
        pass

    if sys.platform == "win32":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.total_physical)
        except (AttributeError, OSError, TypeError, ValueError):
            pass
    return None


def resolve_dkg_heap_mb(default_mb: int = 8192) -> int:
    """Choose a V8 heap cap that fits both the host and its cgroup.

    DKG snapshot recovery retains complete RDF phases in memory.  Node's
    roughly 4 GiB default old-space cap is too small for the Blackbox graph,
    while an unconditional 8 GiB cap is unsafe in a smaller container.  Use at
    most 75% of the effective memory ceiling and never exceed ``default_mb``.
    """
    if default_mb <= 0:
        raise ProcessLimitsError("default DKG heap must be positive")
    limits = [
        value
        for value in (read_cgroup_memory_limit(), read_physical_memory())
        if value and 0 < value < _UNLIMITED_MEMORY_THRESHOLD
    ]
    if not limits:
        return default_mb
    limit_mb = min(limits) // (1024 * 1024)
    sized = int(limit_mb * 0.75)
    if sized <= 0:
        raise ProcessLimitsError("effective memory limit is too small for DKG")
    return min(default_mb, sized)


def merge_node_options(node_options: str, heap_mb: int) -> str:
    """Add a DKG heap cap while preserving explicit Node options."""
    existing = str(node_options or "").strip()
    if _V8_HEAP_OPTION_RE.search(existing):
        return existing
    heap = int(heap_mb)
    if heap <= 0:
        raise ProcessLimitsError("DKG heap must be positive")
    option = f"--max-old-space-size={heap}"
    return f"{existing} {option}".strip()


#: The installer's queue limit for the store (DKG's own default is lower).
DEFAULT_STORE_QUEUE_LIMIT = 512
#: The installer's default heap ceiling, in MB, before host/cgroup sizing.
DEFAULT_HEAP_CEILING_MB = 8192
#: The record of the limits the installer chose, inside the node's home.
PROFILE_NAME = "blackbox-process-limits.json"
_PROFILE_VERSION = 1
_MAX_PROFILE_BYTES = 4096
_MAX_SETTING = 2_147_483_647
_EXPLICIT_HEAP_RE = re.compile(r"--max[-_]old[-_]space[-_]size(?:=|\s+)([0-9]+)", re.IGNORECASE)


@dataclass(frozen=True)
class ProcessLimits:
    """The node's environment-only limits.

    ``heap_mb`` — V8 old-space cap in MB; ``store_queue_limit`` — the store's
    common queue limit; ``list_context_graphs_projection`` — DKG's faster
    graph-list projection. All positive / boolean; build through
    :func:`default_process_limits` or :func:`read_process_limits`.
    """

    heap_mb: int
    store_queue_limit: int
    list_context_graphs_projection: bool


def _bounded_positive(value: object) -> bool:
    return type(value) is int and 0 < value <= _MAX_SETTING


def explicit_heap_mb(node_options: str) -> Optional[int]:
    """The heap cap an operator already set in *node_options*, if any."""
    match = _EXPLICIT_HEAP_RE.search(str(node_options or ""))
    value = int(match.group(1)) if match else None
    return value if value is not None and _bounded_positive(value) else None


def default_process_limits(node_options: str = "") -> ProcessLimits:
    """The installer's limits for this host: an explicit heap in *node_options*
    wins, else 75% of RAM / cgroup capped at 8 GB; queue 512; projection on."""
    heap = explicit_heap_mb(node_options) or resolve_dkg_heap_mb(DEFAULT_HEAP_CEILING_MB)
    return ProcessLimits(heap, DEFAULT_STORE_QUEUE_LIMIT, True)


def write_process_limits(dkg_home: str, limits: ProcessLimits) -> Path:
    """Record *limits* in the node's home (atomic tmp + rename); returns the path."""
    if not (_bounded_positive(limits.heap_mb) and _bounded_positive(limits.store_queue_limit)
            and type(limits.list_context_graphs_projection) is bool):
        raise ProcessLimitsError("process limits must be positive integers and a boolean")
    home = Path(dkg_home).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    path = home / PROFILE_NAME
    descriptor, temporary = tempfile.mkstemp(prefix=PROFILE_NAME + ".tmp-", dir=home)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"version": _PROFILE_VERSION, "limits": asdict(limits)}, handle, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def read_process_limits(dkg_home: str) -> Optional[ProcessLimits]:
    """The recorded limits, or None when absent or not exactly well-formed
    (callers then use :func:`default_process_limits`)."""
    path = Path(dkg_home).expanduser() / PROFILE_NAME
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_PROFILE_BYTES + 1)
        if len(raw) > _MAX_PROFILE_BYTES:
            return None
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    if type(data) is not dict or data.get("version") != _PROFILE_VERSION:
        return None
    limits = data.get("limits")
    if type(limits) is not dict or set(limits) != set(ProcessLimits.__dataclass_fields__):
        return None
    if not (_bounded_positive(limits["heap_mb"]) and _bounded_positive(limits["store_queue_limit"])
            and type(limits["list_context_graphs_projection"]) is bool):
        return None
    return ProcessLimits(**limits)


def apply_process_limits(env: Dict[str, str], limits: ProcessLimits) -> None:
    """Put *limits* into the launch environment *env* (in place). A value the
    environment already carries wins: an explicit heap in ``NODE_OPTIONS``, an
    explicit queue limit or projection switch."""
    env["NODE_OPTIONS"] = merge_node_options(env.get("NODE_OPTIONS", ""), limits.heap_mb)
    env.setdefault("DKG_STORE_QUEUE_LIMIT", str(limits.store_queue_limit))
    env.setdefault("DKG_LIST_CONTEXT_GRAPHS_PROJECTION", "1" if limits.list_context_graphs_projection else "0")
