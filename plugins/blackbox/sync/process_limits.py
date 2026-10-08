"""The DKG node's process limits: the V8 heap cap Blackbox launches it with.

Shared by the installer (through ``scripts/blackbox-dkg-runtime-fingerprint.py``,
which loads this file by path, so it imports nothing from the plugin) and the
plugin's own node restarts. Standard library only.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


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
