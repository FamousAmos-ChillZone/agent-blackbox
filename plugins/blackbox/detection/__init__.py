"""Detection — the CHECK hot path: is this tool call / model request a threat?

Pure matchers over the compiled ruleset plus the two advisory look-asides.
Callers use this package's surface only:

* ``Finding`` and the ``detect_*`` / ``discover_*`` functions (from
  :mod:`.detectors`) — pure, microsecond-scale, no I/O.
* :mod:`.osv` — OSV.dev dependency lookups (3 s timeout, background only).
* :mod:`.reviewer` — the opt-in LLM second opinion (advisory, never blocks).

Usage::

    from ..detection import Finding, detect_all
    from ..detection import osv, reviewer
"""

from __future__ import annotations

from . import osv, reviewer
from .detectors import (
    Finding,
    detect_all,
    detect_custom_fileaccess,
    detect_dependency,
    detect_escalation,
    detect_fileaccess,
    detect_injection,
    detect_ioc,
    detect_secret_exposure,
    detect_skill,
    discover_dependency_candidates,
    discover_injection,
    injection_scan_text,
)

__all__ = [
    "Finding",
    "detect_all",
    "detect_custom_fileaccess",
    "detect_dependency",
    "detect_escalation",
    "detect_fileaccess",
    "detect_injection",
    "detect_ioc",
    "detect_secret_exposure",
    "detect_skill",
    "discover_dependency_candidates",
    "discover_injection",
    "injection_scan_text",
    "osv",
    "reviewer",
]
