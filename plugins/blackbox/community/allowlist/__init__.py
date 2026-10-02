"""Allowlist, warninglist and canaries (Refine R9, plan §06).

The look-alike rule is INVERTED from the usual blocklist practice: a report
that names an allowlisted brand byte-for-byte is HELD (weight 0) until a
curator looks, while a name that merely resembles one SUPPORTS the report
and is tagged ``confusable-of:<name>`` — a homograph is impersonation, not
a false positive. The warninglist holds name-level and vulnerability reports
on popular packages only; version-pinned malware reports on them count.
Canaries are curator-private planted identifiers: reporting one is bad
faith by construction, settled by a rejection + strike.

Public surface: :func:`check` → :class:`Verdict` (:class:`AllowlistVerdict`),
:func:`confusable_of`, the tables (:func:`load`, :class:`AllowTables`,
:func:`allowlist_key`) and :class:`CanaryStore`.
"""

from __future__ import annotations

from .canaries import CanaryStore
from .tables import SEED_DOMAINS, SEED_PACKAGES, AllowTables, allowlist_key, load
from .verdicts import CONFUSABLE_DISTANCE, AllowlistVerdict, Verdict, check, confusable_of, edit_distance, skeleton

__all__ = [
    "AllowTables", "AllowlistVerdict", "CONFUSABLE_DISTANCE", "CanaryStore", "SEED_DOMAINS", "SEED_PACKAGES",
    "Verdict", "allowlist_key", "check", "confusable_of", "edit_distance", "load", "skeleton",
]
