"""Whether this machine may share with the community graph — the ONE gate
every send path asks (Refine R13, revised 2026-10-12).

Community sharing is ON BY DEFAULT with an easy opt-out (founder decision
2026-10-12: "stop it from being opt-in, make it on by default"; it was
opt-in, default off). Nothing sent is ever a prompt, command, path or file
(see ``docs/REPORTER_TERMS.md``); the installer and the dashboard tell the
operator that sharing is on and how to turn it off. Turning it off is one
action (`blackbox report --withdraw-consent`, `--disable-sharing`, or the
dashboard toggle) and it actually stops processing: the share gate refuses
on the next call. Turning it back on records a fresh acceptance.

The record is local, owner-readable, atomic (``$BLACKBOX_HOME/sharing_consent.json``)
and is erased with the identity (`--erase-identity`). No record means the
default: sharing allowed. A record with ``withdrawn_at`` means the operator
opted out, whatever terms version it names.

Usage::

    consent.in_force()                      # the gate's question: False only after an opt-out
    consent.record()                        # opt back in (CLI `--consent`)
    consent.for_settings(payload)           # a settings write that turns sharing on opts back in
    consent.withdraw()                      # opt out: stops sharing
    consent.terms_text()                    # the terms shown to the operator
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from ..kernel import constants

logger = logging.getLogger(__name__)

#: The reporter terms the record is bound to (shipped next to the code).
TERMS_PATH = Path(__file__).resolve().parent.parent / "docs" / "REPORTER_TERMS.md"
_RECORD_FILE = "sharing_consent.json"


@dataclass(frozen=True)
class SharingConsentRecord:
    """``terms_hash`` — sha256 of the terms text consented to; ``terms_version``
    — the version line of that text; ``accepted_at`` — UTC time; ``withdrawn_at``
    — UTC time the consent was withdrawn ("" while in force)."""

    terms_hash: str
    terms_version: str
    accepted_at: str
    withdrawn_at: str = ""


def terms_text() -> str:
    """The reporter terms as shipped ("" when the file is missing — then nothing can be consented to)."""
    try:
        return TERMS_PATH.read_text(encoding="utf-8")
    except OSError:
        return ""


def terms_hash(text: Optional[str] = None) -> str:
    return hashlib.sha256((terms_text() if text is None else text).encode("utf-8")).hexdigest()


def terms_version(text: Optional[str] = None) -> str:
    for line in (terms_text() if text is None else text).splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip().split()[0]   # "1.0 (draft …)" → "1.0"
    return "unversioned"


def _record_path() -> Path:
    return constants.blackbox_home() / _RECORD_FILE


def current() -> Optional[SharingConsentRecord]:
    try:
        data = json.loads(_record_path().read_text(encoding="utf-8"))
        return SharingConsentRecord(terms_hash=str(data.get("terms_hash", "")), terms_version=str(data.get("terms_version", "")),
                                    accepted_at=str(data.get("accepted_at", "")), withdrawn_at=str(data.get("withdrawn_at", "")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):   # a non-object JSON reads as no record
        return None


def in_force() -> bool:
    """True unless the operator opted out (a withdrawn record). No record is the
    default — sharing on. An unreadable record file reads as no record."""
    record = current()
    return record is None or not record.withdrawn_at


def why_not() -> str:
    """"" when consent is in force; otherwise ONE plain sentence saying why not —
    never given, withdrawn, or given for an earlier text of the terms (which
    is what every operator sees once after the terms change, Community
    Curation C11). The share gates, `blackbox report --consent` and the
    operator's health list all say it the same way. It never disagrees
    with :func:`in_force`: when that says yes, this says nothing."""
    if in_force():
        return ""
    entry = current()
    day = entry.withdrawn_at[:10] if entry is not None else ""
    return f"community sharing was turned off on {day} (`blackbox report --enable-sharing` or the dashboard toggle turns it back on)"


def changes_section(text: Optional[str] = None) -> str:
    """The terms' "What changed" section ("" when there is none) — shown first to
    an operator who consented to an earlier version."""
    lines = (terms_text() if text is None else text).splitlines()
    start = next((i for i, line in enumerate(lines) if line.lower().startswith("## what changed")), None)
    if start is None:
        return ""
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[start:end]).strip()


def record() -> Optional[SharingConsentRecord]:
    """Record acceptance of the terms as they are now — the opt-back-in after an
    opt-out. Works without the terms file too (the record then names no version):
    turning sharing back on must never depend on it. None when it could not be saved."""
    text = terms_text()
    entry = SharingConsentRecord(terms_hash=terms_hash(text) if text else "", terms_version=terms_version(text) if text else "",
                                 accepted_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    return entry if _save(entry) else None


def for_settings(payload: Mapping[str, Any]) -> bool:
    """The ``sharing_consent`` a settings write passes on: turning sharing ON
    (``report: true`` in *payload*) is the operator's opt-back-in, so a
    standing opt-out is replaced by a fresh acceptance first. The dashboard
    toggle and `blackbox report --enable-sharing` both call this — one rule.

        settings.write_settings(payload, sharing_consent=consent.for_settings(payload))
    """
    if payload.get("report") is True and not in_force():
        record()
    return in_force()


def withdraw() -> bool:
    """Opt out: record the withdrawal (keeping any earlier acceptance as history).
    True when sharing was allowed and the opt-out is now SAVED; False when it was
    already off or the record could not be written (callers must say so: sharing
    would otherwise continue). An opt-out on the default writes its own record."""
    entry = current()
    if entry is not None and entry.withdrawn_at:
        return False
    text = terms_text()
    base = entry or SharingConsentRecord(terms_hash=terms_hash(text) if text else "", terms_version=terms_version(text) if text else "",
                                         accepted_at="")
    return _save(SharingConsentRecord(base.terms_hash, base.terms_version, base.accepted_at,
                                      withdrawn_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat()))


def erase() -> bool:
    """Identity erasure: drop the acceptance history and leave sharing OFF. An
    erased identity must never restart sharing on its own (with no record the
    default is ON), so the history is replaced by a bare opt-out; the operator
    turns sharing back on deliberately. True when a record existed before."""
    existed = _record_path().exists()
    _save(SharingConsentRecord(terms_hash="", terms_version="", accepted_at="",
                               withdrawn_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat()))
    return existed


def _save(entry: SharingConsentRecord) -> bool:
    """Write *entry* atomically (mode 600); True when it is on disk."""
    path = _record_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
        tmp.write_text(json.dumps(entry.__dict__), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True
    except OSError as exc:   # an opt-out that could not be written must be loud: sharing would continue
        logger.warning("blackbox: could not save the community sharing choice (%s)", exc)
        return False
