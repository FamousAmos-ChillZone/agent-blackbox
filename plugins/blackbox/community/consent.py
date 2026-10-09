"""The sharing consent record (Refine R13, plan §13 data protection).

Nothing leaves this machine for the community graph until its operator has
read the reporter terms and recorded consent — opt-IN, default OFF, bound to
the CONTENT of the terms (their sha256): when the terms change, the old
consent no longer counts and sharing stops until the operator consents
again. Withdrawal is as easy as granting (`blackbox report --withdraw-consent`)
and it actually stops processing: the share gate refuses on the next call.

The record is local, owner-readable, atomic (``$BLACKBOX_HOME/sharing_consent.json``),
and is erased with the identity (`--erase-identity`).

Usage::

    consent.in_force()                      # the gate's question
    consent.record()                        # after the operator read the terms (CLI)
    consent.withdraw()                      # stops sharing
    consent.terms_text()                    # the terms the operator is asked to read
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
from typing import Optional

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

    def in_force_for(self, current_hash: str) -> bool:
        return not self.withdrawn_at and self.terms_hash == current_hash


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
        return SharingConsentRecord(terms_hash=str(data["terms_hash"]), terms_version=str(data.get("terms_version", "")),
                                    accepted_at=str(data.get("accepted_at", "")), withdrawn_at=str(data.get("withdrawn_at", "")))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def in_force() -> bool:
    """True only with a record bound to the CURRENT terms and not withdrawn."""
    record = current()
    text = terms_text()
    return bool(text) and record is not None and record.in_force_for(terms_hash(text))


def why_not() -> str:
    """"" when consent is in force; otherwise ONE plain sentence saying why not —
    never given, withdrawn, or given for an earlier text of the terms (which
    is what every operator sees once after the terms change, Community
    Curation C11). The share gates, `blackbox report --consent` and the
    operator's health list all say it the same way. It never disagrees
    with :func:`in_force`: when that says yes, this says nothing."""
    if in_force():
        return ""
    text = terms_text()
    if not text:
        return "the reporter terms are missing from this installation, so nothing can be consented to"
    entry = current()
    if entry is None:
        return "no sharing consent is recorded (`blackbox report --consent`)"
    if entry.withdrawn_at:
        return f"sharing consent was withdrawn on {entry.withdrawn_at[:10]} (`blackbox report --consent` to give it again)"
    if entry.terms_hash != terms_hash(text):
        return (f"the reporter terms changed since you consented to version {entry.terms_version} on {entry.accepted_at[:10]} "
                f"(now version {terms_version(text)}); sharing stopped until you read and accept them (`blackbox report --consent`)")
    return ""


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
    """Record consent to the terms as they are now (None when there are no terms to consent to)."""
    text = terms_text()
    if not text:
        return None
    entry = SharingConsentRecord(terms_hash=terms_hash(text), terms_version=terms_version(text),
                                 accepted_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    _save(entry)
    return entry


def withdraw() -> bool:
    """Mark the consent withdrawn (kept as the record that it existed); True when there was one in force."""
    entry = current()
    if entry is None or entry.withdrawn_at:
        return False
    _save(SharingConsentRecord(entry.terms_hash, entry.terms_version, entry.accepted_at,
                               withdrawn_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat()))
    return True


def erase() -> bool:
    """Delete the record outright (identity erasure)."""
    try:
        _record_path().unlink()
        return True
    except FileNotFoundError:
        return False


def _save(entry: SharingConsentRecord) -> None:
    path = _record_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
        tmp.write_text(json.dumps(entry.__dict__), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as exc:   # a consent that could not be written is no consent: the gate stays closed
        logger.warning("blackbox: could not save the sharing consent record (%s)", exc)
