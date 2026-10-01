"""Audit — the RECORD flow: what Blackbox saw, kept locally and redacted.

Everything here writes to or reads from ``$BLACKBOX_HOME`` (default
``~/.hermes/blackbox/``) on this machine only — size-capped JSONL logs, plus a
private working-memory record in the local node. Callers use this surface:

* Writing: :func:`record`, :func:`record_file_access`, :func:`record_dependency`,
  :func:`write_private_audit_ka`; redaction: :func:`sanitize_text`, :func:`redact`.
* Reading: :func:`read_findings`, :func:`count_findings`, :func:`read_audit`,
  :func:`count_audit`, :func:`read_local_activity`, :func:`read_file_access`,
  :func:`local_frameworks`, :func:`local_active_frameworks`.
* Outbound-report bookkeeping: :func:`record_share_outcome`,
  :func:`read_share_ledger`, :func:`recently_reported`, :func:`mark_reported`,
  :func:`allow_report`.

Usage::

    from .. import audit
    audit.record(event, finding, detail)
"""

from __future__ import annotations

from .activity import count_audit, read_audit, read_local_activity
from .findings import (
    count_findings,
    local_active_frameworks,
    local_frameworks,
    read_file_access,
    read_findings,
    record,
    record_dependency,
    record_file_access,
)
from .private_ka import write_private_audit_ka
from .redaction import redact, sanitize_text
from .share_ledger import (
    allow_report,
    mark_reported,
    read_share_ledger,
    recently_reported,
    record_share_outcome,
)

__all__ = [
    "allow_report",
    "count_audit",
    "count_findings",
    "local_active_frameworks",
    "local_frameworks",
    "mark_reported",
    "read_audit",
    "read_file_access",
    "read_findings",
    "read_local_activity",
    "read_share_ledger",
    "recently_reported",
    "record",
    "record_dependency",
    "record_file_access",
    "record_share_outcome",
    "redact",
    "sanitize_text",
    "write_private_audit_ka",
]
