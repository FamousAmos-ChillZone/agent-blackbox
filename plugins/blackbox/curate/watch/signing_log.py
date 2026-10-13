"""SigningLog — this node's own record of every signature its keys made.

The reconciler (``watch``) compares what was published under this node's key
with this log: a published statement the log does not hold means the key was
used somewhere else. So the log has exactly ONE writer — the signing choke
point ``CurateContext.sign`` / ``.cosign`` (``curate/context.py``); an AST test
(``test_blackbox_curate_signing_path.py``) keeps every other signing call out
of ``curate/``.

A row records WHAT was signed, never the words around it: the statement kind,
the digest of the signed bytes (``signing.content_id`` — the identity readers
key on), the signing key's public key, whether it was a first signature or a
co-signature, and the time. No payload, prompt or command text is stored.

Append-only JSONL at ``<curate home>/signing_log.jsonl`` (owner-only file
mode), one lock per log object.

Usage::

    log = SigningLog()                         # <curate home>/signing_log.jsonl
    log.record(envelope, key, action="sign")   # the choke point does this
    [row.digest for row in log.rows()]         # what the reconciler reads
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ...kernel import signing
from .. import keys

_LOG_FILE = "signing_log.jsonl"
#: ``action`` values: the first signature on a statement, or one more on it.
ACTIONS = ("sign", "cosign")


@dataclass(frozen=True)
class SigningRow:
    """One signature this node made. ``kind`` — the envelope's statement type;
    ``digest`` — ``signing.content_id`` of the signed bytes; ``key`` — the
    signer's public key (hex, as envelopes name signers); ``action`` — one of
    :data:`ACTIONS`; ``at`` — Unix time of the signature."""

    kind: str
    digest: str
    key: str
    action: str
    at: float


class SigningLog:
    """Append-only log of this node's signatures (see the module doc)."""

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (keys.curate_home() / _LOG_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, envelope: signing.SignedEnvelope, key: Ed25519PrivateKey, *, action: str) -> SigningRow:
        """Append the row for *key* having signed *envelope* and return it."""
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        row = SigningRow(kind=envelope.statement_type, digest=signing.content_id(envelope),
                         key=signing.public_key_hex(key), action=action, at=self._clock())
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
        return row

    def rows(self) -> list[SigningRow]:
        """Every well-formed row, oldest first (a damaged line is skipped)."""
        try:
            lines = self._path.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            return []
        parsed: list[SigningRow] = []
        for line in lines:
            try:
                entry = json.loads(line)
                parsed.append(SigningRow(kind=str(entry["kind"]), digest=str(entry["digest"]), key=str(entry["key"]),
                                         action=str(entry["action"]), at=float(entry["at"])))
            except (ValueError, KeyError, TypeError):
                continue
        return parsed
