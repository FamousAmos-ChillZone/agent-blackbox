"""This node's reporter key — the private key that signs its community reports.

One Ed25519 key per Blackbox home, created on first use and kept at
``$BLACKBOX_HOME/reporter_key.pem`` with owner-only permissions (0600). It is
NOT the DKG node's wallet: the wallet pays and is managed by the node; this key
only signs statements (see :mod:`.signing`). Losing it means a new reporter
identity; leaking it lets someone sign as this node, so it never leaves the
machine and is never logged.

Pattern: the key file has exactly one owner — :class:`ReporterKeyStore` — with
one lock; creation is atomic (exclusive temp file, 0600 from the first byte,
fsync, then a hard link that refuses to overwrite), so two processes starting
together end up sharing ONE key and a reader never sees a half-written file.

Usage::

    from ..kernel import reporter_key
    store = reporter_key.ReporterKeyStore()        # default path
    key = store.load_or_create()                   # Ed25519PrivateKey
    print(store.public_key_hex())                  # the signer name
"""

from __future__ import annotations

import os
import secrets
import threading
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from . import constants, signing

KEY_FILE_NAME = "reporter_key.pem"
_KEY_FILE_MODE = 0o600


class ReporterKeyError(RuntimeError):
    """The key file exists but cannot be used (unreadable, not Ed25519)."""


class ReporterKeyStore:
    """Owns this node's reporter key file.

    ``path`` defaults to ``$BLACKBOX_HOME/reporter_key.pem``. The loaded key is
    cached per instance; :meth:`load_or_create` is thread-safe.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (constants.blackbox_home() / KEY_FILE_NAME)
        self._lock = threading.Lock()
        self._key: Optional[Ed25519PrivateKey] = None

    @property
    def path(self) -> Path:
        return self._path

    def load_or_create(self) -> Ed25519PrivateKey:
        """Return the key, creating it on first use. Raises
        :class:`ReporterKeyError` when an existing file is unusable — never
        silently replaces a key (that would change this node's identity)."""
        with self._lock:
            if self._key is None:
                self._key = self._read() if self._path.exists() else self._create()
            return self._key

    def public_key_hex(self) -> str:
        """The signer name of this node's key (creates the key if needed)."""
        return signing.public_key_hex(self.load_or_create())

    def _read(self) -> Ed25519PrivateKey:
        try:
            key = load_pem_private_key(self._path.read_bytes(), password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise ReporterKeyError(f"reporter key at {self._path} is unreadable: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ReporterKeyError(f"reporter key at {self._path} is not an Ed25519 key")
        return key

    def _create(self) -> Ed25519PrivateKey:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        if not self._link_new(pem):
            return self._read()   # another process created the key meanwhile: keep theirs
        return key

    def _link_new(self, pem: bytes) -> bool:
        """Atomically create the key file holding *pem* (0600 from the first
        byte); False when a key file already exists (it is never replaced)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Unique per creator (process AND thread), so concurrent first uses never collide.
        tmp = self._path.with_name(f"{self._path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_FILE_MODE)
        try:
            os.write(fd, pem)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, self._path)   # refuses to overwrite an existing key
        except FileExistsError:
            return False
        finally:
            tmp.unlink(missing_ok=True)
        return True
