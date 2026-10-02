"""Signing — the one envelope every signed Blackbox statement uses.

A kernel sub-package (the kernel folder reached its file alarm). The public API
is re-exported here, so callers keep writing ``from ..kernel import signing``
and ``signing.sign(...)`` / ``signing.verify(...)``:

* :mod:`.envelope` — the signed envelope: :func:`sign`, :func:`verify`,
  :func:`from_text`, :func:`public_key_hex`, :class:`SignedEnvelope`.
"""

from .envelope import (
    ENVELOPE_VERSION,
    MAX_ENVELOPE_CHARS,
    SignedEnvelope,
    from_text,
    public_key_hex,
    sign,
    verify,
)

__all__ = [
    "ENVELOPE_VERSION",
    "MAX_ENVELOPE_CHARS",
    "SignedEnvelope",
    "from_text",
    "public_key_hex",
    "sign",
    "verify",
]
