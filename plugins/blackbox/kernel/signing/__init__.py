"""Signing — the one envelope every signed Blackbox statement uses.

A kernel sub-package (the kernel folder reached its file alarm). The public API
is re-exported here, so callers keep writing ``from ..kernel import signing``
and ``signing.sign(...)`` / ``signing.verify(...)``:

* :mod:`.envelope` — the signed envelope: :func:`sign`, :func:`cosign`,
  :func:`verify` (one signer), :func:`verified_signers` (several),
  :func:`from_text`, :func:`public_key_hex`, :class:`SignedEnvelope`.
* :mod:`.key_manifest` — the curator key manifest (Refine R7a): which keys may
  sign for an environment, the threshold, the pinned promotion author, the
  legacy-corpus pin. Imported as ``signing.key_manifest``.
* :mod:`.statement_order` — curator statement types and which statement about
  a threat is current (per-threat sequence; terminal statements dominate).
"""

from .envelope import (
    ENVELOPE_VERSION,
    MAX_ENVELOPE_CHARS,
    MAX_SIGNATURES,
    Signature,
    SignedEnvelope,
    cosign,
    from_text,
    public_key_hex,
    sign,
    verified_signers,
    verify,
)

from . import key_manifest, statement_order

__all__ = [
    "ENVELOPE_VERSION",
    "MAX_ENVELOPE_CHARS",
    "MAX_SIGNATURES",
    "Signature",
    "SignedEnvelope",
    "cosign",
    "key_manifest",
    "statement_order",
    "from_text",
    "public_key_hex",
    "sign",
    "verified_signers",
    "verify",
]
