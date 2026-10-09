"""Signing — the one envelope every signed Blackbox statement uses.

A kernel sub-package (the kernel folder reached its file alarm). The public API
is re-exported here, so callers keep writing ``from ..kernel import signing``
and ``signing.sign(...)`` / ``signing.verify(...)``:

* :mod:`.envelope` — the signed envelope: :func:`sign`, :func:`cosign`,
  :func:`verify` (one signer), :func:`verified_signers` (several),
  :func:`from_text`, :func:`public_key_hex`, :class:`SignedEnvelope`;
  :func:`content_id` (what was signed — the identity readers key on) and
  :func:`canonical_text` / :func:`is_canonical` (the one text a statement is written as).
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
    canonical_text,
    content_id,
    cosign,
    from_text,
    is_canonical,
    public_key_hex,
    sign,
    verified_signers,
    verify,
)

from . import authority, key_manifest, statement_order, trust_anchors

__all__ = [
    "ENVELOPE_VERSION",
    "MAX_ENVELOPE_CHARS",
    "MAX_SIGNATURES",
    "Signature",
    "SignedEnvelope",
    "authority",
    "canonical_text",
    "content_id",
    "cosign",
    "is_canonical",
    "key_manifest",
    "statement_order",
    "trust_anchors",
    "from_text",
    "public_key_hex",
    "sign",
    "verified_signers",
    "verify",
]
