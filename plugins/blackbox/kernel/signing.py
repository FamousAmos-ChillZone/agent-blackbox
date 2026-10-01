"""Signed statements — the one envelope every signed Blackbox statement uses.

Why this exists: who wrote a community report must come from a signature,
never from a field the writer fills in (LES-014). The DKG's own authorship
signals are unchecked on some delivery routes (LES-017, KI-102), so each
report carries its author's signature INSIDE the statement, and a reader
believes a report only after checking it.

What is signed: a canonical byte string built from the envelope's
domain-separation fields — statement ``type`` (what kind of statement),
``environment`` (sim / testnet / mainnet), ``graph`` (the context graph it
belongs to) and ``schema_version`` — plus the payload. A signature made for one
type, environment, graph or schema can therefore never be replayed as another.
Community Refine item R7a later extends this same envelope to two signatures
and a key manifest; there is only ever ONE envelope format (KI-171).

Algorithm: Ed25519 (``cryptography``, already a pinned core dependency). The
signer is named by its raw public key (hex); binding that key to an agent
address is the roster's job, not this module's.

Usage::

    from ..kernel import signing
    envelope = signing.sign(private_key, statement_type="blackbox.report",
                            environment="sim", graph=graph_id,
                            payload={"identifier": "ioc:domain:x.example"})
    text = envelope.to_text()                 # store as one literal
    parsed = signing.from_text(text)          # None when malformed
    signer = signing.verify(parsed, statement_type="blackbox.report",
                            environment="sim", graph=graph_id)   # hex key | None
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#: Bumped when the canonical encoding below changes; old signatures then fail.
ENVELOPE_VERSION = 1
#: Domain tag prefixed to every signed message, so these signatures can never
#: be confused with any other Ed25519 use of the same key.
_DOMAIN_TAG = b"blackbox-signed-statement\n"
#: Hard cap on a serialized envelope (it travels as one graph literal, and
#: oversized literals break peers' sync — see kernel.rdf_terms).
MAX_ENVELOPE_CHARS = 4096
_PUBLIC_KEY_HEX_CHARS = 64
_SIGNATURE_HEX_CHARS = 128


@dataclass(frozen=True)
class SignedEnvelope:
    """One signed statement.

    Fields: ``statement_type``, ``environment``, ``graph``,
    ``schema_version`` (the domain separation), ``payload`` (flat
    str→str mapping — the statement itself), ``signer`` (Ed25519 public key,
    64 hex chars) and ``signature`` (128 hex chars). Build with :func:`sign`,
    check with :func:`verify`; never trust ``signer`` before :func:`verify`.
    """

    statement_type: str
    environment: str
    graph: str
    schema_version: int
    payload: Mapping[str, str]
    signer: str
    signature: str

    def to_text(self) -> str:
        """The envelope as compact JSON — the form stored in the graph."""
        return json.dumps(
            {
                "v": ENVELOPE_VERSION,
                "type": self.statement_type,
                "env": self.environment,
                "graph": self.graph,
                "schema": self.schema_version,
                "payload": dict(self.payload),
                "signer": self.signer,
                "sig": self.signature,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _signed_message(statement_type: str, environment: str, graph: str, schema_version: int,
                    payload: Mapping[str, str]) -> bytes:
    """The exact bytes that are signed: domain tag + canonical JSON."""
    body = json.dumps(
        {
            "v": ENVELOPE_VERSION,
            "type": statement_type,
            "env": environment,
            "graph": graph,
            "schema": schema_version,
            "payload": dict(payload),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return _DOMAIN_TAG + body.encode("ascii")


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    """The signer name for *private_key*: its raw public key as hex."""
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign(private_key: Ed25519PrivateKey, *, statement_type: str, environment: str, graph: str,
         payload: Mapping[str, str], schema_version: int = 1) -> SignedEnvelope:
    """Sign *payload* for one statement type, environment and graph.

    Raises ``ValueError`` when the payload is not a flat str→str mapping or
    the serialized envelope would exceed :data:`MAX_ENVELOPE_CHARS`.
    """
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in payload.items()):
        raise ValueError("payload must map str to str")
    message = _signed_message(statement_type, environment, graph, schema_version, payload)
    envelope = SignedEnvelope(
        statement_type=statement_type,
        environment=environment,
        graph=graph,
        schema_version=schema_version,
        payload=dict(payload),
        signer=public_key_hex(private_key),
        signature=private_key.sign(message).hex(),
    )
    if len(envelope.to_text()) > MAX_ENVELOPE_CHARS:
        raise ValueError(f"signed envelope exceeds {MAX_ENVELOPE_CHARS} characters")
    return envelope


def from_text(text: str) -> Optional[SignedEnvelope]:
    """Parse a stored envelope; None for anything malformed or oversized.

    Untrusted input (LES-001/002): size-capped first, then strict shape checks.
    Parsing does NOT verify — call :func:`verify` before trusting it.
    """
    if not isinstance(text, str) or len(text) > MAX_ENVELOPE_CHARS:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("v") != ENVELOPE_VERSION:
        return None
    payload = data.get("payload")
    fields = (data.get("type"), data.get("env"), data.get("graph"), data.get("signer"), data.get("sig"))
    if not all(isinstance(f, str) for f in fields) or not isinstance(data.get("schema"), int):
        return None
    if not isinstance(payload, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in payload.items()):
        return None
    return SignedEnvelope(
        statement_type=data["type"],
        environment=data["env"],
        graph=data["graph"],
        schema_version=data["schema"],
        payload=payload,
        signer=data["signer"],
        signature=data["sig"],
    )


def verify(envelope: Optional[SignedEnvelope], *, statement_type: str, environment: str,
           graph: str) -> Optional[str]:
    """The signer's public key (hex) when *envelope* is a valid signature for
    exactly this statement type, environment and graph; otherwise None.

    Never raises: a malformed key or signature is simply "not verified".
    """
    if envelope is None:
        return None
    if (envelope.statement_type, envelope.environment, envelope.graph) != (statement_type, environment, graph):
        return None
    if len(envelope.signer) != _PUBLIC_KEY_HEX_CHARS or len(envelope.signature) != _SIGNATURE_HEX_CHARS:
        return None
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(envelope.signer))
        message = _signed_message(envelope.statement_type, envelope.environment, envelope.graph,
                                  envelope.schema_version, envelope.payload)
        public_key.verify(bytes.fromhex(envelope.signature), message)
    except (ValueError, InvalidSignature):
        return None
    return envelope.signer.lower()
