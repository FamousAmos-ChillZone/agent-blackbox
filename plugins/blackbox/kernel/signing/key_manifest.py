"""The curator key manifest — which keys may sign what, per environment (Refine R7a).

A key manifest is a statement signed by the curator ROOT that lists, for ONE
environment (DKG network id) and ONE verified graph:

* the curator keys and the threshold of them a statement needs (2-of-3 —
  one key is neither enough nor a veto, KI-134);
* the pinned PROMOTION AUTHOR — the only publisher whose verified rows count
  (KI-106);
* a content-hash pin over the LEGACY verified assets (the corpus published
  before signed statements existed), which grandfathers them so requiring
  signatures never un-serves the existing corpus (KI-118).

Manifests are ordered by ``(root_epoch, version)`` compared as a pair, so a
root rotation can reset a version counter that was pushed to its maximum.
Curator keys are per environment: a key in the sandbox manifest is not a key
in the mainnet manifest, and statements are signed for one environment only,
so a sandbox signature can never count on mainnet (KI-143).

This module is the FORMAT: build, sign, parse and check a manifest, and ask
whether a statement meets its quorum. Which manifest a reader trusts (root
pins, the 72 h time-lock, freezes) is reader policy (R7b).

Pattern: Value Object (:class:`KeyManifest`) + pure functions.

Usage::

    from ..kernel.signing import key_manifest
    manifest = key_manifest.KeyManifest(environment=net, graph=vm_graph, chain="base:8453",
        root_epoch=1, version=1, curator_keys=(a, b, c), threshold=2,
        promotion_author="0x...", legacy_assets_hash=key_manifest.legacy_assets_hash(uals))
    envelope = key_manifest.sign_manifest(manifest, root_private_key)
    trusted = key_manifest.verify_manifest(envelope, environment=net, graph=vm_graph, root_keys={root_hex})
    trusted.has_quorum(statement, statement_type="blackbox.promotion")   # True with 2 of the 3 keys
"""

from __future__ import annotations

import hashlib
import re
from datetime import date, timedelta
from dataclasses import dataclass
from typing import AbstractSet, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import envelope as signing

#: The statement type of a key manifest (signed by the root).
KEY_MANIFEST_STATEMENT = "blackbox.key-manifest"
#: The fewest keys a curator statement may need (one key is never enough).
MIN_THRESHOLD = 2
#: The most curator keys one manifest may list (the envelope caps signatures).
MAX_CURATOR_KEYS = 8
#: R7b: a dated manifest is valid this long, and takes effect this long after its day (the 72 h time-lock).
MANIFEST_VALID_DAYS = 60
MANIFEST_TIME_LOCK_DAYS = 3
_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class KeyManifestError(ValueError):
    """A manifest that must not be built or trusted; the message says why."""


@dataclass(frozen=True)
class KeyManifest:
    """One environment's curator keys, signed by the root.

    ``environment`` / ``graph`` / ``chain`` — where it applies (the verified
    graph). ``root_epoch`` / ``version`` — its order. ``curator_keys`` —
    Ed25519 public keys (hex), sorted. ``threshold`` — how many of them a
    curator statement needs. ``promotion_author`` — the pinned publisher of
    verified rows. ``legacy_assets_hash`` — sha256 pin of the grandfathered
    legacy assets (:func:`legacy_assets_hash`).
    """

    environment: str
    graph: str
    chain: str
    root_epoch: int
    version: int
    curator_keys: Tuple[str, ...]
    threshold: int
    promotion_author: str
    legacy_assets_hash: str
    #: R10b: the oldest plugin version that can read the curators' newer statements
    #: ("" = no requirement); omitted from the payload when empty, so older manifests hash the same.
    min_reader_version: str = ""
    #: R7b: the UTC day the root signed it. A manifest is STALE MANIFEST_VALID_DAYS
    #: later (raising statements freeze; reductions and existing rules keep working)
    #: and takes effect only MANIFEST_TIME_LOCK_DAYS after this day. "" = no clock.
    issued_day: str = ""
    #: R7b: a sealed break-glass curator key — its signature counts ONLY on
    #: statements that reduce enforcement (revocations, rejections). "" = none.
    break_glass_key: str = ""

    def __post_init__(self) -> None:
        _validate(self)

    @property
    def order(self) -> Tuple[int, int]:
        """``(root_epoch, version)`` — compare manifests by this pair."""
        return self.root_epoch, self.version

    def to_payload(self) -> Dict[str, str]:
        """The manifest as the flat str→str payload its envelope signs."""
        return {
            "environment": self.environment,
            "graph": self.graph,
            "chain": self.chain,
            "rootEpoch": str(self.root_epoch),
            "version": str(self.version),
            "curatorKeys": ",".join(self.curator_keys),
            "threshold": str(self.threshold),
            "promotionAuthor": self.promotion_author,
            "legacyAssetsHash": self.legacy_assets_hash,
            **({"minReaderVersion": self.min_reader_version} if self.min_reader_version else {}),
            **({"issuedDay": self.issued_day} if self.issued_day else {}),
            **({"breakGlassKey": self.break_glass_key} if self.break_glass_key else {}),
        }

    def content_hash(self) -> str:
        """sha256 of the canonical payload — the manifest's identity."""
        canonical = "\n".join(f"{k}={v}" for k, v in sorted(self.to_payload().items()))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def grandfathers(self, legacy_uals: Iterable[str]) -> bool:
        """True when *legacy_uals* is exactly the asset set this manifest
        grandfathered — an asset added later is not legacy and must be signed."""
        return legacy_assets_hash(legacy_uals) == self.legacy_assets_hash

    def curator_signers(self, statement: Optional[signing.SignedEnvelope], *, statement_type: str,
                        graph: Optional[str] = None) -> FrozenSet[str]:
        """This manifest's curator keys that validly signed *statement* for its
        environment, chain and root epoch, in *graph* (default: the manifest's
        verified graph — advisory statements live in the community graph)."""
        signers = signing.verified_signers(statement, statement_type=statement_type, environment=self.environment,
                                           graph=graph or self.graph, chain=self.chain, root_epoch=self.root_epoch)
        counted = signers & frozenset(self.curator_keys)
        if self.break_glass_key and self.break_glass_key in counted and not _reduces(statement_type):
            counted = counted - {self.break_glass_key}   # R7b: the break-glass key only ever reduces enforcement
        return counted

    def has_quorum(self, statement: Optional[signing.SignedEnvelope], *, statement_type: str,
                   graph: Optional[str] = None) -> bool:
        """True when at least ``threshold`` curator keys signed *statement*
        (see :meth:`curator_signers`)."""
        return len(self.curator_signers(statement, statement_type=statement_type, graph=graph)) >= self.threshold


#: Statement types a break-glass key may sign (reduction-only; the kill-list and
#: heartbeat live elsewhere and never reduce).
_REDUCING_STATEMENTS = frozenset({"blackbox.revocation", "blackbox.rejection"})


def _reduces(statement_type: str) -> bool:
    return statement_type in _REDUCING_STATEMENTS


def manifest_clock(manifest: KeyManifest, today: str) -> Tuple[str, str]:
    """R7b: ("" | "pending" | "stale", detail day). A dated manifest is PENDING
    before its time-lock ends (issued + 3 d, the day it takes effect) and
    STALE after issued + 60 d (the day it expired). Undated: ""."""
    if not manifest.issued_day:
        return "", ""
    try:
        issued = date.fromisoformat(manifest.issued_day)
    except ValueError:
        return "stale", manifest.issued_day
    effective = (issued + timedelta(days=MANIFEST_TIME_LOCK_DAYS)).isoformat()
    expires = (issued + timedelta(days=MANIFEST_VALID_DAYS)).isoformat()
    if today < effective:
        return "pending", effective
    if today > expires:
        return "stale", expires
    return "", expires


def _validate(manifest: KeyManifest) -> None:
    keys = manifest.curator_keys
    if manifest.break_glass_key and manifest.break_glass_key not in keys:
        raise KeyManifestError("the break-glass key must be one of the curator keys")
    if manifest.issued_day and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", manifest.issued_day):
        raise KeyManifestError("issued_day must be a UTC day (YYYY-MM-DD)")
    if not all(isinstance(k, str) and _KEY_HEX.fullmatch(k) for k in keys):
        raise KeyManifestError("curator keys must be Ed25519 public keys (64 lower-case hex)")
    if len(set(keys)) != len(keys) or tuple(sorted(keys)) != keys:
        raise KeyManifestError("curator keys must be distinct and sorted")
    if not 1 <= len(keys) <= MAX_CURATOR_KEYS:
        raise KeyManifestError(f"a manifest lists 1-{MAX_CURATOR_KEYS} curator keys")
    if not MIN_THRESHOLD <= manifest.threshold <= len(keys):
        raise KeyManifestError(f"threshold must be at least {MIN_THRESHOLD} and at most the number of keys")
    if manifest.root_epoch < 0 or manifest.version < 1:
        raise KeyManifestError("root_epoch must be >= 0 and version >= 1")
    if not (manifest.environment and manifest.graph and manifest.promotion_author):
        raise KeyManifestError("environment, graph and promotion author are required")
    if not _SHA256_HEX.fullmatch(manifest.legacy_assets_hash):
        raise KeyManifestError("legacy_assets_hash must be a sha256 hex digest")


def legacy_assets_hash(uals: Iterable[str]) -> str:
    """sha256 over the sorted, de-duplicated legacy asset UALs (one per line)."""
    canonical = "\n".join(sorted({str(ual).strip() for ual in uals if str(ual).strip()}))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_manifest(manifest: KeyManifest, root_key: Ed25519PrivateKey) -> signing.SignedEnvelope:
    """The manifest as a root-signed statement (its version is the sequence)."""
    return signing.sign(root_key, statement_type=KEY_MANIFEST_STATEMENT, environment=manifest.environment,
                        graph=manifest.graph, payload=manifest.to_payload(), chain=manifest.chain,
                        root_epoch=manifest.root_epoch, sequence=manifest.version)


def verify_manifest(envelope: Optional[signing.SignedEnvelope], *, environment: str, graph: str,
                    root_keys: AbstractSet[str]) -> Optional[KeyManifest]:
    """The manifest when *envelope* is signed by one of *root_keys* for this
    environment and graph and its payload agrees with its signed domain
    fields; otherwise None. Never raises."""
    if envelope is None:
        return None
    signers = signing.verified_signers(envelope, statement_type=KEY_MANIFEST_STATEMENT,
                                       environment=environment, graph=graph)
    if not signers & {key.lower() for key in root_keys}:
        return None
    manifest = _from_payload(envelope.payload)
    if manifest is None or (manifest.environment, manifest.graph, manifest.chain, manifest.root_epoch,
                            manifest.version) != (environment, graph, envelope.chain, envelope.root_epoch,
                                                  envelope.sequence):
        return None
    return manifest


def _from_payload(payload: Mapping[str, str]) -> Optional[KeyManifest]:
    try:
        return KeyManifest(
            environment=payload["environment"], graph=payload["graph"], chain=payload["chain"],
            root_epoch=int(payload["rootEpoch"]), version=int(payload["version"]),
            curator_keys=tuple(k for k in payload["curatorKeys"].split(",") if k),
            threshold=int(payload["threshold"]), promotion_author=payload["promotionAuthor"],
            legacy_assets_hash=payload["legacyAssetsHash"], min_reader_version=str(payload.get("minReaderVersion") or ""),
            issued_day=str(payload.get("issuedDay") or ""), break_glass_key=str(payload.get("breakGlassKey") or ""),
        )
    except (KeyError, ValueError):
        return None


def newest(manifests: Iterable[KeyManifest]) -> Optional[KeyManifest]:
    """The manifest with the highest ``(root_epoch, version)``, or None."""
    return max(manifests, key=lambda m: m.order, default=None)
