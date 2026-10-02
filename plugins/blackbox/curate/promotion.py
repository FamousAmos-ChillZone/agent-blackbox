"""Promotion — a threat enters the verified tier (Refine R6; scope: dependency, kind=malware).

Plan §09 PROMOTION WRITE: the promotion is written in the EXISTING verified-rule
vocabulary the verified reader already compiles (no second reader): a
``urn:defender:DependencySignal`` threat with identifier, severity, kind,
package fields, advisory, name — plus the two-signature ``blackbox.promotion``
envelope over the same fields (R7a), and PROVENANCE as random report ids whose
mapping to the real report subjects stays curator-private (:class:`ProvenanceMap`).
Kind is mandatory and must be ``malware``; the scope is exact versions unless
the checklist's scope reason allows ``*``.

Usage::

    payload = promotion.payload_for(identifier, severity="critical", advisory="MAL-2026-1", report_subjects=[...], provenance=ProvenanceMap())
    envelope = promotion.sign(payload, key, manifest)        # first key; signing.cosign adds the second
    quads = promotion.verified_rule_quads(payload, envelope)  # -> node_routes.publish_to_verified_memory
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..kernel import constants, rdf_terms, signing, threat_ids
from ..kernel.signing.key_manifest import KeyManifest
from ..kernel.signing.statement_order import CuratorStatement
from . import keys

_PROVENANCE_FILE = "provenance.jsonl"


class PromotionError(ValueError):
    """A promotion outside R6's scope or missing a mandatory field."""


class ProvenanceMap:
    """Curator-PRIVATE mapping random provenance id -> report subject
    (append-only JSONL in the curate home). The verified graph carries only
    the random ids, so reporters are credited without being linkable."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _PROVENANCE_FILE)
        self._lock = threading.Lock()

    def credit(self, identifier: str, report_subjects: Iterable[str]) -> List[str]:
        ids = []
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a", encoding="utf-8") as fh:
                for subject in report_subjects:
                    random_id = secrets.token_hex(8)
                    fh.write(json.dumps({"id": random_id, "identifier": identifier, "subject": subject}) + "\n")
                    ids.append(random_id)
        return ids


def payload_for(identifier: str, *, severity: str, advisory: str, report_subjects: Iterable[str],
                provenance: ProvenanceMap, name: str = "") -> Dict[str, str]:
    """The flat, signed payload of a promotion. Dependency + kind=malware only."""
    parts = threat_ids.parse_dependency_identifier(identifier)
    if parts is None:
        raise PromotionError("R6 promotes dependency threats only (dep:<ecosystem>:<name>@<version>)")
    ecosystem, package, version = parts
    if severity.lower() not in constants.SEVERITY_ORDER:
        raise PromotionError(f"severity must be one of {constants.SEVERITY_ORDER}")
    return {
        "identifier": identifier,
        "severity": severity.lower(),
        "kind": constants.KIND_MALWARE,
        "ecosystem": ecosystem,
        "packageName": package,
        "packageVersion": version,
        "advisoryId": advisory.strip(),
        "name": name.strip() or f"{package}@{version} (malicious {ecosystem} package)",
        "provenance": ",".join(provenance.credit(identifier, report_subjects)),
    }


def sign(payload: Mapping[str, str], key: Ed25519PrivateKey, manifest: KeyManifest, *, sequence: int) -> signing.SignedEnvelope:
    """The first curator signature on a promotion (co-sign with signing.cosign)."""
    return signing.sign(key, statement_type=CuratorStatement.PROMOTION.value, environment=manifest.environment,
                        graph=manifest.graph, payload=dict(payload), chain=manifest.chain,
                        root_epoch=manifest.root_epoch, sequence=sequence)


def verified_rule_quads(payload: Mapping[str, str], envelope: signing.SignedEnvelope) -> List[rdf_terms.Quad]:
    """The verified-graph quads the existing reader compiles into a BLOCKING rule."""
    subject = threat_ids.threat_uri(payload["identifier"])
    literals = (
        (constants.IDENTIFIER_PRED, payload["identifier"]),
        (constants.SEVERITY_PRED, payload["severity"]),
        (constants.KIND_PRED, payload["kind"]),
        (constants.PACKAGE_ECOSYSTEM_PRED, payload["ecosystem"]),
        (constants.PACKAGE_NAME_PRED, payload["packageName"]),
        (constants.PACKAGE_VERSION_PRED, payload["packageVersion"]),
        (constants.SCHEMA_NAME_PRED, payload["name"]),
        (constants.CURATED_PRED, "true"),
        (constants.SOURCE_OBSERVATION_PROVENANCE_JSON_PRED, json.dumps(payload["provenance"].split(",") if payload["provenance"] else [])),
        (constants.SIGNED_STATEMENT_PRED, envelope.to_text()),
    )
    quads = [rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.DEFENDER_DEPENDENCY_TYPE_IRI))]
    quads += [rdf_terms.make_quad(subject, predicate, rdf_terms.literal(value)) for predicate, value in literals if value]
    if payload.get("advisoryId"):
        quads.append(rdf_terms.make_quad(subject, constants.SCHEMA_IDENTIFIER_PRED, rdf_terms.literal(payload["advisoryId"])))
    return quads


def asset_name(identifier: str) -> str:
    """The KA name of a promoted threat (deterministic: one asset per threat)."""
    return f"threat-{threat_ids.stable_hash(identifier, 16)}"
