"""Test helper: real signed community report rows, built by the real writer.

``signed_row`` runs community.report_builder.build_report_quads with a real
ReportSigner and turns the quads into the row shape the reader's SPARQL
returns ({variable: value}), so reader tests exercise exactly what writers
produce. ``Reporter`` is one node: an agent address + its own reporter key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.community import report_builder
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.kernel import signing

NETWORK = "test-network-id"
GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"


@dataclass(frozen=True)
class Reporter:
    address: str
    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)  # gitleaks:allow — annotation; keys are generated per test

    @property
    def author(self) -> str:
        return signing.public_key_hex(self.key)


def signed_row(identifier: str, reporter: Reporter, severity: str = "high", category: str = "",
               environment: str = NETWORK, graph: str = GRAPH, **evidence: str) -> Dict[str, str]:
    """One report row as the community reader's query returns it."""
    category = category or {"dep": "dependency"}.get(identifier.split(":", 1)[0], identifier.split(":", 1)[0])
    if category == "ioc":                                       # a real IOC report names its type and context
        evidence = {"ioc_type": identifier.split(":", 2)[1], "ioc_context": "fetched-by-tool", **evidence}
    if category == "dependency":                                # a real dependency report carries its package
        eco, rest = identifier.split(":", 2)[1:]
        name, version = rest.rsplit("@", 1)
        evidence = {"ecosystem": eco, "package_name": name, "package_version": version, "kind": "malware",
                    "reason": "typosquat", **evidence}
    signer = ReportSigner(private_key=reporter.key, environment=environment, graph=graph)
    quads = report_builder.build_report_quads(identifier=identifier, category=category, severity=severity,
                                              reporter_address=reporter.address, signer=signer, **evidence)
    row = {"r": quads[0]["subject"]}
    for quad in quads:
        obj = quad["object"]
        if obj.startswith('"') and obj.endswith('"'):   # plain literals only (skip IRIs and typed dates)
            row[quad["predicate"].rsplit("/", 1)[-1]] = json.loads(obj)
    return row


def signed_retraction_row(identifier: str, reporter: Reporter, environment: str = NETWORK,
                          graph: str = GRAPH, signed: bool = True) -> Dict[str, str]:
    """One retraction row as the reader's retraction query returns it (Refine R1)."""
    signer = ReportSigner(private_key=reporter.key, environment=environment, graph=graph) if signed else None
    quads = report_builder.build_retraction_quads(identifier=identifier, reporter_address=reporter.address,
                                                  signer=signer)
    row = {"r": quads[0]["subject"]}
    for quad in quads:
        obj = quad["object"]
        if obj.startswith('"') and obj.endswith('"'):
            row[quad["predicate"].rsplit("/", 1)[-1]] = json.loads(obj)
    return row


def signed_dispute_row(identifier: str, reporter: Reporter, reason: str = "wrong", environment: str = NETWORK,
                       graph: str = GRAPH) -> Dict[str, str]:
    """One dispute (g:FalsePositive) row as the reader's dispute query returns it (Refine R2)."""
    signer = ReportSigner(private_key=reporter.key, environment=environment, graph=graph)
    quads = report_builder.build_false_positive_quads(identifier=identifier, reporter_address=reporter.address,
                                                      reason=reason, signer=signer)
    row = {"r": quads[0]["subject"]}
    for quad in quads:
        obj = quad["object"]
        if obj.startswith('"') and obj.endswith('"'):
            row[quad["predicate"].rsplit("/", 1)[-1]] = json.loads(obj)
    return row
