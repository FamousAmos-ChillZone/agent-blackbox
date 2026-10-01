"""The private working-memory audit record kept in the local DKG node.

Redacted-but-local evidence stays in the node's PRIVATE working memory — never
shared to SWM. Best-effort; failures are swallowed.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict
from ..kernel import constants
from . import redaction

logger = logging.getLogger(__name__)

def write_private_audit_ka(client: Any, cg_id: str, event: str, finding: Dict[str, Any]) -> None:
    """Write a private WM audit KA carrying the observed command/prompt.

    Privacy split: the redacted-but-local evidence lives in the node's private
    working memory, never shared to SWM. Best-effort — failures are swallowed.
    """
    from .kernel import rdf_terms, threat_ids

    try:
        ident = str(finding.get("identifier") or "unknown")
        ts = rdf_terms.datetime_literal()
        subj = f"urn:guardian:audit:{threat_ids.stable_hash(ident + str(time.time()), 24)}"
        q = [
            {"subject": subj, "predicate": constants.RDF_TYPE, "object": f"{constants.BLACKBOX_ONTOLOGY}AuditRecord"},
            {"subject": subj, "predicate": constants.IDENTIFIER_PRED, "object": rdf_terms.literal(ident)},
            {"subject": subj, "predicate": constants.SEVERITY_PRED, "object": rdf_terms.literal(str(finding.get("severity") or "info"))},
            {"subject": subj, "predicate": constants.SCHEMA_DESCRIPTION_PRED, "object": rdf_terms.literal(redaction.sanitize_text(str(finding.get("evidence") or ""), 1200))},
            {"subject": subj, "predicate": constants.SCHEMA_DATE_MODIFIED_PRED, "object": ts},
        ]
        # Private: create+write+seal in WM, do NOT share to SWM.
        client.write_private_knowledge_asset(cg_id, subj.rsplit(":", 1)[-1], q)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: private audit KA write failed: %s", exc)
