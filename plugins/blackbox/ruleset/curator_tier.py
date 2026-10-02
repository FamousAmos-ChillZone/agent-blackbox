"""The curator overlay on the verified ruleset — revocations (Refine R2).

A curator revocation withdraws a verified rule. It REDUCES enforcement, so it
always applies, on every refresh path and whether or not a community graph is
configured (asymmetric safety, LES-016). Only revocations this node can
verify count: signed by the trusted key manifest's curator keys, in the
verified graph (:func:`..community.read_curator_view`). Fail-open: a curator
read problem never degrades the verified ruleset; it simply removes nothing.

A re-promotion (a higher-sequence promotion after a revocation) takes effect
at the next full compile of the verified graph. Delaying an un-revoke is the
safe direction, because it raises enforcement.

Usage (from the refresh cycle)::

    curator_tier.apply_curator_tier(rs, client, config)
"""

from __future__ import annotations

import logging

from .. import community
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient
from . import compiler

logger = logging.getLogger(__name__)


def apply_curator_tier(rs: compiler.Ruleset, client: DkgClient, config: BlackboxConfig) -> int:
    """Drop the verified rules the curator revoked; returns how many."""
    try:
        revoked = community.read_curator_view(client, config).revoked
    except Exception as exc:  # pragma: no cover - fail open (an outer boundary)
        logger.warning("blackbox: curator revocations not applied this refresh: %s", exc)
        return 0
    removed = rs.drop_identifiers(revoked)
    if removed:
        logger.info("blackbox: %d verified rule(s) withdrawn by curator revocation", removed)
    return removed
