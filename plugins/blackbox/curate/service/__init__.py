"""Service — the curator node's own routine work (Community Curation C9, plan §07).

* :mod:`.policy` — the automation policy: one pure table that says, for an
  action and the facts this node established itself, whether the service may
  sign or a person must.
* :mod:`.policy_consent` — the operator's standing consent, bound to the
  policy's exact text; :func:`policy_command` is ``blackbox curate policy``.

The service is its own process (``blackbox curate run``), started only on
curator nodes; it never runs inside an agent's hooks.
"""

from __future__ import annotations

from . import policy
from .commands import policy_command
from .policy import Action, Facts, PolicyDecision, action_for, decide, policy_hash, policy_text
from .policy_consent import Acceptance, PolicyConsent

__all__ = ["Acceptance", "Action", "Facts", "PolicyConsent", "PolicyDecision", "action_for", "decide", "policy",
           "policy_command", "policy_hash", "policy_text"]
