"""Service — the curator node's own routine work (Community Curation C9, plan §07).

* :mod:`.policy` — the automation policy: one pure table that says, for an
  action and the facts this node established itself, whether the service may
  sign or a person must.
* :mod:`.policy_consent` — the operator's standing consent, bound to the
  policy's exact text; :func:`policy_command` is ``blackbox curate policy``.
* :mod:`.evidence` — the facts this node establishes by itself: its own
  advisory lookup and what its own ledger calls for.
* :mod:`.budget` — the service's own daily limit on raising statements.
* :mod:`.self_test` — the fixed fixture set (10 threats, 10 clean, 2 could-not-tell)
  run at start, daily and while failing; a failing curator is suspended.
* :mod:`.inbox` — which received proposals are a curator's, and which of this
  node's own are finished because another curator published them.
* :mod:`.beat` — one beat: the fixed order of steps (:class:`Beat`), reporting a
  :class:`BeatReport` (:mod:`.report`);
  :func:`run_command` is ``blackbox curate run`` (``--publisher`` on the wallet
  node); both verbs register from :mod:`.commands` (``add_service_parser``).
* :mod:`.steps` — the trust-and-threat-lab steps, one line each in the beat:
  source look-ups, the lab's collect and submit, the batch publisher (step 8),
  the weekly withdrawal re-check and the alarms (``ServiceSteps``). Imported
  by path, not from this surface: it loads ``curate.sources``, which reads this package.

The service is its own process (``blackbox curate run``), started only on
curator nodes; it never runs inside an agent's hooks.
"""

from __future__ import annotations

from . import policy, self_test
from .beat import Beat
from .commands import policy_command, run_command
from .evidence import Lookup, OwnCheck, own_check
from .policy import Action, Facts, PolicyDecision, action_for, decide, policy_hash, policy_text
from .policy_consent import Acceptance, PolicyConsent
from .report import BeatReport, HumanItem
from .self_test import SelfTest, SelfTestResult, SelfTestStore

__all__ = ["Acceptance", "Action", "Beat", "BeatReport", "Facts", "HumanItem", "Lookup", "OwnCheck", "PolicyConsent",
           "PolicyDecision", "SelfTest", "SelfTestResult", "SelfTestStore", "action_for", "decide", "own_check", "policy",
           "policy_command", "policy_hash", "policy_text", "run_command", "self_test"]
