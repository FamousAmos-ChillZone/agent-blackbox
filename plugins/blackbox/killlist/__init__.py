"""Kill list (Refine R14, plan §06): curator-signed DISABLE / WARN for installed skills and MCP servers.

A 2-of-3 signed, versioned statement in the verified graph names artifacts
to refuse at the hook (files and config untouched; never uninstall) or to
warn about, keyed on registry + identifier + version + hash. Readers apply
blast-radius gates (wide kills need the root; popular / allowlisted targets
need the root and a 24 h hold; ≤ 20 new disables per version) and keep the
LAST-GOOD list on any failure — never "disable all", never "enable all".

Modules: :mod:`.statement` (build / sign / parse), :mod:`.gates` (admit →
Decision), :mod:`.store` (last-good on disk), :mod:`.check` (the hook's
match → Finding). The ruleset refresh reads and admits; the guard enforces.
Depends on the kernel and on ``detection`` (the skill-install parser and
the Finding type) only.
"""

from __future__ import annotations

from .check import finding_for, match
from .gates import MAX_NEW_DISABLES, POPULAR_HOLD_SECONDS, Decision, admit
from .statement import (KILL_LIST_STATEMENT, KILL_LIST_TYPE_IRI, MAX_ENTRIES, KillAction, KillEntry, KillList,
                        kill_list_quads, kill_list_sparql, kill_list_subject, parse_kill_list, sign_kill_list)
from .store import LastGoodStore

__all__ = [
    "Decision", "KILL_LIST_STATEMENT", "KILL_LIST_TYPE_IRI", "KillAction", "KillEntry", "KillList", "LastGoodStore",
    "MAX_ENTRIES", "MAX_NEW_DISABLES", "POPULAR_HOLD_SECONDS", "admit", "finding_for", "kill_list_quads",
    "kill_list_sparql", "kill_list_subject", "match", "parse_kill_list", "sign_kill_list",
]
