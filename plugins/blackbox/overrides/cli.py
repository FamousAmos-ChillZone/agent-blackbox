"""`blackbox rules` — the operator's local release valve (R7b).

* ``blackbox rules unblock <identifier> --reason "…"`` — the verified rule
  flags instead of blocking on THIS machine (audited in the override store
  and in every hook decision it changes; never shared).
* ``blackbox rules reblock <identifier>`` — remove the override.
* ``blackbox rules list`` — what is overridden here, since when, why.

There is deliberately no ``rules block``: raising enforcement needs the
curators' 2-of-3, never one operator.
"""

from __future__ import annotations

import argparse
from typing import Any

from ..kernel import display_safety
from .store import OverrideStore


def add_rules_parser(sub: Any) -> None:
    rules = sub.add_parser("rules", help="Local overrides: unblock a verified rule on this machine (flag only), reblock, list")
    rules.set_defaults(func=cmd_rules, rules_verb=None)
    verbs = rules.add_subparsers(dest="rules_verb")
    unblock = verbs.add_parser("unblock", help="Demote one verified rule BLOCK → FLAG here (audited, never shared)")
    unblock.add_argument("identifier")
    unblock.add_argument("--reason", default="", help="why (kept in the local override record)")
    reblock = verbs.add_parser("reblock", help="Remove a local override: the rule blocks again")
    reblock.add_argument("identifier")
    verbs.add_parser("list", help="The local overrides on this machine")


def cmd_rules(args: argparse.Namespace) -> int:
    store = OverrideStore()
    if args.rules_verb == "unblock":
        override = store.unblock(args.identifier, args.reason)
        print(f"LOCAL OVERRIDE: {display_safety.term_safe(override.identifier)} now FLAGS instead of blocking on this machine.")
        print("Recorded locally with your reason; never shared. `blackbox rules reblock` restores the block.")
        return 0
    if args.rules_verb == "reblock":
        print("Override removed: the rule blocks again." if store.reblock(args.identifier) else "No local override for that identifier.")
        return 0
    current = store.current()
    if not current:
        print("No local overrides: every verified rule enforces as published.")
        return 0
    for override in sorted(current.values(), key=lambda o: o.identifier):
        print(f"{display_safety.term_safe(override.day, 10)}  {display_safety.term_safe(override.identifier, 90)}  — "
              f"{display_safety.term_safe(override.reason, 120) or 'no reason given'}")
    return 0
