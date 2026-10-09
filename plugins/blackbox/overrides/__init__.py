"""Local overrides (Refine R7b): the operator's release valve, reduction-only.

`blackbox rules unblock <identifier>` demotes a verified rule from BLOCK to
FLAG on this machine only — audited (the store is the record and every hook
decision it changes says so), never shared, never a graph statement. There
is no way to raise enforcement here: that needs the curators' 2-of-3.

Public surface: :class:`OverrideStore` / :class:`LocalOverride`,
:func:`demote_blocking` (used by the guard), :func:`add_rules_parser` (the CLI).
Depends on the kernel only.
"""

from __future__ import annotations

from .cli import add_rules_parser, cmd_rules
from .store import LocalOverride, OverrideStore, demote_blocking

__all__ = ["LocalOverride", "OverrideStore", "add_rules_parser", "cmd_rules", "demote_blocking"]
