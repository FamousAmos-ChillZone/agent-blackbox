"""Ruleset refresh outcomes callers branch on (raised by :mod:`.refresh_cycle`)."""

from __future__ import annotations


class RulesetRefreshUnavailable(RuntimeError):
    """A required post-barrier refresh did not produce a fresh snapshot."""


class RulesetRefreshLockUnavailable(RulesetRefreshUnavailable):
    """A required post-barrier refresh could not acquire its process lock."""


class RulesetRefreshIncomplete(RulesetRefreshUnavailable):
    """A required post-barrier refresh could not read a complete VM snapshot."""
