"""The error every curator verb raises when it refuses."""

from __future__ import annotations


class VerbError(ValueError):
    """A verb refused; the message says why (printed, never a traceback)."""
