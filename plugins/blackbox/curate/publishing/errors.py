"""The errors the publishing step raises when it refuses."""

from __future__ import annotations


class VerbError(ValueError):
    """A verb refused; the message says why (printed, never a traceback)."""


class PublishLedgerError(ValueError):
    """The publish ledger refused: an illegal state transition, a record
    missing a field its state requires, or an unreadable ledger file. Never
    caught to "carry on" — a ledger that cannot be trusted stops the publisher
    (fail closed: a wrong guess here can pay to mint the same batch twice)."""
