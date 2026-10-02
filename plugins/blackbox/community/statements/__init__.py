"""Statements about reports and threats, and how readers honour them.

A ``community`` sub-package (the community folder reached its file alarm):

* :mod:`.retractions` — a reporter withdrawing its own report; the reader drops it.
* :mod:`.curator_statements` — the curator's verdicts and notices on the wire
  (build, sign, parse against the trusted key manifest).

Imported as modules: ``from .statements import retractions``.
"""

from . import curator_statements, retractions

__all__ = ["curator_statements", "retractions"]
