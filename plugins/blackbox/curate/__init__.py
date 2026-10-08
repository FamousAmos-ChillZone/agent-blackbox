"""``curate`` — the curator node's tooling (Community Graph Refine, R6; Community Curation).

A curator machine acts for ONE authority (:mod:`.context`): the verified one
publishes its manifest and enforcement statements in the verified graph; the
community one publishes everything in the community graph and can only ever
cause FLAG. ``blackbox curate --authority community …`` selects it explicitly.

The read side (queue, dossier, saved node-UI views) and the two-key write
side (propose -> private message -> approve + consent -> publish) of the
curator role. Public entry: :func:`add_curate_parser` (wired by cli.py).

* :mod:`.parser` — the `blackbox curate` argument parser; :mod:`.commands` — one Command per verb.
* :mod:`.publishing` — numbering, quorum check, consent and the write of an approved proposal.
* :mod:`.queue` — the delta view (NEW vs ALREADY VERIFIED) and lanes.
* :mod:`.dossier` — evidence dossier (Builder) + the ≤3-item checklist.
* :mod:`.proposal` — proposals and their lifecycle (State) + store.
* :mod:`.consent` — content-bound typed consent + the local ledger.
* :mod:`.promotion` — the verified-rule write for a promoted dependency.
* :mod:`.transport` — proposals by private point-to-point message.
* :mod:`.intake` — watch the delta view, notify a webhook.
* :mod:`.node_ui_views` — saved queries for the DKG node's own UI.
* :mod:`.catalog_import` — threat-catalog import helpers (unused; kept for adoption or deletion).
"""

from .commands import cmd_curate
from .parser import add_curate_parser

__all__ = ["add_curate_parser", "cmd_curate"]
