"""``curate`` — the curator node's tooling (Community Graph Refine, R6).

The read side (queue, dossier, saved node-UI views) and the two-key write
side (propose -> private message -> approve + consent -> publish) of the
curator role. Public entry: :func:`add_curate_parser` (wired by cli.py).

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

from .commands import add_curate_parser, cmd_curate

__all__ = ["add_curate_parser", "cmd_curate"]
