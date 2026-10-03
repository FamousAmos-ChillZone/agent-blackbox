"""The ``blackbox curate`` argument parser — every verb and its options.

Parsing only: each verb's behaviour is one Command function in
:mod:`.commands`, reached through ``cmd_curate``. The compiled ruleset is
injected by cli.py, the composition root.

Usage (from cli.py)::

    curate.add_curate_parser(subparsers, compiled_ruleset=ruleset.peek)
"""

from __future__ import annotations

import argparse
from typing import Any, Optional

from . import node_ui_views
from .commands import cmd_curate
from .context import CompiledRuleset


def add_curate_parser(sub: "argparse._SubParsersAction", *, compiled_ruleset: Optional[CompiledRuleset] = None) -> None:
    """Register ``blackbox curate <verb>`` on the CLI's sub-parsers."""
    curate = sub.add_parser("curate", help="Curator tooling: queue, dossier, two-key proposals, publish")
    curate.set_defaults(func=cmd_curate, compiled_ruleset=compiled_ruleset, verb=None)
    curate.add_argument("--authority", choices=["verified", "community"], default=None,
                        help="which authority this machine acts for (default: the one whose manifest lists its key)")
    verbs_ = curate.add_subparsers(dest="verb")
    k = verbs_.add_parser("keys", help="Show or create this machine's curator key (sandbox: --root too)")
    k.add_argument("--root", action="store_true", help="SANDBOX: also create/show a local root key")
    m = verbs_.add_parser("manifest", help="SANDBOX: stage a root-signed key manifest (then `publish`)")
    m.add_argument("--curator-key", dest="curator_keys", action="append", required=True, metavar="HEX")
    m.add_argument("--threshold", type=int, default=2)
    m.add_argument("--promotion-author", dest="promotion_author", default="", metavar="ADDRESS",
                   help="verified authority only: the pinned publisher of verified rows")
    m.add_argument("--issued-day", dest="issued_day", default="", metavar="YYYY-MM-DD",
                   help="date the manifest (60-day validity, 72 h time-lock); omit for no clock")
    m.add_argument("--root-epoch", dest="root_epoch", type=int, default=1)
    m.add_argument("--version", type=int, default=1)
    verbs_.add_parser("queue", help="The delta view: NEW threats by lane; already-verified closed as duplicates")
    s = verbs_.add_parser("show", help="The evidence dossier and checklist preview for one threat")
    s.add_argument("identifier")
    _add_propose(verbs_)
    verbs_.add_parser("inbox", help="Receive proposals sent by the other curator")
    a = verbs_.add_parser("approve", help="Second key: co-sign, consent, publish")
    a.add_argument("proposal_id")
    a.add_argument("--evidence", default="", help="your own check of the evidence (promotions, community confirmations)")
    a.add_argument("--root", action="store_true", help="SANDBOX: add the root signature (wide / popular kills, R14)")
    _add_consent(a)
    p = verbs_.add_parser("publish", help="Publish an APPROVED proposal (after consent)")
    p.add_argument("proposal_id")
    _add_consent(p)
    r = verbs_.add_parser("reject", help="Drop a proposal locally (no statement is sent)")
    r.add_argument("proposal_id")
    verbs_.add_parser("list", help="This machine's proposals and their state")
    h = verbs_.add_parser("heartbeat", help="Publish this curator key's heartbeat (one key; daily)")
    _add_consent(h)
    verbs_.add_parser("upkeep", help="Re-publish this node's current statements before shared memory forgets them")
    w = verbs_.add_parser("watch", help="Intake: announce NEW threats to a webhook")
    w.add_argument("--webhook", required=True)
    w.add_argument("--interval", type=float, default=60.0)
    w.add_argument("--once", action="store_true")
    vi = verbs_.add_parser("views", help="Install the saved node-UI queries (query catalog)")
    vi.add_argument("--install", action="store_true", required=True)
    _add_reputation(verbs_)
    verbs_.add_parser("metrics", help="R15: the latest shadow-phase snapshot and the newcomer calibration gap")
    v = verbs_.add_parser("view", help="Run one saved view from the CLI")
    v.add_argument("slug", choices=[x.slug for x in (*node_ui_views.COMMUNITY_VIEWS, *node_ui_views.VERIFIED_VIEWS)])


def _add_propose(verbs_: Any) -> None:
    p = verbs_.add_parser("propose", help="First key: sign a proposal and send it to the other curator")
    what = p.add_mutually_exclusive_group(required=True)
    what.add_argument("--promote", metavar="IDENTIFIER", help="promote a malware dependency (dep:…)")
    what.add_argument("--verdict", nargs=2, metavar=("KIND", "IDENTIFIER"),
                      help="confirmation | rejection | revocation | deferral | in-review | deferral-lapsed")
    what.add_argument("--nominate", metavar="KEY_HEX", help="counted-author entry for a reporter key")
    what.add_argument("--attest", nargs=2, metavar=("STAGE", "IDENTIFIER"),
                      help="stage attestation (R3-attest): reported | held | corroborated | deferred")
    what.add_argument("--pause", action="store_true", help="pause community ingest (needs --until)")
    what.add_argument("--kill-list", dest="kill_list", metavar="FILE", help="R14: a JSON list of kill entries (next version)")
    p.add_argument("--severity", default="critical")
    p.add_argument("--evidence", default="", help="item 1: advisory:<id> | registry-action:<url> | reproduced:<sha256>")
    p.add_argument("--reason", default="", help="verdict reason / scope reason")
    p.add_argument("--name", default="")
    p.add_argument("--class", dest="author_class", default="established", choices=["partner", "established"])
    p.add_argument("--address", default="", help="nomination: the reporter's agent address")
    p.add_argument("--org", default="")
    p.add_argument("--expires", default="")
    p.add_argument("--until", default="")
    p.add_argument("--delist", action="store_true", help="nomination: remove (the denylist)")
    p.add_argument("--to", default="", metavar="PEER", help="send to this curator peer (name or peer id)")


def _add_reputation(verbs_: Any) -> None:
    """R4: the curator-private reputation verbs (``outcome``, ``graduate``)."""
    o = verbs_.add_parser("outcome", help="R4: record a curator decision about a reporter's report in the PRIVATE reputation ledger")
    o.add_argument("key", help="the reporter KEY (64 hex) — the identity, never an address")
    decided = o.add_mutually_exclusive_group(required=True)
    decided.add_argument("--confirmed", action="store_true")
    decided.add_argument("--rejected", action="store_true")
    o.add_argument("--novel", action="store_true", help="the report earned a novelty credit (judge with the §05 rules first)")
    o.add_argument("--strike", action="store_true", help="confirmed bad faith")
    o.add_argument("--first-seen", dest="first_seen", default="", help="UTC day of the reporter's first share (new entries)")
    o.add_argument("--day", default="", help="UTC day of the decision (default today)")
    g = verbs_.add_parser("graduate", help="R4: who graduates or is demoted today; --propose builds the counted-author proposal")
    g.add_argument("--propose", metavar="KEY", default="", help="propose the listing / delisting this key calls for")
    g.add_argument("--address", default="", help="the reporter's agent address (display only; required with --propose)")
    g.add_argument("--cluster", default="", help="collapse: list the key under this shared cluster id")
    g.add_argument("--erase", metavar="KEY", default="", help="crypto-shred this reporter's ledger entry (erasure request)")
    g.add_argument("--to", default="", metavar="PEER")


def _add_consent(parser: Any) -> None:
    parser.add_argument("--code", default=None, help="the 8-hex confirmation code shown for this content")
    parser.add_argument("--yes", action="store_true", help="SANDBOX only: consent without typing the code")
