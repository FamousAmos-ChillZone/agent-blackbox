"""``blackbox curate`` — the curator's CLI (Refine R6, curator tooling lite).

Verbs (plan §09): ``keys`` (this machine's curator key; a root key in the
sandbox) · ``manifest`` (sandbox: stage a root-signed key manifest) · ``queue``
(the delta view: NEW vs ALREADY VERIFIED, by lane) · ``show`` (the dossier +
checklist preview) · ``propose`` (promotion / verdict / nomination / pause,
first key) · ``inbox`` (receive proposals) · ``approve`` (second key: co-sign,
consent, publish) · ``publish`` · ``reject`` · ``list`` · ``watch`` (intake ->
webhook) · ``views`` / ``view`` (saved node-UI queries). Each verb is one
Command function; read verbs need no keys. The compiled ruleset is injected by
cli.py, the composition root.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Any, Callable, Dict, Optional

from .. import community
from ..detection import osv
from ..kernel import display_safety, node_routes, signing
from ..kernel.signing.statement_order import CuratorStatement
from . import dossier, intake, keys, node_ui_views, queue, transport, verbs
from .context import CompiledRuleset, CurateContext, build_context, verified_identifiers
from .proposal import ProposalState, ProposalStore

_term = display_safety.term_safe


def add_curate_parser(sub: "argparse._SubParsersAction", *, compiled_ruleset: Optional[CompiledRuleset] = None) -> None:
    """Register ``blackbox curate <verb>`` on the CLI's sub-parsers."""
    curate = sub.add_parser("curate", help="Curator tooling: queue, dossier, two-key proposals, publish")
    curate.set_defaults(func=cmd_curate, compiled_ruleset=compiled_ruleset, verb=None)
    verbs_ = curate.add_subparsers(dest="verb")
    k = verbs_.add_parser("keys", help="Show or create this machine's curator key (sandbox: --root too)")
    k.add_argument("--root", action="store_true", help="SANDBOX: also create/show a local root key")
    m = verbs_.add_parser("manifest", help="SANDBOX: stage a root-signed key manifest (then `publish`)")
    m.add_argument("--curator-key", dest="curator_keys", action="append", required=True, metavar="HEX")
    m.add_argument("--threshold", type=int, default=2)
    m.add_argument("--promotion-author", dest="promotion_author", required=True, metavar="ADDRESS")
    m.add_argument("--root-epoch", dest="root_epoch", type=int, default=1)
    m.add_argument("--version", type=int, default=1)
    verbs_.add_parser("queue", help="The delta view: NEW threats by lane; already-verified closed as duplicates")
    s = verbs_.add_parser("show", help="The evidence dossier and checklist preview for one threat")
    s.add_argument("identifier")
    _add_propose(verbs_)
    verbs_.add_parser("inbox", help="Receive proposals sent by the other curator")
    a = verbs_.add_parser("approve", help="Second key: co-sign, consent, publish")
    a.add_argument("proposal_id")
    a.add_argument("--evidence", default="", help="your own item-1 evidence (promotions)")
    a.add_argument("--root", action="store_true", help="SANDBOX: add the root signature (wide / popular kills, R14)")
    _add_consent(a)
    p = verbs_.add_parser("publish", help="Publish an APPROVED proposal (after consent)")
    p.add_argument("proposal_id")
    _add_consent(p)
    r = verbs_.add_parser("reject", help="Drop a proposal locally (no statement is sent)")
    r.add_argument("proposal_id")
    verbs_.add_parser("list", help="This machine's proposals and their state")
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


# -- dispatch --------------------------------------------------------------------


def cmd_curate(args: argparse.Namespace) -> int:
    verb: Callable[[argparse.Namespace], int] = _VERBS.get(args.verb or "", _usage)
    try:
        return verb(args)
    except verbs.VerbError as exc:
        print(f"Refused: {exc}")
        return 2
    except Exception as exc:  # the outermost CLI boundary: a readable line, never a traceback
        print(f"curate {args.verb} failed: {_term(str(exc), 200)}")
        return 1


def _usage(args: argparse.Namespace) -> int:
    print("usage: blackbox curate {keys,manifest,queue,show,propose,inbox,approve,publish,reject,list,watch,views,view,outcome,graduate}")
    return 2


def _ctx(args: argparse.Namespace) -> CurateContext:
    return build_context(getattr(args, "compiled_ruleset", None))


# -- read verbs ------------------------------------------------------------------


def _keys(args: argparse.Namespace) -> int:
    print(f"curator key: {keys.curator_key_store().public_key_hex()}")
    if args.root:
        print(f"root key (SANDBOX ONLY): {keys.root_key_store().public_key_hex()}")
        print("Set BLACKBOX_CURATOR_ROOT_KEYS to this root key on every sandbox node before publishing a manifest.")
    return 0


def _queue(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    if ctx.compiled is None:
        print("No compiled ruleset available.")
        return 1
    view = queue.delta_view(ctx.compiled.community, verified_identifiers(ctx.compiled))
    print(f"NEW: {len(view.new)} · ALREADY VERIFIED (closed as duplicates): {len(view.already_verified)}"
          f" · UNLISTED-ONLY (stored, no lane): {len(view.unlisted_only)}"
          + ("" if ctx.manifest else " · no trusted key manifest: every author is unlisted"))
    for item in view.new:
        print(f"  lane {item.lane.value}  [{item.stage} · {item.enforcement}]  {_term(item.identifier, 80)}  "
              f"{item.reporters} signer(s){' · disputed' if item.disputed else ''}  — {_term(item.reason, 100)}")
    return 0


def _show(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    rule = ctx.compiled.community.get(args.identifier) if ctx.compiled is not None else None
    read = community.read_verified_reports(ctx.client, ctx.cfg)
    weight = community.counted_dispute_weight(read.disputes, ctx.view).get(args.identifier, 0) if read.available else 0
    verdict = ctx.view.verdict(args.identifier)
    built = (dossier.DossierBuilder(args.identifier).community(rule).advisories(osv.lookup)
             .allowlist(community.allowlist.check(args.identifier, rule))
             .curator(verdict.value if verdict else None, weight).heat(read.heat.get(args.identifier))
             .history(ProposalStore().for_identifier(args.identifier)).build())
    for line in dossier.render(built):
        print(_term(line, 220))
    kind = str((rule or {}).get("kind") or "malware")
    for item in dossier.checklist(args.identifier, kind=kind, evidence="", reason=""):
        print(f"  checklist {item.item}. {item.title}: {'ok' if item.ok else 'NOT YET'} — {item.note}")
    return 0


def _list(args: argparse.Namespace) -> int:
    rows = ProposalStore().all()
    if not rows:
        print("No proposals on this machine.")
        return 0
    for p in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(p.updated))
        print(f"  {p.id}  {p.state.value:<9} {when}  {_term(p.kind, 24)}  {_term(p.identifier, 70)}  {_term(p.note, 60)}")
    return 0


def _view(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    saved = node_ui_views.find_view(args.slug)
    community_view = saved in node_ui_views.COMMUNITY_VIEWS
    graph = ctx.community_graph if community_view else ctx.verified_graph
    rows = ctx.client.query(saved.sparql, graph, view=("shared-working-memory" if community_view else "verifiable-memory"),
                            on_error=None) or []
    print(f"{saved.name} — {len(rows)} row(s)")
    for row in rows[:200]:
        print("  " + "  ".join(f"{k}={_term(v, 60)}" for k, v in row.items()))
    return 0


def _views(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    for graph, views in ((ctx.community_graph, node_ui_views.COMMUNITY_VIEWS), (ctx.verified_graph, node_ui_views.VERIFIED_VIEWS)):
        if not graph:
            continue
        node_routes.write_query_catalog(ctx.client, graph, node_ui_views.catalog_quads(views, graph))
        print(f"installed {len(views)} saved view(s) for {graph}")
    return 0


# -- write verbs -----------------------------------------------------------------


def _propose(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    store = ProposalStore()
    if args.promote:
        proposal = _propose_promotion(ctx, store, args)
    elif args.verdict:
        kind = CuratorStatement(f"blackbox.{args.verdict[0]}")
        fields = {"reason": args.reason} if args.reason else {}
        proposal = verbs.propose_statement(ctx, store, kind=kind, identifier=args.verdict[1], fields=fields, evidence=args.evidence)
    elif args.kill_list:
        with open(args.kill_list, encoding="utf-8") as handle:
            proposal = verbs.propose_kill_list(ctx, store, entries=json.load(handle))
    elif args.attest:
        proposal = verbs.propose_statement(ctx, store, kind=CuratorStatement.ATTESTATION, identifier=args.attest[1],
                                           fields={"stage": args.attest[0]}, evidence=args.evidence)
    elif args.nominate:
        fields = {"listed": "no" if args.delist else "yes", "class": args.author_class, "org": args.org,
                  "expires": args.expires, "address": args.address.lower()}
        proposal = verbs.propose_statement(ctx, store, kind=CuratorStatement.COUNTED_AUTHORS,
                                           identifier=f"author:{args.nominate.lower()}", fields=fields)
    else:
        proposal = verbs.propose_statement(ctx, store, kind=CuratorStatement.PAUSE, identifier="curator",
                                           fields={"until": args.until})
    print(f"proposed {proposal.id} ({proposal.kind} · {_term(proposal.identifier, 80)})")
    if args.to:
        result = verbs.send(ctx, proposal, args.to)
        print(f"sent to {_term(args.to, 60)}: delivered={result.get('delivered')}")
    else:
        print("not sent: pass --to <peer> to hand it to the second curator")
    return 0


def _propose_promotion(ctx: CurateContext, store: ProposalStore, args: argparse.Namespace):
    read = community.read_verified_reports(ctx.client, ctx.cfg)
    subjects = [r.subject for r in read.reports if r.identifier == args.promote] if read.available else []
    return verbs.propose_promotion(ctx, store, identifier=args.promote, severity=args.severity, evidence=args.evidence,
                                   reason=args.reason, report_subjects=subjects, name=args.name)


def _inbox(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    store = ProposalStore()
    received = transport.receive_proposals(ctx.client, transport.InboxCursor())
    for proposal in received:
        store.save(proposal)
        print(f"received {proposal.id} ({proposal.kind} · {_term(proposal.identifier, 80)})")
    if not received:
        print("no new proposals")
    return 0


def _approve(args: argparse.Namespace) -> int:
    proposal, outcome = verbs.approve(_ctx(args), ProposalStore(), args.proposal_id, evidence=args.evidence,
                                      typed_code=args.code, yes=args.yes, root=args.root)
    print(f"{proposal.id}: {outcome}")
    return 0 if proposal.state is ProposalState.PUBLISHED or "published" in outcome else 2


def _publish(args: argparse.Namespace) -> int:
    proposal, outcome = verbs.publish(_ctx(args), ProposalStore(), args.proposal_id, typed_code=args.code, yes=args.yes)
    print(f"{proposal.id}: {outcome}")
    return 0 if outcome.startswith("published") else 2


def _reject(args: argparse.Namespace) -> int:
    store = ProposalStore()
    proposal = store.get(args.proposal_id)
    if proposal is None:
        raise verbs.VerbError("no proposal with that id")
    store.save(proposal.transition(ProposalState.REJECTED, note="rejected locally"))
    print(f"{proposal.id}: rejected locally (nothing was sent)")
    return 0


def _manifest(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    if not ctx.sandbox:
        raise verbs.VerbError("this network has a pinned curator root; manifests come from the offline root (R7b)")
    proposal = verbs.manifest_proposal(ctx, ProposalStore(), curator_keys=args.curator_keys, threshold=args.threshold,
                                       promotion_author=args.promotion_author, root_epoch=args.root_epoch,
                                       version=args.version, legacy_uals=[])
    print(f"manifest staged as {proposal.id} (root {signing.public_key_hex(keys.root_key_store().load_or_create())[:16]}…); "
          f"run `blackbox curate publish {proposal.id} --yes`")
    return 0


def _watch(args: argparse.Namespace) -> int:
    ctx = _ctx(args)
    watcher = intake.IntakeWatcher()
    alarms = intake.AlarmWatcher()
    sink = intake.WebhookSink(args.webhook)
    while True:
        compiled = args.compiled_ruleset(ctx.cfg) if args.compiled_ruleset else None
        if compiled is not None:
            announced = watcher.poll(queue.delta_view(compiled.community, verified_identifiers(compiled)), sink)
            if announced:
                print(f"announced {len(announced)} new threat(s): " + ", ".join(_term(a, 60) for a in announced[:10]))
        delivered = alarms.poll(verbs.curator_alarms(ctx, compiled, today=_today(), now=time.time()), sink)   # R10b
        if delivered:
            print(f"delivered {len(delivered)} curator alarm(s)")
        if args.once:
            return 0
        time.sleep(max(5.0, args.interval))


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _outcome(args: argparse.Namespace) -> int:
    standing = verbs.record_outcome(args.key, confirmed=args.confirmed, day=args.day or _today(), novel=args.novel,
                                    strike=args.strike, first_seen_day=args.first_seen)
    print(f"recorded for {_term(args.key[:16], 16)}…: band {standing.band.value} · confirmed {standing.confirmed} · "
          f"rejected {standing.rejected} · strikes {standing.strikes} · novel {standing.novel_credits}")
    return 0


def _graduate(args: argparse.Namespace) -> int:
    today = _today()
    if args.erase:
        print("erased" if community.reputation.ReputationLedger().erase(args.erase) else "no ledger entry for that key")
        return 0
    if args.propose:
        if not args.address:
            print("--address is required with --propose (the agent address shown on the list)")
            return 2
        proposal = verbs.propose_graduation(_ctx(args), ProposalStore(), key=args.propose, address=args.address, today=today,
                                            cluster=args.cluster)
        print(f"proposed {proposal.id} ({proposal.kind} · {_term(proposal.identifier, 80)})")
        if args.to:
            result = verbs.send(_ctx(args), proposal, args.to)
            print(f"sent to {_term(args.to, 60)}: delivered={result.get('delivered')}")
        return 0
    rows = verbs.graduation_candidates(today)
    if not rows:
        print("the reputation ledger is empty")
        return 0
    for standing, score, action in rows:
        print(f"{standing.key[:16]}…  {standing.band.value:<11} rep {score:.2f}  confirmed {standing.confirmed} rejected "
              f"{standing.rejected} strikes {standing.strikes} novel {standing.novel_credits}  {action or '-'}")
    return 0


def _metrics(args: argparse.Namespace) -> int:
    snapshot = community.shadow.latest()
    if snapshot is None:
        print("no shadow snapshots yet (set `community_shadow: true`; one is written per refresh)")
    else:
        print(f"{snapshot.at}  community {snapshot.community_total} · already verified {snapshot.already_verified} "
              f"(delta share {snapshot.delta_share:.0%}) · reporters median {snapshot.reporters_median:.1f} · "
              f"days to corroborated median {snapshot.days_to_corroborated_median:.1f}")
        print(f"  stages: {snapshot.stages} · would enforce: {snapshot.would_enforce} · counted {snapshot.counted} / unlisted {snapshot.unlisted}")
    unlisted, counted, ratio = community.shadow.calibration_gap(community.reputation.ReputationLedger(), _today())
    print(f"  newcomer calibration: unlisted rejection {unlisted:.0%} vs counted {counted:.0%} → ratio {ratio:.2f}"
          + (" — REVIEW the graduation rule (gap > 2×)" if ratio > 2 else ""))
    return 0


_VERBS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "keys": _keys, "manifest": _manifest, "queue": _queue, "show": _show, "propose": _propose, "inbox": _inbox,
    "approve": _approve, "publish": _publish, "reject": _reject, "list": _list, "watch": _watch, "views": _views,
    "view": _view, "outcome": _outcome, "graduate": _graduate, "metrics": _metrics,
}
