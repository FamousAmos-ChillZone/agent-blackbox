"""``blackbox attach`` / ``blackbox detach`` — and the report rows they print."""

from __future__ import annotations

import argparse
from typing import Any, Dict
from .. import attach


def add_attach_parsers(sub: argparse._SubParsersAction) -> None:
    """Register ``blackbox attach`` and ``blackbox detach`` on the CLI's sub-parsers
    (called once by ``cli.setup_cli``); the parsed namespaces go to :func:`cmd_attach`
    and :func:`cmd_detach`."""
    attach_p = sub.add_parser(
        "attach", help="Auto-protect every local Hermes home + OpenClaw workspace"
    )
    attach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    attach_p.add_argument("--hermes-only", action="store_true", help="Only attach to Hermes homes")
    attach_p.add_argument("--openclaw-only", action="store_true", help="Only attach to OpenClaw workspaces")
    attach_p.set_defaults(func=cmd_attach)

    detach_p = sub.add_parser("detach", help="Disable Blackbox in every local agent")
    detach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    detach_p.add_argument("--remove-files", action="store_true", help="Also delete copied plugin files")
    detach_p.add_argument("--hermes-only", action="store_true", help="Only detach from Hermes homes")
    detach_p.add_argument("--openclaw-only", action="store_true", help="Only detach from OpenClaw workspaces")
    detach_p.set_defaults(func=cmd_detach)


def cmd_attach(args: argparse.Namespace) -> int:
    do_hermes = not args.openclaw_only
    do_openclaw = not args.hermes_only
    report = attach.attach_all(hermes=do_hermes, openclaw=do_openclaw, dry_run=args.dry_run, explicit=True)
    prefix = "Would protect" if args.dry_run else "Protected"
    for row in report.get("hermes", []):
        print_hermes_attach_row(row, prefix)
    for row in report.get("openclaw", []):
        print_openclaw_attach_row(row, prefix)
    count = report.get("count", 0)
    if args.dry_run:
        print(f"\nDry run: Blackbox would watch {count} agent(s). Nothing was written.")
    else:
        print(f"\nBlackbox is watching {count} agent(s). Restart any running agent to activate.")
    return 0


def cmd_detach(args: argparse.Namespace) -> int:
    do_hermes = not args.openclaw_only
    do_openclaw = not args.hermes_only
    report = attach.detach_all(
        hermes=do_hermes, openclaw=do_openclaw, remove_files=args.remove_files, dry_run=args.dry_run
    )
    prefix = "Would detach" if args.dry_run else "Detached"
    for row in report.get("hermes", []):
        if row.get("error"):
            print(f"  ! {row['target']} (hermes): {row['error']}")
        elif row.get("already") and not row.get("removed"):
            print(f"  - {row['target']} (hermes): already detached")
        else:
            extra = ", files removed" if row.get("removed") else ""
            print(f"  {prefix} {row['target']} (hermes){extra}")
    for row in report.get("openclaw", []):
        if row.get("error"):
            print(f"  ! {row['target']} (openclaw): {row['error']}")
        elif row.get("already"):
            print(f"  - {row['target']} (openclaw): already detached")
        else:
            print(f"  {prefix} {row['target']} (openclaw)")
    print("\nBlackbox detached. Restart any running agent to apply.")
    return 0


def print_hermes_attach_row(row: dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (hermes): {row['error']}")
        return
    if row.get("already") and not row.get("copied"):
        print(f"  - {row['target']} (hermes): already protected")
        return
    bits = []
    if row.get("copied"):
        bits.append("plugin copied")
    if row.get("enabled"):
        bits.append("enabled")
    elif row.get("already"):
        bits.append("already enabled")
    detail = f" ({', '.join(bits)})" if bits else ""
    print(f"  {prefix} {row['target']} (hermes){detail}")


def print_openclaw_attach_row(row: dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (openclaw): {row['error']}")
        return
    if row.get("already"):
        print(f"  - {row['target']} (openclaw): already protected")
        return
    note = f"  note: {row['note']}" if row.get("note") else ""
    print(f"  {prefix} {row['target']} (openclaw){note}")
