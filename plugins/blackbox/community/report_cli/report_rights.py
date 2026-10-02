"""The operator's rights over this node's reporter identity (Refine R1).

Three local verbs of ``blackbox report``. None needs the DKG node, and none
sends anything:

* ``--export PATH`` — a machine-readable JSON copy of this node's statements
  (the share ledger: reports, disputes, retractions and their outcomes) plus
  a BACKUP of the reporter key, so a reinstall does not silently drop a
  counted author. The file holds the private key: it is written owner-only
  (0600), never over an existing file, and the command says so.
* ``--restore-key PATH`` — install the key from such an export (or a bare
  PEM). It refuses to replace a different existing key, which would silently
  change this node's identity.
* ``--erase-identity --confirm`` — destroy the reporter key and the local
  share records. The next report starts a new, unlinked identity. What was
  already shared stays on the network (a shared graph cannot delete it), and
  the command says so; retract first to stop old reports counting.

Usage (from :func:`.report_command.cmd_report`)::

    if report_rights.wants_local_verb(args):
        return report_rights.run_local_verb(args)
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from ... import audit
from ...kernel import display_safety, reporter_key, signing

#: Identifies an export file and its layout version.
EXPORT_FORMAT = "blackbox-reporter-export"
EXPORT_VERSION = 1
#: Ledger rows an export carries (the ledger itself is size-capped).
_EXPORT_LEDGER_ROWS = 100_000


def wants_local_verb(args: argparse.Namespace) -> bool:
    """True when *args* ask for one of this module's verbs."""
    return bool(getattr(args, "export", None) or getattr(args, "restore_key", None)
                or getattr(args, "erase_identity", False))


def run_local_verb(args: argparse.Namespace) -> int:
    """Run the requested verb; returns the process exit code."""
    store = reporter_key.ReporterKeyStore()
    if args.export:
        return export_identity(store, Path(args.export).expanduser())
    if args.restore_key:
        return restore_key(store, Path(args.restore_key).expanduser())
    return erase_identity(store, confirmed=bool(args.confirm))


def export_document(store: reporter_key.ReporterKeyStore) -> Dict[str, Any]:
    """The export as a dict: format, time, signer name, key backup, ledger."""
    pem = store.export_pem().decode("ascii")
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "reporter_public_key": signing.public_key_hex(store.load_or_create()),
        "reporter_key_pem": pem,
        "statements": audit.read_share_ledger(limit=_EXPORT_LEDGER_ROWS),
    }


def export_identity(store: reporter_key.ReporterKeyStore, path: Path) -> int:
    """``--export PATH``: write the export, owner-only, never overwriting."""
    try:
        document = export_document(store)
    except reporter_key.ReporterKeyError as exc:
        print(f"Nothing to export: {exc}")
        return 2
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"Refusing to overwrite {display_safety.term_safe(str(path))} — choose a new file.")
        return 2
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
    print(f"Exported {len(document['statements'])} statement record(s) and a key backup to "
          f"{display_safety.term_safe(str(path))}")
    print("This file contains your reporter PRIVATE KEY: anyone holding it can sign as this node.")
    print("Keep it offline; restore it with `blackbox report --restore-key FILE` after a reinstall.")
    return 0


def restore_key(store: reporter_key.ReporterKeyStore, path: Path) -> int:
    """``--restore-key PATH``: install the key from an export or a PEM file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"Cannot read {display_safety.term_safe(str(path))}: {exc.strerror}")
        return 2
    pem = _pem_from(raw)
    try:
        signer = store.install_pem(pem)
    except reporter_key.ReporterKeyError as exc:
        print(f"Key not restored: {exc}")
        return 2
    print(f"Reporter key restored (signer {signer[:16]}…). Reports you sent before keep counting as yours.")
    return 0


def _pem_from(raw: bytes) -> bytes:
    """The PEM inside an export document, or *raw* itself (a bare PEM file)."""
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return raw
    if isinstance(document, dict) and document.get("format") == EXPORT_FORMAT:
        return str(document.get("reporter_key_pem") or "").encode("ascii")
    return raw


def erase_identity(store: reporter_key.ReporterKeyStore, *, confirmed: bool) -> int:
    """``--erase-identity``: destroy the key and local share records (needs --confirm)."""
    if not confirmed:
        print("This destroys this node's reporter key and its local record of what it shared.")
        print("Reports already shared stay on the network — a shared graph cannot delete them. To stop")
        print("them counting, `blackbox report --retract IDENTIFIER` each one BEFORE erasing (afterwards")
        print("this node can no longer sign as their author). Keep a copy first with `--export FILE`.")
        print("Run again with --confirm to erase. Nothing was changed.")
        return 2
    had_key = store.erase()
    records = audit.erase_share_records()
    print(f"Erased: reporter key {'removed' if had_key else '(none present)'}; {records} local share record file(s).")
    print("Your next report starts a new reporter identity.")
    return 0
