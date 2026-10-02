"""The curator's keys and private working directory (Refine R6).

A curator machine holds ONE curator key (one of the manifest's 2-of-3) at
``$BLACKBOX_HOME/curate/curator_key.pem``. In the SANDBOX a machine may also
hold a root key (``root_key.pem``) to sign key manifests; on a real network the
root is an offline, pre-rotated, custodian-split key (R7b) and never lives in
this directory. Both reuse the reporter key store's one-owner, atomic,
owner-only file discipline — there is one key-file implementation.

Usage::

    store = keys.curator_key_store()          # ReporterKeyStore at the curator path
    key = store.load_or_create()
"""

from __future__ import annotations

from pathlib import Path

from ..kernel import constants, reporter_key

CURATOR_KEY_FILE = "curator_key.pem"
ROOT_KEY_FILE = "root_key.pem"


def curate_home() -> Path:
    """``$BLACKBOX_HOME/curate`` — proposals, consent ledger, intake memory, keys."""
    return constants.blackbox_home() / "curate"


def curator_key_store() -> reporter_key.ReporterKeyStore:
    return reporter_key.ReporterKeyStore(curate_home() / CURATOR_KEY_FILE)


def root_key_store() -> reporter_key.ReporterKeyStore:
    """SANDBOX ONLY: a locally held root key. Real roots stay offline (R7b)."""
    return reporter_key.ReporterKeyStore(curate_home() / ROOT_KEY_FILE)
