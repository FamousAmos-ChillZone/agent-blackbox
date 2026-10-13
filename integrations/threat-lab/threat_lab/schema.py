"""The evidence contract, loaded by file path from the plugin — one schema, no copy.

The lab runner is a separate deployable (proposal §03.5, D28), not plugin code:
it imports NOTHING from ``plugins.blackbox``. The one exception is this by-path
load of ``plugins/blackbox/curate/lab/evidence_schema.py`` (a standard-library
only module), the way ``scripts/blackbox-dkg-runtime-fingerprint.py`` loads
``sync/process_limits.py``. A runner test fails on any other plugin import.

On the lab host the file is deployed beside the runner; point
``THREAT_LAB_EVIDENCE_SCHEMA`` at it. Without the variable the in-repo path is
used. A missing file stops the runner at import (fail closed): without the
shared vocabulary it could write output the curator would refuse.

The lab never builds Evidence (the curator's extractor does); it uses the
schema for its closed note vocabulary and its key and digest rules.

Usage::

    from threat_lab.schema import evidence_schema
    evidence_schema.NoteCode.DEADLINE_REACHED.value; evidence_schema.is_job_key(key)
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

SCHEMA_PATH_VARIABLE = "THREAT_LAB_EVIDENCE_SCHEMA"
_IN_REPO_PATH = Path(__file__).resolve().parents[3] / "plugins" / "blackbox" / "curate" / "lab" / "evidence_schema.py"
_MODULE_NAME = "threat_lab_evidence_schema"


def schema_path() -> Path:
    """Where the evidence schema file is read from."""
    configured = os.environ.get(SCHEMA_PATH_VARIABLE, "").strip()
    return Path(configured) if configured else _IN_REPO_PATH


def _load():
    path = schema_path()
    if not path.is_file():
        raise ImportError(f"evidence schema not found at {path} (set {SCHEMA_PATH_VARIABLE})")
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, path)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the schema's dataclasses resolve their module by name.
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


evidence_schema = sys.modules.get(_MODULE_NAME) or _load()
