"""Trust anchors — which root keys this node trusts.

A root key signs one thing: the key manifest that names the curator keys
(:mod:`.key_manifest`). This module answers "which roots may do that here".
Roots are pinned in code per network (``constants.CURATOR_ROOT_KEYS``); only a
network with no pinned root (a sandbox) may take roots from the
``BLACKBOX_CURATOR_ROOT_KEYS`` environment variable. The root is deliberately
NOT a config-file setting, so a config edit can never move trust.

Usage::

    from ..kernel.signing import trust_anchors
    roots = trust_anchors.trusted_roots(environment)      # frozenset of 64-hex public keys
"""

from __future__ import annotations

import os
import re
from typing import FrozenSet, Mapping

from .. import constants

_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_ROOT_ENV = "BLACKBOX_CURATOR_ROOT_KEYS"


def trusted_roots(environment: str, env: Mapping[str, str] = os.environ) -> FrozenSet[str]:
    """The curator root keys *environment* (a DKG network id) trusts: the
    pinned ones, else (sandbox networks only) those in the environment
    variable. Malformed keys are ignored."""
    pinned = constants.CURATOR_ROOT_KEYS.get(environment)
    if pinned:
        return frozenset(k.lower() for k in pinned if _KEY_HEX.fullmatch(k.lower()))
    raw = env.get(_ROOT_ENV, "")
    return frozenset(k.strip().lower() for k in raw.split(",") if _KEY_HEX.fullmatch(k.strip().lower()))
