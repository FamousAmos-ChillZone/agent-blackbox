"""Trust anchors — which root keys this node trusts, per authority.

A root key signs one thing: the key manifest that names the curator keys
(:mod:`.key_manifest`). This module answers "which roots may do that here".
There are two authorities (:mod:`.authority`) and their roots are NEVER
interchangeable:

* VERIFIED roots are pinned per NETWORK (``constants.CURATOR_ROOT_KEYS``).
* COMMUNITY roots are pinned per COMMUNITY GRAPH (:data:`COMMUNITY_ROOT_KEYS`):
  a community root is trusted for the one graph it is pinned to and nothing
  else. A graph's entry lists its root and its pre-agreed backup root, so a
  lost or exposed root is replaced by a manifest, not by an emergency release.

Only an UNPINNED network or graph (a development setup) may take roots from the
environment (``BLACKBOX_CURATOR_ROOT_KEYS`` / ``BLACKBOX_COMMUNITY_ROOT_KEYS``);
a pinned one ignores the variable. A root is deliberately NOT a config-file
setting, so a config edit can never move trust: pointing the config at another
graph selects that graph's pin, or no root at all.

Usage::

    from ..kernel.signing import trust_anchors
    trust_anchors.trusted_roots(environment)             # verified authority, by network id
    trust_anchors.community_roots(community_graph_id)    # community authority, by graph id
    trust_anchors.community_root_pinned(graph_id)        # True: the env variable is ignored
"""

from __future__ import annotations

import os
import re
from typing import FrozenSet, Mapping, Tuple

from .. import constants

_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_ROOT_ENV = "BLACKBOX_CURATOR_ROOT_KEYS"
_COMMUNITY_ROOT_ENV = "BLACKBOX_COMMUNITY_ROOT_KEYS"

#: Community roots pinned per community graph id: ``{graph id: (root, backup root)}``.
#: Empty until launch — the pin ships as ONE unit with the default community
#: graph id and its owner peer id (``constants.DEFAULT_COMMUNITY_GRAPH_ID`` /
#: ``DEFAULT_COMMUNITY_GRAPH_PEER_ID``).
COMMUNITY_ROOT_KEYS: Mapping[str, Tuple[str, ...]] = {}


def _keys(values) -> FrozenSet[str]:
    """Well-formed keys only (64 lower-case hex); malformed ones are ignored."""
    return frozenset(k.strip().lower() for k in values if _KEY_HEX.fullmatch(k.strip().lower()))


def trusted_roots(environment: str, env: Mapping[str, str] = os.environ) -> FrozenSet[str]:
    """The curator root keys *environment* (a DKG network id) trusts: the
    pinned ones, else (sandbox networks only) those in the environment
    variable. Malformed keys are ignored."""
    pinned = constants.CURATOR_ROOT_KEYS.get(environment)
    if pinned:
        return frozenset(k.lower() for k in pinned if _KEY_HEX.fullmatch(k.lower()))
    raw = env.get(_ROOT_ENV, "")
    return frozenset(k.strip().lower() for k in raw.split(",") if _KEY_HEX.fullmatch(k.strip().lower()))


def community_root_pinned(graph_id: str) -> bool:
    """True when *graph_id* has pinned community roots (the environment is then ignored)."""
    return bool(COMMUNITY_ROOT_KEYS.get(graph_id))


def community_roots(graph_id: str, env: Mapping[str, str] = os.environ) -> FrozenSet[str]:
    """The community root keys trusted for the community graph *graph_id*: the
    pinned ones, else (unpinned graphs only) those in
    ``BLACKBOX_COMMUNITY_ROOT_KEYS``. No graph id, no root."""
    if not graph_id:
        return frozenset()
    pinned = COMMUNITY_ROOT_KEYS.get(graph_id)
    if pinned:
        return _keys(pinned)
    return _keys(env.get(_COMMUNITY_ROOT_ENV, "").split(","))
