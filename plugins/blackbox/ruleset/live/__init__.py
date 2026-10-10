"""Live verified lookups — the graph is the rule store (DKG-lookup build).

WHY (KI-322): compiling every verified dependency / IOC rule into
``ruleset.json`` made that file 352 MB on a fully synced node; one load cost
1.4 GB and 3.7 s, every process paid it, and 8 GB machines ran out of memory.
The rules already live in the DKG node's local store, which answers an exact
lookup in about 2 ms. So the hot path asks the store at check time, and only a
small scope travels in ``ruleset.json``.

* :class:`VerifiedScope` — what a lookup may believe: the owner-pinned confirmed
  assertion graphs, suppressed subjects, curator-revoked identifiers, the
  mixed-case package spellings, and the store endpoint. Rebuilt every refresh.
* :func:`refresh_scope` / :func:`scope_for_generation` — build the next scope
  from the node (fail-open: a part that could not be read keeps its previous
  value); the refresh cycle calls the latter on every path.
* :class:`VerifiedLookup` — exact dependency / IOC lookups against the store,
  answered as :class:`LookupAnswer` with three outcomes (``HIT``, ``CLEAN``,
  ``COULD_NOT_TELL``). Rows come back as triples and go through the SAME
  row builder and row adapters that compiled today's rules, so a verdict is
  byte-identical to the compiled one (bench 2026-10-10: 60/60 sampled rules).

Usage::

    lookup = VerifiedLookup(rs.verified_scope, StoreClient(rs.verified_scope.store_url))
    answer = lookup.dependencies([("npm", "wallet-security-checker", "2.0.3")])
    answer.rules            # {"npm:wallet-security-checker@2.0.3": rule}
    answer.outcome          # HIT | CLEAN | COULD_NOT_TELL
"""

from .lookup import CLEAN, COULD_NOT_TELL, HIT, LookupAnswer, VerifiedLookup
from .scope import VerifiedScope, refresh_scope, scope_for_generation

__all__ = ["CLEAN", "COULD_NOT_TELL", "HIT", "LookupAnswer", "VerifiedLookup", "VerifiedScope", "refresh_scope", "scope_for_generation"]
