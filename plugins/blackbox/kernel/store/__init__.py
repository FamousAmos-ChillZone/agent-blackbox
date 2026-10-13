"""Store — read-only SPARQL access to the DKG node's LOCAL triple store.

A kernel sub-package (the kernel folder reached its file alarm). Why it
exists: the node's ``/api/query`` evaluates a query against a memory view
and answers an exact one-threat lookup in about 2 s; the store it reads from
(Oxigraph or Blazegraph, on loopback) answers the same lookup in about 2 ms
(bench bb-swm-c, DKG 10.0.23, 2026-10-10). The hot path asks the store.

* :class:`StoreClient` — ``select(sparql)`` with a hard timeout.
* :class:`StoreAnswer` — the three-outcome result: rows, or could-not-tell.
* :func:`loopback_store_url` — the store endpoint the node reports, accepted
  only when it is on this machine.

Usage::

    from ..kernel.store import StoreClient, loopback_store_url
    client = StoreClient(loopback_store_url(node_status))
    answer = client.select("SELECT ?s WHERE { ... } LIMIT 10")
    if answer.known: rows = answer.rows
"""

from .client import LOOKUP_TIMEOUT_SECONDS, StoreAnswer, StoreClient, loopback_store_url

__all__ = ["LOOKUP_TIMEOUT_SECONDS", "StoreAnswer", "StoreClient", "loopback_store_url"]
