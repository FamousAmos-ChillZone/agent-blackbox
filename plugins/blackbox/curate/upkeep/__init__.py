"""Upkeep — keeping an authority's word alive on the network (Community Curation C5).

Shared memory forgets after about 30 days, so what a curator published in the
community graph must be re-published, and readers must be able to tell a
silent curator from an absent one.

* :mod:`.published` — what this curator node published in the community graph
  and is still current; :func:`published.publish_due` re-publishes it once per
  keep-alive epoch under a new asset name with the same signed content.
* :mod:`.heartbeat` — one small signed statement per curator key: "this key
  is alive".

Import the submodule you need (``from .upkeep import published``); this
package deliberately imports nothing itself, because ``publishing`` uses
``published`` and ``heartbeat`` uses the verbs.
"""
