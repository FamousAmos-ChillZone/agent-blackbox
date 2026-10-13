"""What a report says about the sighting beside its evidence (threat-profiles, 2026-10-12).

Every shared report carries, in closed vocabulary only: the host tool that met
the threat, what the agent was doing, blocked or flagged, how it was matched and
by which build, the verified rule it matched, and what the threat goes after
(goal, resource class at risk, ATT&CK technique). An injection found in a
fetched page also names the page's site (registrable domain only). Nothing comes
from the user's prompt, command, path or page text.

Public surface: :func:`sighting_fields`, :func:`canonical_tool`, :func:`classify`,
:class:`Classification`, :func:`injection_host_identifier`, and :mod:`.vocab`
(the closed sets, the shapes and the predicates).
"""

from __future__ import annotations

from . import vocab
from .classification import Classification, classify
from .fields import canonical_tool, sighting_fields
from .hosts import USER_CONTENT_PLATFORMS, injection_host_identifier

__all__ = ["Classification", "USER_CONTENT_PLATFORMS", "canonical_tool", "classify", "injection_host_identifier",
           "sighting_fields", "vocab"]
