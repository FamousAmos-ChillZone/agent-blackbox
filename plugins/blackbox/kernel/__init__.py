"""Kernel — shared infrastructure owned by no feature.

Every feature package may import these modules directly; the kernel never
imports a feature (enforced by tests/plugins/test_blackbox_architecture.py).

* :mod:`.constants` — ontology IRIs (byte-stable with the published corpus),
  defaults, severity ladder, home-directory helpers.
* :mod:`.config` — :class:`~.config.BlackboxConfig`, the frozen settings object.
* :mod:`.settings` — validate-then-persist for the user-tunable settings (the
  dashboard gear page and ``setup-llm`` write through it).
* :mod:`.dkg_client` — the ONLY module that speaks HTTP to the local DKG node.
* :mod:`.dkg_version` — installed-node version check (run by the installers as
  ``python -m plugins.blackbox.kernel.dkg_version``).
* :mod:`.redaction` — THE secret-value patterns and redactor (G1).
* :mod:`.identity` — this node's reporting identity (agent address; fails closed).
* :mod:`.threat_ids` — deterministic threat identifiers and URIs.
* :mod:`.rdf_terms` — N-Triples terms, ``Quad``, literal size caps.
* :mod:`.sparql_text` — THE SPARQL string escaper and the row ceiling.
* :mod:`.yaml_files` — safe YAML config read/write (atomic).
* :mod:`.display_safety` — terminal-safe printing of untrusted text.

Usage: ``from ..kernel import constants`` / ``from ..kernel.config import load_blackbox_config``.
"""
