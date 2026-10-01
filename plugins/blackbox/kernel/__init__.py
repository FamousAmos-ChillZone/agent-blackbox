"""Kernel — shared infrastructure owned by no feature.

Every feature package may import these modules; the kernel never imports a
feature (enforced by tests/plugins/test_blackbox_architecture.py).

* :mod:`.constants` — ontology IRIs (byte-stable with the published corpus),
  defaults, severity ladder, home-directory helpers.
* :mod:`.config` — :class:`~.config.BlackboxConfig`, the frozen settings object.
* :mod:`.dkg_client` — the ONLY module that speaks HTTP to the local DKG node.
* :mod:`.dkg_version` — installed-node version check (run by the installers as
  ``python -m plugins.blackbox.kernel.dkg_version``).

Usage: ``from ..kernel import constants`` / ``from ..kernel.config import load_blackbox_config``.
"""
