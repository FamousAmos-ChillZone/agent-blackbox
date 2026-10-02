"""What every `blackbox curate` verb needs resolved once (Refine R6).

:class:`CurateContext` holds the config, the node client, the network id, the
trusted curator view (key manifest, counted authors, verdicts), whether this
network is a SANDBOX (no pinned curator root — consent by ``--yes`` allowed),
and the compiled ruleset the composition root injected (the ruleset depends
on this package, never the reverse).

Pattern: a Facade over the kernel + community pieces the verbs use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .. import community
from ..kernel import constants
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient
from ..kernel.signing.key_manifest import KeyManifest

#: cfg -> the compiled Ruleset (injected by cli.py).
CompiledRuleset = Callable[[Any], Any]


@dataclass(frozen=True)
class CurateContext:
    cfg: BlackboxConfig
    client: DkgClient
    environment: str
    view: community.CuratorView
    sandbox: bool
    compiled: Optional[Any]

    @property
    def manifest(self) -> Optional[KeyManifest]:
        return self.view.manifest

    @property
    def verified_graph(self) -> str:
        return self.cfg.context_graph_id

    @property
    def community_graph(self) -> str:
        return self.cfg.community_graph_id


def build_context(compiled_ruleset: Optional[CompiledRuleset]) -> CurateContext:
    """Resolve the context from the live node. The node must be reachable."""
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    environment = community.network_environment(client.status())
    view = community.read_curator_view(client, cfg, environment)
    sandbox = not constants.CURATOR_ROOT_KEYS.get(environment)
    compiled = compiled_ruleset(cfg) if compiled_ruleset is not None else None
    return CurateContext(cfg=cfg, client=client, environment=environment, view=view, sandbox=sandbox, compiled=compiled)


def verified_identifiers(compiled: Any) -> set:
    """Identifiers the verified tier already lists (the delta view's "already verified")."""
    if compiled is None:
        return set()
    return {str(rule.get("identifier") or "") for _category, rule in compiled.iter_rules() if rule.get("source") == "public"}
