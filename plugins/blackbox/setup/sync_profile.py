"""Fresh Base profiles use registered cores; existing trust settings are retained."""
import os
from ..kernel import constants, yaml_files
from ..kernel.snapshot_config import REGISTERED_BASE_CORES, snapshot_config


def configure(args):
    graph_id = getattr(args, "snapshot_graph_id", None)
    peers = getattr(args, "trusted_core_peer", None)
    registered = getattr(args, "registered_cores", False)
    explicit = graph_id is not None or bool(peers) or registered
    path = constants.hermes_home() / "config.yaml"
    if yaml_files.yaml is None:
        raise ValueError("YAML support is required to configure snapshot sync")
    if path.is_symlink():
        raise ValueError("Configure the snapshot profile in the linked config file explicitly")
    try:
        data = yaml_files.yaml.safe_load(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
    except Exception as exc:
        raise ValueError("Existing config.yaml could not be read; it was not changed") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("Existing config.yaml must be a mapping")
    target = data
    for key in ("plugins", "entries", "blackbox"):
        target = target.setdefault(key, {})
        if not isinstance(target, dict):
            raise ValueError("Existing Blackbox configuration must be a mapping")
    if not explicit:
        # Re-running setup must not migrate an existing graph or trust mode.
        if any(key in target for key in ("context_graph_id", "detection_backend", "snapshot_sync", "dkg_home")):
            return
        if (os.environ.get("BLACKBOX_DKG_NETWORK", "mainnet-base") != "mainnet-base"
                or os.environ.get("BLACKBOX_CONTEXT_GRAPH_ID", constants.DEFAULT_CONTEXT_GRAPH_ID)
                != constants.DEFAULT_CONTEXT_GRAPH_ID):
            return
        registered, graph_id = True, "14"
    if registered and peers:
        raise ValueError("Choose registered cores or explicit peers, not both")
    if registered and graph_id is None:
        if target.get("context_graph_id", constants.DEFAULT_CONTEXT_GRAPH_ID) != constants.DEFAULT_CONTEXT_GRAPH_ID:
            raise ValueError("A custom graph requires --snapshot-graph-id")
        graph_id = "14"
    requested = {"detection_backend": "dkg", "snapshot_sync": {
        "on_chain_id": graph_id or "", "trusted_core_peers": peers or [], "mode": "core-cache",
        **({"source_policy": REGISTERED_BASE_CORES} if registered else {})}}
    snapshot_config(requested)
    existing = target.get("snapshot_sync")
    if existing is not None and existing != requested["snapshot_sync"]:
        raise ValueError("Existing snapshot trust differs; use a fresh profile for a different trust scope")
    target.update(requested)
    yaml_files.dump_yaml(path, data)
    print("Snapshot sync configured: chain statements come from the selected cores; "
          "asset identity and content roots are still verified. No automatic trust fallback.")
