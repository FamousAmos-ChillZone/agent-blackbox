"""The DKG node's process limits (sync/process_limits.py).

The heap-sizing tests moved here from tests/scripts/test_blackbox_dkg_runtime_fingerprint.py
together with the code; the rest pin the recorded limits and that every
Blackbox-driven node restart relaunches with them (PR #21 runtime-safety gap).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.sync import managed_node
from plugins.blackbox.sync import process_limits as LIMITS

REPO = Path(__file__).resolve().parents[2]


def test_dkg_heap_uses_smallest_host_or_cgroup_limit():
    gb = 1024**3
    with (
        mock.patch.object(LIMITS, "read_cgroup_memory_limit", return_value=4 * gb),
        mock.patch.object(LIMITS, "read_physical_memory", return_value=48 * gb),
    ):
        assert LIMITS.resolve_dkg_heap_mb() == 3072

    with (
        mock.patch.object(LIMITS, "read_cgroup_memory_limit", return_value=None),
        mock.patch.object(LIMITS, "read_physical_memory", return_value=48 * gb),
    ):
        assert LIMITS.resolve_dkg_heap_mb() == 8192


def test_node_options_merge_preserves_flags_and_explicit_heap():
    assert LIMITS.merge_node_options("--enable-source-maps", 8192) == (
        "--enable-source-maps --max-old-space-size=8192"
    )
    assert LIMITS.merge_node_options("--max-old-space-size=12288", 8192) == (
        "--max-old-space-size=12288"
    )
    assert LIMITS.merge_node_options("--max_old_space_size 6144", 8192) == (
        "--max_old_space_size 6144"
    )


# --- the recorded limits and every Blackbox restart (PR #21 runtime-safety gap) ---


def test_recorded_limits_read_back_exactly(tmp_path):
    limits = LIMITS.ProcessLimits(heap_mb=6144, store_queue_limit=256, list_context_graphs_projection=False)

    LIMITS.write_process_limits(str(tmp_path), limits)

    assert LIMITS.read_process_limits(str(tmp_path)) == limits


@pytest.mark.parametrize("content", [
    "not json",
    json.dumps({"version": 2, "limits": {"heap_mb": 1, "store_queue_limit": 1, "list_context_graphs_projection": True}}),
    json.dumps({"version": 1, "limits": {"heap_mb": 0, "store_queue_limit": 1, "list_context_graphs_projection": True}}),
    json.dumps({"version": 1, "limits": {"heap_mb": "4096", "store_queue_limit": 1, "list_context_graphs_projection": True}}),
    json.dumps({"version": 1, "limits": {"heap_mb": 4096, "store_queue_limit": 1, "list_context_graphs_projection": 1}}),
    json.dumps({"version": 1, "limits": {"heap_mb": 4096, "store_queue_limit": 1, "list_context_graphs_projection": True, "extra": 1}}),
    "{" + " " * 5000 + "}",
])
def test_a_record_that_is_not_exactly_well_formed_is_ignored(tmp_path, content):
    (tmp_path / LIMITS.PROFILE_NAME).write_text(content, encoding="utf-8")

    assert LIMITS.read_process_limits(str(tmp_path)) is None


def test_no_record_reads_as_none(tmp_path):
    assert LIMITS.read_process_limits(str(tmp_path)) is None


def test_an_invalid_record_is_never_written(tmp_path):
    with pytest.raises(LIMITS.ProcessLimitsError):
        LIMITS.write_process_limits(str(tmp_path), LIMITS.ProcessLimits(0, 512, True))
    assert not (tmp_path / LIMITS.PROFILE_NAME).exists()


def test_defaults_are_the_installers_and_an_explicit_heap_wins():
    with mock.patch.object(LIMITS, "resolve_dkg_heap_mb", return_value=6000):
        assert LIMITS.default_process_limits() == LIMITS.ProcessLimits(6000, 512, True)
        assert LIMITS.default_process_limits("--enable-source-maps --max-old-space-size=3000").heap_mb == 3000


def test_applied_limits_fill_the_launch_environment():
    env = {"NODE_OPTIONS": "--enable-source-maps"}

    LIMITS.apply_process_limits(env, LIMITS.ProcessLimits(4096, 256, False))

    assert env["NODE_OPTIONS"] == "--enable-source-maps --max-old-space-size=4096"
    assert env["DKG_STORE_QUEUE_LIMIT"] == "256"
    assert env["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "0"


def test_values_the_environment_already_carries_win():
    env = {"NODE_OPTIONS": "--max-old-space-size=2048", "DKG_STORE_QUEUE_LIMIT": "64",
           "DKG_LIST_CONTEXT_GRAPHS_PROJECTION": "1"}

    LIMITS.apply_process_limits(env, LIMITS.ProcessLimits(8192, 512, False))

    assert env == {"NODE_OPTIONS": "--max-old-space-size=2048", "DKG_STORE_QUEUE_LIMIT": "64",
                   "DKG_LIST_CONTEXT_GRAPHS_PROJECTION": "1"}


def _restart_environment(tmp_path, monkeypatch):
    for name in ("NODE_OPTIONS", "DKG_STORE_QUEUE_LIMIT", "DKG_LIST_CONTEXT_GRAPHS_PROJECTION"):
        monkeypatch.delenv(name, raising=False)
    cfg = BlackboxConfig(dkg_home=str(tmp_path), dkg_bin=str(tmp_path / "dkg"))
    return managed_node._dkg_sync_environment(cfg)


def test_a_blackbox_restart_relaunches_the_node_with_its_recorded_limits(tmp_path, monkeypatch):
    LIMITS.write_process_limits(str(tmp_path), LIMITS.ProcessLimits(3000, 256, False))

    env = _restart_environment(tmp_path, monkeypatch)

    assert "--max-old-space-size=3000" in env["NODE_OPTIONS"]
    assert env["DKG_STORE_QUEUE_LIMIT"] == "256"
    assert env["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "0"


def test_a_node_installed_before_the_record_restarts_with_the_installers_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(LIMITS, "resolve_dkg_heap_mb", lambda ceiling=8192: 5000)

    env = _restart_environment(tmp_path, monkeypatch)

    assert "--max-old-space-size=5000" in env["NODE_OPTIONS"]
    assert env["DKG_STORE_QUEUE_LIMIT"] == "512"
    assert env["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "1"


def test_an_unsizeable_host_restarts_without_limits_instead_of_failing(tmp_path, monkeypatch, caplog):
    def too_small(ceiling=8192):
        raise LIMITS.ProcessLimitsError("effective memory limit is too small for DKG")

    monkeypatch.setattr(LIMITS, "resolve_dkg_heap_mb", too_small)

    env = _restart_environment(tmp_path, monkeypatch)

    assert "max-old-space-size" not in env.get("NODE_OPTIONS", "")
    assert "process limits unavailable" in caplog.text


@pytest.mark.parametrize("installer", ["scripts/blackbox-install.sh", "scripts/blackbox-install.ps1"])
def test_both_installers_record_the_limits_they_chose(installer):
    text = (REPO / installer).read_text(encoding="utf-8")

    assert "write-limits" in text
