"""The DKG node's process limits (sync/process_limits.py): the V8 heap cap.

Moved from tests/scripts/test_blackbox_dkg_runtime_fingerprint.py together with
the code (the installer script now loads this module by path).
"""

from __future__ import annotations

from unittest import mock

from plugins.blackbox.sync import process_limits as LIMITS


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
