"""G5 regression: the in-memory ruleset cache checks and reloads in ONE step.

Before RulesetCache (2026-10-01) the stale-stamp check and the disk reload
took the lock separately, so two threads that both saw a replaced cache file
both reloaded it, and a reader still holding the old file's contents could
overwrite a generation refresh() had just stored.
"""

from __future__ import annotations

import threading

from plugins.blackbox.ruleset import refresh_cycle
from plugins.blackbox.ruleset.compiler import Ruleset
from plugins.blackbox.ruleset.memory_cache import RulesetCache


class _SlowDisk:
    """A cache file whose read blocks until released; counts reads."""

    def __init__(self, contents: Ruleset, stamp: int = 1) -> None:
        self.contents = contents
        self.stamp = stamp
        self.reads = 0
        self.reading = threading.Event()
        self.release = threading.Event()

    def load(self):
        self.reads += 1
        self.reading.set()
        assert self.release.wait(5)
        return self.contents


def _start(target) -> threading.Thread:
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread


def test_concurrent_readers_of_a_replaced_file_reload_once():
    disk = _SlowDisk(Ruleset(synced_at=1.0))
    cache = RulesetCache(stamp=lambda: disk.stamp, load=disk.load)
    results = []
    readers = [_start(lambda: results.append(cache.current())) for _ in range(4)]
    assert disk.reading.wait(5)
    disk.release.set()
    for reader in readers:
        reader.join(5)
    assert disk.reads == 1
    assert all(r is disk.contents for r in results)


def test_a_slow_reader_never_overwrites_a_newer_stored_generation():
    old = Ruleset(synced_at=1.0)
    new = Ruleset(synced_at=2.0)
    disk = _SlowDisk(old)
    cache = RulesetCache(stamp=lambda: disk.stamp, load=disk.load)
    reader = _start(cache.current)
    assert disk.reading.wait(5)               # reader is mid-load of the OLD file
    storer = _start(lambda: cache.store(new))  # refresh() installs a newer generation
    disk.release.set()
    reader.join(5)
    storer.join(5)
    assert cache.memory_only() is new


def test_unchanged_file_is_served_from_memory():
    disk = _SlowDisk(Ruleset())
    disk.release.set()
    cache = RulesetCache(stamp=lambda: disk.stamp, load=disk.load)
    first = cache.current()
    assert cache.current() is first
    assert disk.reads == 1


def test_failed_reload_keeps_the_generation_in_memory():
    held = Ruleset(synced_at=5.0)
    stamp = {"value": 1}
    cache = RulesetCache(stamp=lambda: stamp["value"], load=lambda: None)
    cache.store(held)
    stamp["value"] = 2                       # file replaced but unreadable
    assert cache.current() is held


def test_module_readers_share_one_reload(monkeypatch):
    disk = _SlowDisk(Ruleset(synced_at=3.0))
    monkeypatch.setattr(refresh_cycle, "_cache_file_stamp", lambda: disk.stamp)
    monkeypatch.setattr(refresh_cycle.disk_cache, "_read_cache", disk.load)
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    readers = [_start(lambda: refresh_cycle._latest_cached_ruleset("")) for _ in range(3)]
    assert disk.reading.wait(5)
    disk.release.set()
    for reader in readers:
        reader.join(5)
    assert disk.reads == 1
