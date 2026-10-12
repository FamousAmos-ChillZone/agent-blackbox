"""Raw artifacts are kept by sha256 for 90 days, then the retention sweep deletes them."""

from __future__ import annotations

import hashlib
import os
import time

from threat_lab.artifacts import ArtifactStore

DAY = 86_400


def _aged(store: ArtifactStore, data: bytes, days: float) -> str:
    digest = store.put(data)
    then = time.time() - days * DAY
    os.utime(store.path(digest), (then, then))
    return digest


def test_the_91_day_artifact_is_deleted_by_the_retention_sweep(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    old = _aged(store, b"ninety-one days old", 91)
    young = _aged(store, b"eighty-nine days old", 89)
    assert store.sweep() == [old]
    assert not store.path(old).exists()
    assert store.path(young).exists()


def test_an_artifact_is_named_by_its_sha256(tmp_path):
    store = ArtifactStore(tmp_path)
    digest = store.put(b"payload")
    assert digest == hashlib.sha256(b"payload").hexdigest()
    assert store.path(digest).read_bytes() == b"payload"


def test_storing_the_same_bytes_again_restarts_its_window(tmp_path):
    store = ArtifactStore(tmp_path)
    digest = _aged(store, b"seen again", 91)
    store.put(b"seen again")
    assert store.sweep() == []
    assert store.path(digest).exists()


def test_a_sweep_of_a_missing_folder_is_empty(tmp_path):
    assert ArtifactStore(tmp_path / "never-made").sweep() == []


def test_concurrent_stores_of_the_same_bytes_all_succeed(tmp_path):
    """FIX-0094: two jobs storing identical bytes at once (two level-4 runs with the
    same guest report, two downloads of the same page) raced on one shared
    ``.<sha256>.partial`` file — the second ``os.replace`` found it gone and the
    job FAILED for nothing. Every writer gets its own temporary file now."""
    import threading
    store = ArtifactStore(tmp_path / "artifacts")
    errors = []
    for round_number in range(5):
        data = f"the same bytes, round {round_number}".encode() * 2000
        writers = 8
        barrier = threading.Barrier(writers)

        def put() -> None:
            barrier.wait()
            try:
                store.put(data)
            except OSError as error:
                errors.append(error)

        threads = [threading.Thread(target=put) for _ in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert store.path(hashlib.sha256(data).hexdigest()).read_bytes() == data
    assert errors == []
    assert not list((tmp_path / "artifacts").glob(".*")), "no temporary file is left behind"
