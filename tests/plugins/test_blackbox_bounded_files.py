"""The kernel's bounded settings-file reader (kernel/bounded_files.py).

It answers the text of a small regular file, or None — quickly, whatever sits at
the path. The named-pipe case runs in a thread with a join timeout so a
regression fails the test instead of hanging the suite.
"""

from __future__ import annotations

import os
import sys
import threading

import pytest

from plugins.blackbox.kernel.bounded_files import read_small_text

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="Windows has no named pipes or O_NOFOLLOW in the file system")


def _within(seconds, call):
    """``(finished, result)`` of *call* run in a daemon thread for at most *seconds*."""
    outcome = []
    worker = threading.Thread(target=lambda: outcome.append(call()), daemon=True)
    worker.start()
    worker.join(seconds)
    return (not worker.is_alive(), outcome[0] if outcome else None)


def test_a_regular_file_is_read(tmp_path):
    path = tmp_path / "config.yml"
    path.write_bytes(b"\xef\xbb\xbfkeypair_path: /k.json\n")
    assert read_small_text(str(path), 1024) == "keypair_path: /k.json\n"


def test_a_missing_file_is_none(tmp_path):
    assert read_small_text(str(tmp_path / "absent.yml"), 1024) is None


def test_a_file_over_the_cap_is_none(tmp_path):
    path = tmp_path / "big.js"
    path.write_bytes(b"x" * 101)
    assert read_small_text(str(path), 100) is None
    assert read_small_text(str(path), 101) == "x" * 101


@POSIX_ONLY
def test_a_named_pipe_is_none_at_once(tmp_path):
    path = tmp_path / "prefs.js"
    os.mkfifo(path)
    finished, result = _within(1.0, lambda: read_small_text(str(path), 1024))
    assert finished, "reading a named pipe blocked"
    assert result is None


@POSIX_ONLY
def test_a_symlink_is_refused_only_when_asked(tmp_path):
    target = tmp_path / "real.js"
    target.write_text("hello", encoding="utf-8")
    link = tmp_path / "prefs.js"
    link.symlink_to(target)
    assert read_small_text(str(link), 1024, nofollow=True) is None
    assert read_small_text(str(link), 1024) == "hello"


def test_a_folder_is_none(tmp_path):
    assert read_small_text(str(tmp_path), 1024) is None
