"""kill_and_reap: a killed sandbox client is reaped even when a grandchild keeps its pipes open."""
from __future__ import annotations

import subprocess
import sys
import time

import pytest

from threat_lab import sandbox


@pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX shell to leave a grandchild holding the pipe")
def test_kill_and_reap_returns_when_a_grandchild_holds_the_pipes(monkeypatch):
    monkeypatch.setattr(sandbox, "_KILL_TIMEOUT_SECONDS", 0.5)
    process = subprocess.Popen(["sh", "-c", "sleep 30 & sleep 30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        started = time.monotonic()
        sandbox.kill_and_reap(process)
        assert process.returncode is not None
        assert time.monotonic() - started < 5
    finally:
        for stream in (process.stdout, process.stderr):
            if stream:
                stream.close()


def test_kill_and_reap_reaps_an_ordinary_child():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], stdout=subprocess.PIPE)
    sandbox.kill_and_reap(process)
    assert process.returncode is not None
