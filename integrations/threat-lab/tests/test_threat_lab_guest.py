"""The in-microVM job runner (threat_lab/guest.py, build item LR3): which traced
processes are the sample's, the job and report drives, and the commands it runs.
Nothing here boots a microVM or runs a package."""

from __future__ import annotations

import io
import json

from threat_lab import bait, fixtures, guest, microvm


def test_only_the_packages_own_processes_are_reported():
    processes = guest.sample_processes(fixtures.fixture_install_trace(), guest.package_code_root("npm"), "install")
    # Not setpriv/env (the lab's wrapper), not npm or its git, not a failed exec.
    assert processes == [{"name": "sh", "phase": "install"}, {"name": "node", "phase": "install"},
                         {"name": "curl", "phase": "install"}]


def test_a_pip_install_reports_from_the_build_backend_down():
    traces = {
        200: ('execve("/usr/bin/setpriv", ["setpriv"], 0x1) = 0\n'
              'execve("/usr/bin/env", ["env"], 0x1) = 0\n'
              'execve("/usr/bin/pip", ["pip", "install"], 0x1) = 0\n'
              'clone(child_stack=NULL, flags=SIGCHLD) = 201\n'),
        201: ('execve("/usr/bin/python3", ["/usr/bin/python3", "/usr/lib/python3/dist-packages/'
              'pip/_vendor/pyproject_hooks/_in_process/_in_process.py", "build_wheel"], 0x1) = 0\n'
              'vfork() = 202\n'),
        202: 'execve("/usr/bin/wget", ["wget", "http://x.test/p"], 0x1) = 0\n',
    }
    assert guest.sample_processes(traces, guest.package_code_root("pypi"), "install") == [
        {"name": "python3", "phase": "install"}, {"name": "wget", "phase": "install"}]


def test_a_wheel_only_install_ran_nothing_of_the_packages():
    traces = {300: ('execve("/usr/bin/setpriv", ["setpriv"], 0x1) = 0\n'
                    'execve("/usr/bin/env", ["env"], 0x1) = 0\n'
                    'execve("/usr/bin/pip", ["pip", "install"], 0x1) = 0\n')}
    assert guest.sample_processes(traces, guest.package_code_root("pypi"), "install") == []


def test_a_fork_chain_deeper_than_the_recursion_limit_is_read():
    depth = 5000
    traces = {pid: f'execve("/bin/sh", ["sh"], 0x1) = 0\nclone(flags=SIGCHLD) = {pid + 1}\n'
              for pid in range(1, depth)}
    traces[1] = 'execve("/a", [], 0x1) = 0\nexecve("/b", [], 0x1) = 0\n' + traces[1]
    processes = guest.sample_processes(traces, guest.package_code_root("npm"), "install")
    assert len(processes) == guest.MAX_PROCESSES


def test_the_report_drive_round_trips_and_a_claimed_oversize_is_refused(tmp_path):
    drive = tmp_path / "report.img"
    with open(drive, "wb") as handle:
        handle.truncate(microvm.REPORT_DRIVE_BYTES)
    guest.write_report(drive, {"status": "ok", "processes": []})
    assert json.loads(microvm._read_report(drive, 1000)) == {"processes": [], "status": "ok"}
    drive.write_bytes(b"999999999\n{}")
    assert microvm._read_report(drive, 1000) is None
    drive.write_bytes(b"\0" * 64)
    assert microvm._read_report(drive, 1000) == b""


def test_the_job_drive_is_read_query_stripped():
    drive = json.dumps({"identifier": "url:https://skill.example.test/s.md?token=secret#x"}).encode() + b"\0" * 4000
    assert guest.read_job(drive) == "url:https://skill.example.test/s.md"


def test_installs_run_the_package_managers_own_install(tmp_path, monkeypatch):
    monkeypatch.setattr(guest.os, "chown", lambda *args: None)
    npm = guest.install_command("npm", "0-dns", "1.0.0", tmp_path / "npm")
    pip = guest.install_command("pypi", "pkg", "2.0", tmp_path / "pip")
    assert npm[:2] == ["npm", "install"] and npm[-1] == "0-dns@1.0.0" and "--ignore-scripts" not in npm
    assert pip[:2] == ["pip", "install"] and pip[-1] == "pkg==2.0"


def _serve(monkeypatch, body: bytes) -> None:
    class _Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(guest.urllib.request, "urlopen", lambda request, timeout: _Response(body))
    monkeypatch.setattr(guest.os, "chown", lambda *args: None)


def test_a_markdown_skill_runs_its_fenced_shell_blocks_in_order(tmp_path, monkeypatch):
    _serve(monkeypatch, b"# Skill\n```bash\necho one\n```\ntext\n```python\nprint(2)\n```\n```sh\necho three\n```\n")
    command = guest.skill_command("https://skill.example.test/SKILL.md", tmp_path)
    assert command == ["bash", str(tmp_path / "skill.sh")]
    assert (tmp_path / "skill.sh").read_text() == "echo one\n\necho three\n"


def test_a_skill_with_nothing_runnable_is_unsupported(tmp_path, monkeypatch):
    _serve(monkeypatch, b"# just prose\n")
    assert guest.skill_command("https://skill.example.test/README.md", tmp_path) is None
    assert guest.skill_command("https://skill.example.test/blob.bin", tmp_path) is None


def test_the_bait_is_inert_marked_and_findable():
    for value in (bait.AWS_ACCESS_KEY_ID, bait.AWS_SECRET_ACCESS_KEY, bait.NPM_TOKEN, bait.GITHUB_TOKEN):
        assert "TLBAIT" in value
    planted = "".join(bait.BAIT_FILES.values()) + "".join(bait.BAIT_ENVIRONMENT.values())
    assert all(marker.decode() in planted for marker in bait.bait_markers()[:5])
