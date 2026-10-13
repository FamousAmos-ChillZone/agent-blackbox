"""The program that runs INSIDE each level-4 microVM, as its init's last step:
``python3 -m threat_lab.guest`` (see ``microvm/init.sh``).

One job per boot, then the guest reboots, which ends Firecracker (``reboot=k``):

1. read the job, ``{"identifier"}``, from the read-only job drive (:data:`JOB_DEVICE`);
2. plant the inert bait (:mod:`threat_lab.bait`) in the test user's home;
3. run the method the identifier names, as the unprivileged test user, under
   ``strace -ff`` (run by root, so the sample can neither stop it nor edit its log):

   * a package (``dep:npm:`` / ``dep:pypi:``) — **install**: what the package
     manager does on install, nothing more (``npm install`` / ``pip install``);
   * a skill file (``url:`` …) — **run**: download it and run it the way an
     agent following it would (a script by its interpreter; a Markdown skill's
     fenced shell blocks in order);
   * anything else — ``unsupported`` (the curator's Evidence: could-not-tell).
     Prompt injection against a test agent needs a model in the guest and the
     lab holds no keys: not built here (recorded in the README).

4. write the report as ``b"<length>\\n<json>"`` to the raw report drive
   (:data:`REPORT_DEVICE`, root-only — the test user cannot forge it).

The report lists ONLY processes the sample's own code started, never the
package manager's own: for npm, the lifecycle-script shells and everything
under them; for pip, the build backend that runs a source package's
``setup.py`` and everything under it; for a skill, everything. An install that
failed with none of those seen is ``install-failed``: nothing was installed, so
nothing was witnessed — never "no install script ran" (LES-011).

Network traffic is recorded on the HOST (the TAP device), not here.
Copied into the guest image; imports only :mod:`threat_lab.bait` and
:mod:`threat_lab.identifiers`.
"""

from __future__ import annotations

import ctypes
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import bait
from .identifiers import TargetKind, parse_target, strip_query

JOB_DEVICE = Path("/dev/vdb")
REPORT_DEVICE = Path("/dev/vdc")
TRACE_DIR = Path("/run/threat-lab-trace")
LAB_USER_ID = 1000
LAB_HOME = Path("/home/lab")
MAX_JOB_BYTES = 65_536
MAX_REPORT_BYTES = 1_000_000
MAX_SKILL_BYTES = 5_000_000
MAX_PROCESSES = 200
_PATH = "/usr/local/bin:/usr/bin:/bin"
_SHELLS = frozenset({"sh", "bash", "dash"})
#: The wrapper programs the trace starts with before the sample's command (see :func:`traced`).
_WRAPPER_EXECS = 2
_INTERPRETERS = {".sh": "bash", ".bash": "bash", ".py": "python3", ".js": "node", ".mjs": "node"}
_FENCED_SHELL = re.compile(r"^```(?:sh|bash|shell|console)[ \t]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_SYSCALL = re.compile(r"^(execve|clone3?|v?fork)\((.*)\)\s+=\s+(-?\d+)")
_FIRST_STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"')
_LINUX_REBOOT_CMD_RESTART = 0x01234567


def main() -> int:
    try:
        report = run_job(read_job(JOB_DEVICE.read_bytes()))
    except Exception as error:  # the guest must always report and reboot
        report = {"status": "guest-error", "error": type(error).__name__}
    write_report(REPORT_DEVICE, report)
    os.sync()
    ctypes.CDLL(None, use_errno=True).reboot(_LINUX_REBOOT_CMD_RESTART)
    return 0


def read_job(drive: bytes) -> str:
    """The identifier on the job drive (JSON, NUL-padded to the drive's size)."""
    job = json.loads(drive[:MAX_JOB_BYTES].rstrip(b"\0"))
    return strip_query(str(job["identifier"]))


def run_job(identifier: str) -> dict[str, object]:
    target = parse_target(identifier)
    plant_bait(LAB_HOME)
    if target.kind is TargetKind.PACKAGE:
        command = install_command(target.ecosystem, target.name, target.version, LAB_HOME / "work")
        exit_code, processes = traced(command, package_code_root(target.ecosystem), "install")
        if exit_code != 0 and not processes:
            return {"status": "install-failed", "method": "install"}
        return {"status": "ok", "method": "install", "processes": processes}
    if target.kind is TargetKind.URL:
        try:
            command = skill_command(target.url, LAB_HOME / "skill")
        except OSError:                                    # urllib's errors are OSErrors
            return {"status": "unreachable", "method": "run"}
        if command is None:
            return {"status": "unsupported", "method": "run"}
        _exit_code, processes = traced(command, lambda name, line: True, "run")
        return {"status": "ok", "method": "run", "processes": processes}
    return {"status": "unsupported"}


def plant_bait(home: Path) -> None:
    for relative, content in bait.BAIT_FILES.items():
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="ascii")
    for path in [home, *home.rglob("*")]:
        os.chown(path, LAB_USER_ID, LAB_USER_ID)


def install_command(ecosystem: str, name: str, version: str, prefix: Path) -> list[str]:
    """The package manager's own install, scripts ON: that is the behaviour under test."""
    prefix.mkdir(parents=True, exist_ok=True)
    os.chown(prefix, LAB_USER_ID, LAB_USER_ID)
    if ecosystem == "npm":
        return ["npm", "install", "--no-audit", "--no-fund", "--foreground-scripts",
                "--prefix", str(prefix), f"{name}@{version}"]
    return ["pip", "install", "--no-cache-dir", "--no-input", "--target", str(prefix), f"{name}=={version}"]


def package_code_root(ecosystem: str) -> Callable[[str, str], bool]:
    """Whether an exec (basename, its strace line) starts the PACKAGE's code."""
    if ecosystem == "npm":
        return lambda name, line: name in _SHELLS          # npm runs lifecycle scripts via `sh -c`
    return lambda name, line: "_in_process" in line        # pip's build-backend runner (setup.py)


def skill_command(url: str, folder: Path) -> Optional[list[str]]:
    """Download the skill file and the command that runs it, or None when it is not runnable."""
    folder.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "threat-lab/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(MAX_SKILL_BYTES + 1)[:MAX_SKILL_BYTES]
    suffix = posixpath.splitext(posixpath.basename(url.split("?", 1)[0]))[1].lower()
    if suffix == ".md":
        blocks = _FENCED_SHELL.findall(data.decode("utf-8", "replace"))
        if not blocks:
            return None
        data, suffix = "\n".join(blocks).encode("utf-8"), ".sh"
    interpreter = _INTERPRETERS.get(suffix)
    if interpreter is None:
        return None
    script = folder / f"skill{suffix}"
    script.write_bytes(data)
    for path in (folder, script):
        os.chown(path, LAB_USER_ID, LAB_USER_ID)
    return [interpreter, str(script)]


def traced(command: Sequence[str], is_root: Callable[[str, str], bool],
           phase: str) -> tuple[int, list[dict[str, str]]]:
    """Run *command* as the test user, with the bait in its environment, under
    ``strace -ff``; its exit code and the sample's processes."""
    shutil.rmtree(TRACE_DIR, ignore_errors=True)
    TRACE_DIR.mkdir(mode=0o700)
    environment = [f"{key}={value}" for key, value in bait.BAIT_ENVIRONMENT.items()]
    argv = ["strace", "-ff", "-qq", "-e", "trace=execve,clone,clone3,fork,vfork", "-o", str(TRACE_DIR / "t"),
            "setpriv", f"--reuid={LAB_USER_ID}", f"--regid={LAB_USER_ID}", "--init-groups",
            "env", "-i", f"HOME={LAB_HOME}", f"PATH={_PATH}", *environment, *command]
    done = subprocess.run(argv, cwd=LAB_HOME, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False)
    traces = {int(path.suffix[1:]): path.read_text("utf-8", "replace") for path in TRACE_DIR.glob("t.*")
              if path.suffix[1:].isdigit()}
    return done.returncode, sample_processes(traces, is_root, phase)


def sample_processes(traces: dict[int, str], is_root: Callable[[str, str], bool],
                     phase: str) -> list[dict[str, str]]:
    """The sample's processes in ``strace -ff`` output (pid → that pid's log):
    every successful exec by a process at or under a root exec, in pid order,
    each as ``{"name": <basename>, "phase": phase}``.
    The first traced process's first :data:`_WRAPPER_EXECS` execs are the
    lab's own wrapper (``setpriv``, ``env``) and are never the sample's."""
    parents: dict[int, int] = {}
    execs: dict[int, list[tuple[str, str]]] = {}
    for pid, log in traces.items():
        for line in log.splitlines():
            matched = _SYSCALL.match(line)
            if not matched:
                continue
            call, arguments, result = matched.group(1), matched.group(2), int(matched.group(3))
            if call == "execve" and result == 0:
                path = _FIRST_STRING.match(arguments)
                name = posixpath.basename(path.group(1)) if path else "?"
                execs.setdefault(pid, []).append((name[:64], line))
            elif call != "execve" and result > 0:
                parents[result] = pid
    first = min((pid for pid in traces if pid not in parents), default=None)
    if first in execs:
        execs[first] = execs[first][_WRAPPER_EXECS:]
    roots = {pid for pid, calls in execs.items() if any(is_root(name, line) for name, line in calls)}
    processes: list[dict[str, str]] = []
    for pid in sorted(execs):
        if _descends_from(pid, roots, parents):
            processes.extend({"name": name, "phase": phase} for name, _line in execs[pid])
    return processes[:MAX_PROCESSES]


def _descends_from(pid: int, roots: set[int], parents: dict[int, int]) -> bool:
    """Whether *pid* is a root or under one. A loop, not recursion: a sample
    can fork a chain deeper than Python's recursion limit."""
    seen: set[int] = set()
    while pid not in seen:
        if pid in roots:
            return True
        seen.add(pid)
        if pid not in parents:
            return False
        pid = parents[pid]
    return False


def write_report(device: Path, report: dict[str, object]) -> None:
    body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REPORT_BYTES:
        body = json.dumps({"status": "guest-error", "error": "report-too-large"}).encode("utf-8")
    with open(device, "r+b") as drive:
        drive.write(str(len(body)).encode("ascii") + b"\n" + body)


if __name__ == "__main__":
    sys.exit(main())
