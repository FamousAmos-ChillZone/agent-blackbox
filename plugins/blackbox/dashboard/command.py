"""``blackbox dashboard`` — start the local dashboard (replacing a stale one on the port)."""

from __future__ import annotations

import argparse
import logging
import os
from .. import attach
from ..kernel.config import load_blackbox_config

logger = logging.getLogger(__name__)

def cmd_dashboard(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    port = args.port or cfg.dashboard_port
    try:
        from .server import start_dashboard
    except Exception as exc:
        print(f"error: dashboard requires the [web] extra (fastapi/uvicorn): {exc}")
        return 1
    _replace_existing_dashboard(port)
    try:
        report = attach.attach_all(hermes=True, openclaw=True, dry_run=False)
        newly = [r for r in report.get("hermes", []) + report.get("openclaw", []) if not r.get("already") and not r.get("error")]
        if newly:
            for row in report.get("hermes", []):
                if not row.get("already") and not row.get("error"):
                    attach.print_hermes_attach_row(row, "Auto-attached")
            for row in report.get("openclaw", []):
                if not row.get("already") and not row.get("error"):
                    attach.print_openclaw_attach_row(row, "Auto-attached")
            print("  Restart any running agent to activate.")
    except Exception as exc:
        logger.debug("dashboard auto-attach skipped: %s", exc)
    print(f"Starting Blackbox dashboard on http://127.0.0.1:{port} (Ctrl-C to stop)")
    start_dashboard(port)
    return 0


def _replace_existing_dashboard(port: int) -> None:
    """Kill any dashboard already bound to ``port`` so re-running ``hermes
    blackbox dashboard`` seamlessly restarts it instead of colliding.

    Loopback-only, best-effort: probe the port, resolve owning PIDs via
    ``lsof``, and send SIGTERM (then SIGKILL after a short wait). Skips the
    current process — we never signal ourselves. Fail-open: any error just
    proceeds to the bind, which will surface the normal port-in-use error.
    """
    import shutil
    import signal
    import socket

    # Quick reachability probe — if nothing's listening, skip everything.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        if sock.connect_ex(("127.0.0.1", int(port))) != 0:
            return
    finally:
        sock.close()

    lsof = shutil.which("lsof")
    if not lsof:
        print(f"warning: port {port} in use but 'lsof' unavailable — cannot auto-restart.")
        return

    try:
        import subprocess
        out = subprocess.run(
            [lsof, "-tiTCP:" + str(int(port)), "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except Exception as exc:
        logger.debug("dashboard auto-restart: lsof failed: %s", exc)
        return

    my_pid = os.getpid()
    pids = {int(p) for p in out.split() if p.isdigit() and int(p) != my_pid}
    if not pids:
        return

    print(f"restarting: found existing dashboard on port {port} (pid {', '.join(str(p) for p in sorted(pids))}) — stopping it...")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as exc:
            logger.debug("dashboard auto-restart: SIGTERM %s failed: %s", pid, exc)

    # Wait up to 3s for graceful exit, then SIGKILL stragglers.
    import psutil
    import time as _time
    for _ in range(30):
        alive = [pid for pid in pids if psutil.pid_exists(pid)]
        if not alive:
            return
        _time.sleep(0.1)
    kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    for pid in alive:
        try:
            os.kill(pid, kill_signal)
        except Exception as exc:
            logger.debug("dashboard auto-restart: SIGKILL %s failed: %s", pid, exc)
