"""B10 contract: the installer registers boot persistence (KI-022, KI-032).

Script-level structural checks (the live reboot test runs on the dev
droplet and its evidence lives in the build worklog): the service units
exist in the installer with the right shape, the token gets owner-only
permissions, and registration runs in the install sequence.
"""

from __future__ import annotations

from pathlib import Path

import pytest


INSTALLER = (
    Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
)


def _src() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_boot_service_function_exists_and_runs_in_main():
    src = _src()
    assert "register_boot_service()" in src
    main_body = src.split("main() {", 1)[1]
    assert "register_boot_service" in main_body
    # Runs after the dashboard is up, before the closing guidance.
    assert main_body.index("start_dashboard") < main_body.index("register_boot_service")
    assert main_body.index("register_boot_service") < main_body.index("next_steps")


def test_systemd_unit_shape():
    src = _src()
    assert "blackbox-dkg.service" in src
    assert "Restart=on-failure" in src
    assert "WantedBy=multi-user.target" in src
    assert "start --foreground" in src  # systemd owns the lifecycle, no daemonize
    assert "DKG_HOME=$BLACKBOX_DKG_HOME" in src


def test_systemd_unit_keeps_steady_state_sync_enabled():
    """KI-044 regression: the boot service must run with connection-time meta
    sync ON — it is what delivers context-graph authority to subscribers.
    The =0 bootstrap values are for the supervised install transfer only;
    a unit that disables them makes every community-graph subscribe fail
    closed with CONTEXT_GRAPH_AUTHORITY_UNAVAILABLE after the first reboot.
    """
    src = _src()
    unit = src.split("[Unit]", 1)[1].split("UNIT", 1)[0]
    assert "DKG_SYNC_ON_CONNECT_ENABLED=1" in unit
    assert "DKG_SYNC_ON_CONNECT_ENABLED=0" not in unit


def test_systemd_unit_leaves_the_reconciler_to_config_and_carries_the_stream_switch():
    """KI-282: the periodic sync reconciler is chosen per graph in config.json
    (off for Umanitek's default graph on DKG 10.0.21). An environment value in
    the unit would override that choice, so the unit must not set it. The exact
    batch stream, by contrast, exists ONLY as an environment switch: without it
    a service-started node recovers the graph about 8x slower."""
    unit = _src().split("[Unit]", 1)[1].split("UNIT", 1)[0]
    assert "DKG_SYNC_RECONCILER_ENABLED" not in unit
    assert "Environment=DKG_EXACT_BATCH_STREAM_ENABLED=$BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED" in unit
    assert "Environment=DKG_VM_RECOVERY_PREFETCH_ENABLED=$BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED" in unit


def test_systemd_unit_clears_orphaned_daemons():
    """KI-045 regression: DKG CLI commands auto-spawn a detached daemon when
    none is running; that orphan holds daemon.pid and crash-loops the unit
    forever. The unit must stop any orphan before starting and own the stop.
    """
    src = _src()
    unit = src.split("[Unit]", 1)[1].split("UNIT", 1)[0]
    assert "ExecStartPre=-" in unit  # '-' prefix: no orphan present is not an error
    assert "stop" in unit.split("ExecStartPre=-", 1)[1].split("\n", 1)[0]
    assert "ExecStop=" in unit


def test_launchd_plist_shape():
    src = _src()
    assert "ai.umanitek.blackbox-dkg.plist" in src
    assert "<key>RunAtLoad</key><true/>" in src
    assert "<key>KeepAlive</key>" in src


def test_token_permissions_tightened():
    """KI-032: any local process reading the token bypasses every gate."""
    src = _src()
    assert "secure_dkg_token_perms" in src
    assert "chmod 600" in src


def test_disable_instructions_documented():
    src = _src()
    assert "systemctl disable --now blackbox-dkg" in src
    assert "launchctl unload" in src


# ---------------------------------------------------------------- the dashboard (KI-296)


def _dashboard_function() -> str:
    import re
    match = re.search(r"^register_dashboard_service\(\) \{.*?\n\}", _src(), re.DOTALL | re.MULTILINE)
    assert match is not None
    return match.group(0)


def test_dashboard_service_is_registered_after_the_node_in_main():
    """KI-296: a rebooted machine got its DKG node back but not the dashboard, whose
    worker refreshes the rules and whose health poll drives the community pulse."""
    main_body = _src().split("main() {", 1)[1]
    assert main_body.index("register_boot_service") < main_body.index("register_dashboard_service")
    assert main_body.index("register_dashboard_service") < main_body.index("next_steps")


def test_dashboard_unit_starts_after_the_node_and_runs_the_dashboard():
    unit = _dashboard_function().split("[Unit]", 1)[1].split("DASHUNIT", 1)[0]
    assert "After=network-online.target blackbox-dkg.service" in unit
    assert "ExecStart=$HERMES_BIN blackbox dashboard" in unit
    assert "Environment=HERMES_HOME=$HERMES_HOME" in unit
    assert "Restart=on-failure" in unit


def test_dashboard_service_respects_auto_dashboard_off():
    body = _dashboard_function()
    assert body.index('case "$BLACKBOX_AUTO_DASHBOARD"') < body.index("[Unit]")


def test_dashboard_service_is_written_and_enabled_on_a_systemd_machine(tmp_path):
    """Runs the real function on a Linux-shaped sandbox: a non-root user gets a user
    unit under $HOME, and systemctl is asked to enable it (stub records the calls)."""
    import shutil
    import subprocess
    if shutil.which("bash") is None:
        import pytest
        pytest.skip("needs bash")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    calls = tmp_path / "systemctl.calls"
    for name, body in (("systemctl", f'echo "$*" >> "{calls}"'), ("node", "exit 0"), ("uname", "echo Linux"),
                       ("hermes", "exit 0")):
        (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
        (stubs / name).chmod(0o755)
    script = "\n".join([
        "set -euo pipefail",
        "ok() { echo \"OK $*\"; }", "warn() { echo \"WARN $*\"; }", "step() { :; }",
        "id() { echo 1000; }",           # a non-root user: the unit goes under $HOME
        f"HOME={tmp_path}", f"HERMES_HOME={tmp_path}/.hermes", f"HERMES_BIN={stubs}/hermes",
        "BLACKBOX_AUTO_DASHBOARD=1",
        _dashboard_function(),
        "register_dashboard_service",
    ])
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                            env={"PATH": f"{stubs}:/usr/bin:/bin"})

    assert result.returncode == 0, result.stderr
    unit = tmp_path / ".config" / "systemd" / "user" / "blackbox-dashboard.service"
    assert f"ExecStart={stubs}/hermes blackbox dashboard" in unit.read_text()
    assert "--user enable --now blackbox-dashboard" in calls.read_text()


# ------------------------------------------- an update restarts the running dashboard (KI-300)


def _start_dashboard_run(tmp_path, *, running: bool, marker: str | None):
    """Run the real start_dashboard() with a real git checkout, a curl stub that
    says whether a dashboard answers, and run_detached recorded instead of run."""
    import re
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    (repo / "f").write_text("x")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-qm", "v"],
                   cwd=repo, check=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
    home = tmp_path / ".hermes"
    if marker is not None:
        (home / "blackbox").mkdir(parents=True)
        (home / "blackbox" / ".dashboard-revision").write_text((head if marker == "HEAD" else marker) + "\n")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "curl").write_text(f"#!/bin/sh\nexit {0 if running else 7}\n")
    (stubs / "curl").chmod(0o755)
    launched = tmp_path / "launched"
    func = re.search(r"^start_dashboard\(\) \{.*?\n\}", _src(), re.DOTALL | re.MULTILINE).group(0)
    script = "\n".join([
        "set -euo pipefail", "ok() { :; }", "warn() { :; }", "step() { :; }", "heading() { :; }",
        "sleep() { :; }", f'run_detached() {{ echo launched >> "{launched}"; }}',
        f"HERMES_HOME={home}", f"REPO_DIR={repo}", "HERMES_BIN=/bin/true", "BLACKBOX_AUTO_DASHBOARD=1",
        func, "start_dashboard",
    ])
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                            env={"PATH": f"{stubs}:/usr/bin:/bin"})
    assert result.returncode == 0, result.stderr
    revision = (home / "blackbox" / ".dashboard-revision")
    return launched.exists(), (revision.read_text().strip() if revision.exists() else ""), head


@pytest.mark.live_system_guard_bypass   # a throwaway temp repo and stubs, never the real checkout
def test_an_update_restarts_a_dashboard_running_older_code(tmp_path):
    """KI-300: re-running the installer updated the code but left the old dashboard
    process running the old code ("Dashboard already running") until a reboot."""
    launched, revision, head = _start_dashboard_run(tmp_path, running=True, marker="0" * 40)
    assert launched and revision == head


@pytest.mark.live_system_guard_bypass   # a throwaway temp repo and stubs, never the real checkout
def test_a_dashboard_already_running_the_current_code_is_left_alone(tmp_path):
    launched, _, _ = _start_dashboard_run(tmp_path, running=True, marker="HEAD")
    assert not launched


@pytest.mark.live_system_guard_bypass   # a throwaway temp repo and stubs, never the real checkout
def test_a_first_launch_records_the_revision(tmp_path):
    launched, revision, head = _start_dashboard_run(tmp_path, running=False, marker=None)
    assert launched and revision == head
