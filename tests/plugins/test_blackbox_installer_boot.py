"""B10 contract: the installer registers boot persistence (KI-022, KI-032).

Script-level structural checks (the live reboot test runs on the dev
droplet and its evidence lives in the build worklog): the service units
exist in the installer with the right shape, the token gets owner-only
permissions, and registration runs in the install sequence.
"""

from __future__ import annotations

from pathlib import Path


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
    assert "DKG_SYNC_RECONCILER_ENABLED=1" in unit
    assert "DKG_SYNC_ON_CONNECT_ENABLED=0" not in unit
    assert "DKG_SYNC_RECONCILER_ENABLED=0" not in unit


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
