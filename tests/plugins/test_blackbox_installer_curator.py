"""Community Curation C9 — the installer's opt-in service unit for curator nodes.

The curator service is its own process, started only on curator nodes. The
installer registers it ONLY when told to, and these tests RUN the installer's
function (extracted from the script, with ``uname`` / ``systemctl`` / ``id``
stood in for) and read the unit it writes.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"


def _function() -> str:
    source = INSTALLER.read_text(encoding="utf-8")
    start = source.index("register_curator_service() {")
    return source[start:source.index("\n}\n", start) + 3]


def _run(tmp_path, env, *, system="Linux", systemctl=True):
    """Run register_curator_service in a throwaway HOME; returns (stdout, the unit text or None, the systemctl calls)."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    calls = tmp_path / "systemctl.log"
    have_systemctl = f'systemctl() {{ echo "$*" >> "{calls}"; }}' if systemctl else ""
    hide = "" if systemctl else 'command() { if [ "$2" = systemctl ]; then return 1; fi; builtin command "$@"; }'
    script = f"""
set -u
heading() {{ echo "HEADING $1"; }}; ok() {{ echo "OK $1"; }}; warn() {{ echo "WARN $1"; }}; step() {{ echo "STEP $1"; }}
uname() {{ echo {system}; }}
id() {{ echo 1000; }}
{have_systemctl}
{hide}
HERMES_HOME="$HOME/.hermes"; BLACKBOX_HOME="$HERMES_HOME/blackbox"; HERMES_BIN="/opt/venv/bin/hermes"
{_function()}
register_curator_service
"""
    done = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"HOME": str(home), "PATH": "/usr/bin:/bin", **env})
    assert done.returncode == 0, done.stderr
    unit = home / ".config/systemd/user/blackbox-curator.service"
    return done.stdout, (unit.read_text(encoding="utf-8") if unit.exists() else None), \
        (calls.read_text(encoding="utf-8") if calls.exists() else "")


def test_an_ordinary_install_registers_no_curator_service(tmp_path):
    for env in ({}, {"BLACKBOX_CURATOR_SERVICE": "0"}, {"BLACKBOX_CURATOR_PEERS": "peer-a"}):
        out, unit, calls = _run(tmp_path, env)
        assert (out, unit, calls) == ("", None, "")


def test_a_curator_node_gets_a_unit_that_runs_the_service_with_its_peers(tmp_path):
    out, unit, calls = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PEERS": "curator-b,12D3KooWabc:9"})
    assert "ExecStart=/opt/venv/bin/hermes blackbox curate run --peer curator-b --peer 12D3KooWabc:9\n" in unit
    assert "Restart=on-failure" in unit and "After=network-online.target blackbox-dkg.service" in unit
    assert f"Environment=BLACKBOX_HOME={tmp_path}/home/.hermes/blackbox" in unit
    assert "--user daemon-reload" in calls and "--user enable --now blackbox-curator" in calls
    assert "OK curator user service registered" in out
    assert "signs nothing until you accept the automation policy" in out          # the operator is told what is still theirs to do


@pytest.mark.parametrize("peers", ["good-peer,bad peer", "good-peer,$(touch pwned)", "good-peer,a;b", "good-peer,,`id`"])
def test_a_peer_name_that_is_not_a_plain_token_never_reaches_the_unit(tmp_path, peers):
    out, unit, _ = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PEERS": peers})
    assert "ExecStart=/opt/venv/bin/hermes blackbox curate run --peer good-peer\n" in unit
    assert "WARN ignoring curator peer" in out and not (tmp_path / "home" / "pwned").exists()
    assert not list(Path(tmp_path).rglob("pwned"))


def test_without_peers_the_service_is_still_registered_and_says_so(tmp_path):
    out, unit, _ = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1"})
    assert "ExecStart=/opt/venv/bin/hermes blackbox curate run\n" in unit and "WARN no curator peers given" in out


@pytest.mark.parametrize("system, systemctl", [("Darwin", True), ("Linux", False)])
def test_where_there_is_no_systemd_nothing_is_written_and_the_command_is_shown(tmp_path, system, systemctl):
    out, unit, calls = _run(tmp_path, {"BLACKBOX_CURATOR_SERVICE": "1", "BLACKBOX_CURATOR_PEERS": "curator-b"},
                            system=system, systemctl=systemctl)
    assert unit is None and calls == ""
    assert "blackbox curate run --peer curator-b" in out and "Linux with systemd only" in out


def test_the_installer_calls_it_after_the_node_service_and_documents_how_to_stop_it():
    source = INSTALLER.read_text(encoding="utf-8")
    main_body = source.split("main() {", 1)[1]
    assert main_body.index("register_boot_service") < main_body.index("register_curator_service") < main_body.index("next_steps")
    assert "systemctl disable --now blackbox-curator" in source and "BLACKBOX_CURATOR_SERVICE=1" in source
    assert _function().lstrip().split("\n")[1].strip() == '[ "${BLACKBOX_CURATOR_SERVICE:-0}" = 1 ] || return 0'    # opt-in is the first line
