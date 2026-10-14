"""The installer's setup-only mode: everything after Hermes, in the Hermes that runs it.

A Hermes plugin-catalog install brings the plugin only; `hermes blackbox setup`
runs scripts/blackbox-install.sh with BLACKBOX_SETUP_ONLY=true for the rest —
the DKG node, the graphs, attach, sync, dashboard, services. These tests run the
real functions out of the script: setup-only skips every step that installs
Hermes and keeps every step after it, writes `blackbox` beside the user's
`hermes` without touching it, and finds its helper scripts in the plugin.
The curl path (BLACKBOX_SETUP_ONLY unset) is unchanged.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import os
import sys
from pathlib import Path

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"

HERMES_STEPS = ["check_git", "check_python", "resolve_repo", "install_python_env", "link_hermes",
                "refresh_blackbox_plugin_copy", "run_hermes_setup"]


def _body(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", INSTALL_SH.read_text(encoding="utf-8"),
                      re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _main_steps(setup_only: bool) -> list[str]:
    """The step functions main() calls, in order, each stubbed to print its name."""
    steps = set(re.findall(r"^\s+([a-z_]+)\s*$", _body("main"), re.MULTILINE)) - {"else", "fi", "then"}
    stubs = "\n".join(f"{step}() {{ echo {step}; }}" for step in sorted(steps))
    script = f"""
heading() {{ :; }}
{stubs}
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_SETUP_ONLY={'true' if setup_only else 'false'}
main() {{
{_body("main")}
}}
main
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    return result.stdout.split()


def test_curl_install_runs_every_step_in_the_same_order_as_before():
    steps = _main_steps(setup_only=False)

    assert steps[:9] == ["banner", "detect_os", "check_git", "check_python", "ensure_node", "resolve_repo",
                         "install_python_env", "link_hermes", "refresh_blackbox_plugin_copy"]
    assert steps.index("run_hermes_setup") < steps.index("install_dkg")


def test_setup_only_skips_the_hermes_steps_and_keeps_everything_after():
    curl = _main_steps(setup_only=False)
    setup = _main_steps(setup_only=True)

    assert not set(HERMES_STEPS) & set(setup)
    assert setup[:4] == ["banner", "detect_os", "ensure_node", "use_running_hermes"]
    after_hermes = curl[curl.index("run_hermes_setup") + 1:]
    assert setup[4:] == after_hermes


def _use_running_hermes(tmp_path: Path, *, hermes_on_path: bool) -> tuple[subprocess.CompletedProcess, Path]:
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    python.chmod(0o755)
    user_bin = tmp_path / "user-bin"
    user_bin.mkdir()
    hermes = user_bin / "hermes"
    hermes.write_text("#!/bin/sh\necho the-users-hermes\n", encoding="utf-8")
    hermes.chmod(0o755)
    path = f"{user_bin}:/usr/bin:/bin" if hermes_on_path else "/usr/bin:/bin"
    script = f"""
heading() {{ :; }}
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
err() {{ echo "ERR $*"; }}
install_blackbox_shim() {{
{_body("install_blackbox_shim")}
}}
use_running_hermes() {{
{_body("use_running_hermes")}
}}
PATH={shlex.quote(path)}
HERMES_BIN={shlex.quote(str(hermes))}
VENV_DIR={shlex.quote(str(venv))}
use_running_hermes
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True), hermes


def test_setup_only_writes_blackbox_beside_the_users_hermes_and_never_replaces_it(tmp_path):
    result, hermes = _use_running_hermes(tmp_path, hermes_on_path=True)

    assert result.returncode == 0, result.stdout + result.stderr
    shim = hermes.parent / "blackbox"
    assert shim.is_file() and "managed-by: agent-blackbox-installer" in shim.read_text(encoding="utf-8")
    assert not hermes.is_symlink() and hermes.read_text(encoding="utf-8") == "#!/bin/sh\necho the-users-hermes\n"


def test_setup_only_without_the_callers_hermes_stops_with_the_command_to_use(tmp_path):
    script = f"""
heading() {{ :; }}
ok() {{ :; }}
err() {{ echo "ERR $*"; }}
use_running_hermes() {{
{_body("use_running_hermes")}
}}
HERMES_BIN={shlex.quote(str(tmp_path / "missing"))}
VENV_DIR={shlex.quote(str(tmp_path))}
use_running_hermes
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    assert result.returncode == 1
    assert "hermes blackbox setup" in result.stdout


def _helper(env: str) -> str:
    script = f"""
blackbox_helper() {{
{_body("blackbox_helper")}
}}
REPO_DIR=/checkout
{env}
blackbox_helper blackbox-blazegraph.mjs
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout


def test_helpers_come_from_the_checkout_in_a_curl_install():
    assert _helper("") == "/checkout/scripts/blackbox-blazegraph.mjs"


def test_helpers_come_from_the_plugin_in_setup_only_mode():
    assert _helper("BLACKBOX_HELPER_DIR=/home/x/plugins/blackbox/setup") == \
        "/home/x/plugins/blackbox/setup/blackbox-blazegraph.mjs"


def test_no_step_after_hermes_reads_the_checkout_directly():
    """Everything setup-only mode runs reaches the checkout only through blackbox_helper /
    BLACKBOX_PLUGIN_DIR / BLACKBOX_REVISION, so an empty REPO_DIR never points at the wrong folder."""
    lines = INSTALL_SH.read_text(encoding="utf-8").splitlines()
    guard = '[ -n "$REPO_DIR" ]'
    direct = [line.strip() for index, line in enumerate(lines)
              if "$REPO_DIR" in line and not line.lstrip().startswith("#")
              and guard not in lines[index - 1]]   # the line under a non-empty check is safe
    allowed = ("REPO_DIR=", "${BLACKBOX_HELPER_DIR:-$REPO_DIR/scripts}", "${BLACKBOX_PLUGIN_DIR:-$REPO_DIR/plugins/blackbox}",
               "${BLACKBOX_PLUGIN_DIR:-$REPO_DIR}", '[ -n "$REPO_DIR" ]')
    hermes_steps = "".join(_body(step) for step in ("resolve_repo", "install_python_env", "use_hermes_selected_venv",
                                                    "ensure_web_extra", "minimal_python_env",
                                                    "refresh_blackbox_plugin_copy", "reuse_existing_hermes_api_keys"))
    stray = [line for line in direct if line not in hermes_steps and not any(token in line for token in allowed)]
    assert stray == []


def test_setup_only_keeps_community_sharing_on_by_reading_consent_from_the_plugin_folder(tmp_path, monkeypatch):
    """Stock Hermes has its own `plugins` package, so the config writer's consent check must load
    Blackbox from the plugin folder it is given. If it could not, it would answer "no consent" and
    turn sharing OFF on every catalog install (found while building setup-only mode, 2026-10-14)."""
    helper = INSTALL_SH.read_text(encoding="utf-8").split("def _consent_in_force(checkout):", 1)[1].split("\nif ", 1)[0]
    namespace: dict = {"sys": sys, "os": os}
    exec("def _consent_in_force(checkout):" + helper, namespace)
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))   # no sharing record: the default, sharing on
    plugin_dir = Path(__file__).resolve().parents[1] / "plugins" / "blackbox"

    assert namespace["_consent_in_force"](str(plugin_dir)) is True


def test_the_config_writer_is_given_the_plugin_folder_in_setup_only_mode():
    assert '"${BLACKBOX_PLUGIN_DIR:-$REPO_DIR}" <<\'PYEOF\'' in _body("enable_and_configure")


def _install_dkg_package(tmp_path: Path, *, pinned: str, published: str) -> subprocess.CompletedProcess:
    """install_blackbox_dkg_package with a stub npm that publishes *published* and logs installs."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "npm-calls"
    npm = fake_bin / "npm"
    npm.write_text(f"""#!/bin/sh
echo "$*" >> {shlex.quote(str(log))}
if [ "$1" = view ]; then echo {shlex.quote(published)}; exit 0; fi
exit 1
""", encoding="utf-8")
    npm.chmod(0o755)
    script = f"""
warn() {{ echo "WARN $*"; }}
ok() {{ echo "OK $*"; }}
step() {{ :; }}
install_blackbox_dkg_package() {{
{_body("install_blackbox_dkg_package")}
}}
PATH={shlex.quote(str(fake_bin))}:/usr/bin:/bin
HERMES_HOME={shlex.quote(str(tmp_path / "home"))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(tmp_path / "dkg"))}
BLACKBOX_DKG_PACKAGE=@origintrail-official/dkg@10.0.23
BLACKBOX_DKG_INTEGRITY={shlex.quote(pinned)}
install_blackbox_dkg_package
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    result.calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result


def test_a_pinned_dkg_package_with_another_checksum_is_never_installed(tmp_path):
    result = _install_dkg_package(tmp_path, pinned="sha512-pinned", published="sha512-something-else")

    assert result.returncode == 1
    assert "not the one this Blackbox release pins" in result.stdout
    assert not any(call.startswith("install") for call in result.calls)


def test_a_pinned_dkg_package_with_the_pinned_checksum_goes_on_to_install(tmp_path):
    result = _install_dkg_package(tmp_path, pinned="sha512-pinned", published="sha512-pinned")

    assert "checksum matches the pinned one" in result.stdout
    assert any(call.startswith("install") and "@origintrail-official/dkg@10.0.23" in call for call in result.calls)


# -- the Windows installer: the same contract (parsed by its own toolchain in CI, LES-037) --------

INSTALL_PS1 = INSTALL_SH.with_suffix(".ps1")


def _ps1_function(name: str) -> str:
    match = re.search(rf"^function {re.escape(name)}\b.*?^\}}", INSTALL_PS1.read_text(encoding="utf-8"),
                      re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name} not found"
    return match.group(0)


def test_windows_setup_only_skips_the_hermes_steps():
    main = _ps1_function("Main")
    setup_branch = main.split("if ($SetupOnly) {", 1)[1].split("} else {", 1)[0]

    assert "Use-RunningHermes" in setup_branch and "Test-NodeJs" in setup_branch
    assert not any(step in setup_branch for step in ("Test-Git", "Resolve-Python", "Resolve-Repo", "Install-PythonEnv"))
    assert main.index("Install-BlackboxCommand") > main.index("} else {")   # after both branches


def test_windows_helpers_come_from_the_plugin_in_setup_only_mode():
    text = INSTALL_PS1.read_text(encoding="utf-8").replace(_ps1_function("Get-BlackboxHelper"), "")

    assert 'Join-Path $RepoDir "scripts' not in text   # only the helper's own curl default builds it
    assert "if ($env:BLACKBOX_HELPER_DIR) { return Join-Path $env:BLACKBOX_HELPER_DIR $Name }" in _ps1_function("Get-BlackboxHelper")


def test_windows_keeps_sharing_on_and_pins_the_dkg_checksum():
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert 'os.path.isfile(os.path.join(checkout, "plugin.yaml"))' in text
    assert "$(if ($env:BLACKBOX_PLUGIN_DIR) { $env:BLACKBOX_PLUGIN_DIR } else { $RepoDir })" in text
    assert "if ($published -ne $DkgIntegrity)" in _ps1_function("Install-BlackboxDkgPackage")
